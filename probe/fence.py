"""The process fence: nothing in this process may talk to any network except
through GuardedTransport -- not our code, not a library, not a helper program.

Why it exists: the transport guard checks every probe we *mean* to send. This
closes the other ways out ("digging under the fence"):

  * sockets      -> a Python audit hook (PEP 578) sees every connect / sendto /
                    sendmsg / bind / DNS lookup made by *any* code in the process
                    and refuses everything except loopback (the local web view)
  * DNS          -> getaddrinfo / gethostbyname / ... refused for anything but loopback
  * other tools  -> subprocess / os.system / exec / spawn refused outright
                    (no shelling out to ping, nmap, curl, PowerShell...)
  * raw sending  -> every scapy send function and socket `send` is locked so it
                    only works inside GuardedTransport._emit

A violation trips the kill switch (process exits, latch written) or, if no kill
switch is attached, raises ScopeViolation. The hook cannot be removed once
installed. Install it *after* everything that legitimately needs a helper
program has run (interface discovery, starting the auditor).
"""
from __future__ import annotations

import logging
import os
import sys
import threading
from contextlib import contextmanager

from .scope import ScopeViolation

logger = logging.getLogger("probe.fence")

LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost", "::ffff:127.0.0.1", "", None}
SOCKET_ADDR_EVENTS = {"socket.connect", "socket.sendto", "socket.bind", "socket.sendmsg"}
SOCKET_NAME_EVENTS = {"socket.gethostbyname", "socket.gethostbyaddr", "socket.getnameinfo", "socket.getaddrinfo"}
EXEC_EVENTS = {"subprocess.Popen", "os.system", "os.exec", "os.posix_spawn", "os.spawn", "os.fork", "os.forkpty"}

_tls = threading.local()
_installed = False
_on_violation = None
_ALLOWED_PROGRAMS: set[str] = set()   # sanctioned helper programs (e.g. nmap), runnable only inside tool_context()


def _first_token(cmd) -> str:
    """The program in a Popen command. On Windows CPython passes the audit hook a single command-line STRING
    (already joined by list2cmdline), on POSIX a list -- handle both."""
    if isinstance(cmd, (list, tuple)):
        return str(cmd[0]) if cmd else ""
    cmd = str(cmd or "").lstrip()
    if cmd.startswith('"'):
        end = cmd.find('"', 1)
        return cmd[1:end] if end > 0 else cmd[1:]
    return cmd.split(" ", 1)[0]


def _norm(path) -> str:
    return os.path.normcase(os.path.abspath(str(path))) if path else ""


def allow_program(path: str) -> None:
    """Whitelist ONE helper executable. It may be launched only inside tool_context(); everything else stays
    forbidden. The caller (probe.tools) validates the helper's targets against the scope first."""
    _ALLOWED_PROGRAMS.add(_norm(path))


@contextmanager
def tool_context():
    _tls.tool = True
    try:
        yield
    finally:
        _tls.tool = False


def _host(addr):
    if isinstance(addr, tuple) and addr:
        h = addr[0]
        return h.decode() if isinstance(h, bytes) else h
    if isinstance(addr, (str, bytes)):  # AF_UNIX path: stays on this machine
        return ""
    return None


def check_event(event: str, args: tuple) -> str | None:
    """Pure policy: returns a human-readable violation, or None if the event is fine."""
    if event in SOCKET_ADDR_EVENTS:
        h = _host(args[1] if len(args) > 1 else None)
        if h not in LOOPBACK_HOSTS:
            return f"{event} to {h!r}: only loopback is allowed"
    elif event in SOCKET_NAME_EVENTS:
        target = args[0] if args else None
        h = _host(target) if isinstance(target, tuple) else (target.decode() if isinstance(target, bytes) else target)
        if h not in LOOPBACK_HOSTS:
            return f"name lookup of {h!r}: DNS is forbidden"
    elif event == "subprocess.Popen":
        exe = args[0] if args and args[0] else (_first_token(args[1]) if len(args) > 1 and args[1] else "")
        if _norm(exe) in _ALLOWED_PROGRAMS and getattr(_tls, "tool", False):
            return None                                   # a sanctioned helper, launched by probe.tools only
        return f"{event}: launching other programs is forbidden"
    elif event in EXEC_EVENTS:
        return f"{event}: launching other programs is forbidden"
    return None


def _violation(msg: str) -> None:
    logger.critical("FENCE: %s", msg)
    if _on_violation is not None:
        _on_violation(msg)
    raise ScopeViolation(msg)


def _hook(event: str, args: tuple) -> None:
    if event.startswith(("socket.", "subprocess.", "os.")):
        msg = check_event(event, args)
        if msg:
            _violation(msg)


@contextmanager
def authorized_send():
    """Entered only by GuardedTransport around the single real NIC write."""
    _tls.ok = True
    try:
        yield
    finally:
        _tls.ok = False


def _locked(fn, name):
    def wrapper(*a, **kw):
        if not getattr(_tls, "ok", False):
            _violation(f"scapy {name}() called outside GuardedTransport")
        return fn(*a, **kw)
    wrapper.__wrapped__ = fn
    wrapper._probe_locked = True
    return wrapper


def _subclasses(cls):
    for sub in cls.__subclasses__():
        yield sub
        yield from _subclasses(sub)


def lock_scapy_send() -> None:
    import scapy.all as sa
    import scapy.arch.libpcap  # noqa: F401  (make sure the capture socket classes exist before locking)
    import scapy.sendrecv as sr
    from scapy.supersocket import SuperSocket
    for name in ("send", "sendp", "sendpfast", "sr", "sr1", "srp", "srp1", "srloop", "srploop", "sniff_send"):
        for mod in (sr, sa):
            fn = getattr(mod, name, None)
            if callable(fn) and not getattr(fn, "_probe_locked", False):
                setattr(mod, name, _locked(fn, name))
    try:   # the raw libpcap handle: the final step of every send
        from scapy.arch.libpcap import _PcapWrapper_libpcap
        fn = _PcapWrapper_libpcap.__dict__.get("send")
        if fn is not None and not getattr(fn, "_probe_locked", False):
            _PcapWrapper_libpcap.send = _locked(fn, "pcap.send")
    except ImportError:
        pass
    for cls in [SuperSocket, *_subclasses(SuperSocket)]:
        fn = cls.__dict__.get("send")
        if fn is not None and not getattr(fn, "_probe_locked", False):
            setattr(cls, "send", _locked(fn, f"{cls.__name__}.send"))


def install(kill=None, *, lock_scapy: bool = True) -> None:
    """Idempotent. After this call the process cannot reach any network except via GuardedTransport."""
    global _installed, _on_violation
    if kill is not None:
        _on_violation = lambda msg: kill.trip("<fence>", "process-fence", msg)
    if _installed:
        return
    if lock_scapy:
        lock_scapy_send()
    sys.addaudithook(_hook)
    _installed = True
    logger.info("process fence installed: loopback only, no DNS, no subprocesses, scapy send locked")

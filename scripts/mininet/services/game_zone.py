#!/usr/bin/env python3
"""Stand-in for the console on 192.168.60.139:8833 ("Game Zone"), for offline development.

The AUTH step is faithful to the real target: the passkey check is the exact byte-for-byte XOR algorithm
decompiled from the real /vault/keykeeper binary (see docs/PROGRESS.md Entry 17), and the accepted
passkey below ("R3v3rs3_Th3_Z0n3") was recovered from that same binary, not invented.

The WHOAMI -> PIDREQ sequence past AUTH is a RECONSTRUCTION, not a captured transcript: this session
never actually drove the real console that far (the automated agent that can is new -- see
console_session_agent.py), so nothing it says here should be reported as "the real server's own
protocol." It exists so the new console_session_agent, and anyone developing against it, has a real
multi-step target to exercise offline; the flag it returns is a synthetic one, clearly not the real flag.
"""
import secrets
import socketserver
import threading

_PASSKEY = "R3v3rs3_Th3_Z0n3"
_BANNER = (
    b"== Game Zone ==\r\n"
    b"Authenticate with: AUTH <passkey>\r\n"
)
_SYNTHETIC_FLAG = "flag{mininet_replica_not_the_real_target}"

_sessions: dict[int, dict] = {}
_lock = threading.Lock()


class Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.sendall(_BANNER)
        authed = False
        session_id = None
        while True:
            line = self._readline()
            if line is None:
                return
            line = line.strip()
            if not authed:
                if line.startswith("AUTH "):
                    if line[5:] == _PASSKEY:
                        authed = True
                        session_id = secrets.randbelow(900000) + 100000
                        with _lock:
                            _sessions[session_id] = {"authed": True}
                        self.request.sendall(
                            b"[+] passkey accepted.\r\n[+] type HELP for the command list.\r\n"
                        )
                    else:
                        self.request.sendall(b"[-] denied. reverse harder.\r\n")
                else:
                    self.request.sendall(b"[-] AUTH required first.\r\n")
                continue
            if line == "HELP":
                self.request.sendall(b"commands: WHOAMI, PIDREQ <session>, QUIT\r\n")
            elif line == "WHOAMI":
                self.request.sendall(f"user=guest session={session_id}\r\n".encode())
            elif line.startswith("PIDREQ "):
                arg = line[len("PIDREQ "):].strip()
                if arg == str(session_id):
                    self.request.sendall(_SYNTHETIC_FLAG.encode() + b"\r\n")
                else:
                    self.request.sendall(b"[-] unknown session.\r\n")
            elif line == "QUIT":
                return
            else:
                self.request.sendall(b"[-] unrecognised command. try HELP.\r\n")

    def _readline(self) -> str | None:
        buf = b""
        while b"\n" not in buf:
            try:
                chunk = self.request.recv(1)
            except OSError:
                return None
            if not chunk:
                return None
            buf += chunk
        return buf.decode("utf-8", errors="replace")


class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main() -> None:
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8833
    with ThreadingTCPServer(("0.0.0.0", port), Handler) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Generic multi-port service stand-in for one Mininet host.

Listens on every port this host was discovered with on the real lab network (minus the two ports that get
their own dedicated, stateful script -- see game_zone.py and vault_site.py) and sends back a short banner
that matches what the real scan guessed for that service, nothing more. The point is not to reimplement
SSH/MySQL/SMB/etc -- it's to give the orchestrator's agents a real TCP socket to connect to, with real
banner bytes to read, so a replayed assessment exercises the same code paths (connect, read, timeout,
close) it exercises against the real network, offline.

Usage: svc_runner.py '<json: {"port": {"kind": "raw"|"http", "banner": "...", "server": "..."}}>'
"""
import json
import selectors
import socket
import sys
import time

sel = selectors.DefaultSelector()
_last_activity: dict[socket.socket, float] = {}
_IDLE_TIMEOUT = 20.0


def _http_response(server_header: str, banner: str) -> bytes:
    body = f"<html><body><h1>{banner}</h1></body></html>".encode()
    headers = (
        f"HTTP/1.1 200 OK\r\nServer: {server_header}\r\nContent-Type: text/html\r\n"
        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    ).encode()
    return headers + body


def _accept(listen_sock: socket.socket, spec: dict) -> None:
    conn, _ = listen_sock.accept()
    conn.setblocking(False)
    if spec["kind"] == "http":
        # Real HTTP servers wait for the request before replying -- register for read, reply on first data.
        sel.register(conn, selectors.EVENT_READ, data=("http_wait", spec))
    else:
        try:
            conn.sendall(spec["banner"].encode() + b"\r\n")
        except OSError:
            pass
        sel.register(conn, selectors.EVENT_READ, data=("raw_drain", spec))
    _last_activity[conn] = time.monotonic()


def _handle_client(conn: socket.socket, kind: str, spec: dict) -> None:
    try:
        data = conn.recv(4096)
    except OSError:
        data = b""
    _last_activity[conn] = time.monotonic()
    if not data:
        sel.unregister(conn)
        conn.close()
        _last_activity.pop(conn, None)
        return
    if kind == "http_wait":
        try:
            conn.sendall(_http_response(spec.get("server", "unknown"), spec["banner"]))
        except OSError:
            pass
        sel.unregister(conn)
        conn.close()
        _last_activity.pop(conn, None)
    # raw_drain: just keep reading and discarding -- a real banner-only service does the same until the
    # client gives up or the idle timeout below closes it.


def main() -> None:
    config = json.loads(sys.argv[1])
    for port_str, spec in config.items():
        port = int(port_str)
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("0.0.0.0", port))
        listener.listen(16)
        listener.setblocking(False)
        sel.register(listener, selectors.EVENT_READ, data=("accept", spec))

    while True:
        for key, _mask in sel.select(timeout=5.0):
            kind = key.data[0]
            spec = key.data[1]
            if kind == "accept":
                _accept(key.fileobj, spec)
            else:
                _handle_client(key.fileobj, kind, spec)
        now = time.monotonic()
        for conn, last in list(_last_activity.items()):
            if now - last > _IDLE_TIMEOUT:
                try:
                    sel.unregister(conn)
                except KeyError:
                    pass
                conn.close()
                _last_activity.pop(conn, None)


if __name__ == "__main__":
    main()

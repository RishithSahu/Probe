#!/usr/bin/env python3
"""Stand-in for the web site on 192.168.60.139:80, for offline development.

Reproduces the real behaviour this session's content-discovery fix was built against: the home page (and
the whole /vault tree) only appears with a trusted-proxy header set to this subnet's gateway address;
without it, /vault genuinely 404s, exactly like the real host. /vault/keykeeper serves the actual real
binary (copied in at setup time), so Ghidra/binary-analysis work against this replica is analysing the
real artifact, not a stand-in -- only the web layer around it is reconstructed.
"""
import http.server
import sys

_TRUSTED_HEADER = "X-Forwarded-For"
_TRUSTED_VALUE = "192.168.60.1"
_KEYKEEPER_PATH = "/opt/mininet_assets/keykeeper.elf"


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, status, body=b"", headers=None):
        self.send_response(status)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        gated = self.headers.get(_TRUSTED_HEADER) == _TRUSTED_VALUE
        if self.path == "/vault" and gated:
            self._send(308, headers={"Location": "/vault/"})
        elif self.path == "/vault/" and gated:
            self._send(
                200,
                b'<html><body><h1>Index of /vault</h1><a href="keykeeper">keykeeper</a></body></html>',
                headers={"Content-Type": "text/html"},
            )
        elif self.path == "/vault/keykeeper" and gated:
            try:
                with open(_KEYKEEPER_PATH, "rb") as f:
                    body = f.read()
            except OSError:
                self._send(500)
                return
            self._send(200, body, headers={"Content-Type": "application/octet-stream"})
        elif self.path.startswith("/vault"):
            self._send(404)
        elif gated:
            self._send(200, b"<html><body>Mitigata internal portal</body></html>", headers={"Content-Type": "text/html"})
        else:
            self._send(200, b"<html><body>Mitigata public site</body></html>", headers={"Content-Type": "text/html"})


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 80
    server = http.server.ThreadingHTTPServer(("0.0.0.0", port), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()

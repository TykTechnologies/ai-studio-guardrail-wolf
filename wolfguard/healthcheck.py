"""Container healthcheck: GET /readyz over the service's Unix socket (or TCP port). Exit 0 when ready."""
import http.client
import os
import socket
import sys


class UnixConnection(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost", timeout=3)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(3)
        self.sock.connect(self.path)


def main():
    path = os.environ.get("WOLFGUARD_SOCKET", "")
    try:
        conn = UnixConnection(path) if path else http.client.HTTPConnection("127.0.0.1", int(os.environ.get("WOLFGUARD_PORT", "18900")), timeout=3)
        conn.request("GET", "/readyz")
        sys.exit(0 if conn.getresponse().status == 200 else 1)
    except OSError:
        sys.exit(1)


if __name__ == "__main__":
    main()

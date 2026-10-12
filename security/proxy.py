"""Public-only HTTP/CONNECT proxy. DNS is checked AND the connection uses that IP.

The isolated browser has no external network route. HTTPS remains end-to-end;
this proxy does not decrypt traffic or retain browsing payloads.
"""
import ipaddress
import select
import socket
import socketserver
import time
from urllib.parse import urlsplit


def public_destinations(host, port):
    if port not in (80, 443):
        raise ValueError("Port blocked")
    answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    if not answers or any(not ipaddress.ip_address(answer[4][0]).is_global for answer in answers):
        raise ValueError("Non-public destination blocked")
    # Return the actual sockaddr so there is no second DNS resolution.
    return list(dict.fromkeys(answers))


def public_destination(host, port):
    # Kept as a small compatibility helper for diagnostics/tests.
    return public_destinations(host, port)[0]


def connect_public(host, port):
    answers = public_destinations(host, port)
    deadline = time.monotonic() + 15
    last_error = OSError("No reachable public address")
    for family, kind, protocol, _, address in answers:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        connection = socket.socket(family, kind, protocol)
        connection.settimeout(min(5, remaining))
        try:
            connection.connect(address)
            return connection
        except OSError as exc:
            connection.close()
            last_error = exc
    raise last_error


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(20)
        upstream = None
        try:
            line = self.rfile.readline(8193)
            if len(line) > 8192:
                raise ValueError("Request line too large")
            method, target, version = line.decode("ascii").strip().split()
            headers = []
            total = 0
            while True:
                header = self.rfile.readline(8193)
                total += len(header)
                if total > 32768 or len(header) > 8192 or not header:
                    raise ValueError("Invalid headers")
                if header == b"\r\n":
                    break
                headers.append(header)
            if method == "CONNECT":
                parsed = urlsplit("https://" + target)
                if parsed.username or parsed.password or parsed.path or not parsed.hostname:
                    raise ValueError("Invalid CONNECT destination")
                if parsed.port != 443:
                    raise ValueError("Only HTTPS CONNECT allowed")
                upstream = connect_public(parsed.hostname, 443)
                self.connection.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            else:
                if method not in ("GET", "HEAD"):
                    raise ValueError("Plain HTTP writes blocked")
                parsed = urlsplit(target)
                if parsed.scheme != "http" or parsed.username or parsed.password or not parsed.hostname:
                    raise ValueError("Invalid HTTP destination")
                upstream = connect_public(parsed.hostname, parsed.port or 80)
                path = parsed.path or "/"
                if parsed.query:
                    path += "?" + parsed.query
                clean = [h for h in headers if not h.lower().startswith((b"host:", b"proxy-", b"connection:", b"content-length:", b"transfer-encoding:"))]
                request = f"{method} {path} HTTP/1.1\r\nHost: {parsed.hostname}\r\nConnection: close\r\n".encode()
                upstream.sendall(request + b"".join(clean) + b"\r\n")
            while True:
                readable, _, _ = select.select([self.connection, upstream], [], [], 30)
                if not readable:
                    break
                for source in readable:
                    data = source.recv(65536)
                    if not data:
                        return
                    destination = upstream if source is self.connection else self.connection
                    destination.sendall(data)
        except (ValueError, OSError, UnicodeError):
            try:
                self.connection.sendall(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            except OSError:
                pass
        finally:
            if upstream:
                upstream.close()


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    with Server(("0.0.0.0", 8080), Handler) as server:
        server.serve_forever()

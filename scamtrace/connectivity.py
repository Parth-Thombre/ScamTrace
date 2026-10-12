"""Explain browser failures without bypassing the isolated browser."""
import ipaddress
import socket
from urllib.parse import urlsplit


def diagnose(url: str, error: str) -> str:
    if "ERR_CERT_" in error:
        return "tls_certificate_rejected"
    if "ERR_SSL_" in error:
        return "tls_handshake_failed"
    if "ERR_TUNNEL_CONNECTION_FAILED" not in error:
        return "browser_timeout" if "TimeoutError" in error else "connection_failed"
    parsed = urlsplit(url)
    try:
        answers = socket.getaddrinfo(parsed.hostname, parsed.port or 443, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return "dns_resolution_failed"
    if not answers:
        return "dns_resolution_failed"
    if any(not ipaddress.ip_address(a[4][0]).is_global for a in answers):
        return "non_public_dns_blocked"
    # DNS can change and this lookup is from the scanner, not the proxy.
    # Public DNS alone does not identify why the CONNECT attempt failed.
    return "proxy_tunnel_failed_with_public_dns"

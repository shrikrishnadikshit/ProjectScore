"""Keeps the scanner from reaching private networks.

Anyone can ask for a free report on any domain, and a domain's DNS can point at internal addresses
(127.0.0.1, 10.x, cloud metadata on 169.254.169.254). Every host is checked before it is contacted,
and so is every redirect target.
"""

import ipaddress
import socket

import httpx


def is_public_host(host: str) -> bool:
    """True only if the host resolves and every address it resolves to is a public internet address."""
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError, OSError):
        return False
    addrs = {info[4][0] for info in infos}
    return bool(addrs) and all(ipaddress.ip_address(a.split("%")[0]).is_global for a in addrs)


def public_hosts(hosts: list[str]) -> list[str]:
    return [h for h in hosts if is_public_host(h)]


def block_private_redirects(request: httpx.Request) -> None:
    """httpx request hook: refuse any request (including redirects) to a non-public host."""
    host = request.url.host
    if not host or not is_public_host(host):
        raise httpx.RequestError(f"refusing to contact non-public host {host!r}", request=request)

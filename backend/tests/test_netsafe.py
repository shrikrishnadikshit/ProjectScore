import socket

import httpx
import pytest

from app.collectors import netsafe


def fake_dns(monkeypatch, table):
    def getaddrinfo(host, port, proto=0):
        if host not in table:
            raise socket.gaierror("no such host")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port)) for ip in table[host]]
    monkeypatch.setattr(netsafe.socket, "getaddrinfo", getaddrinfo)


def test_only_public_hosts_pass(monkeypatch):
    fake_dns(monkeypatch, {"good.example": ["93.184.216.34"], "meta.example": ["169.254.169.254"],
                           "mixed.example": ["93.184.216.34", "10.0.0.5"], "lo.example": ["127.0.0.1"]})
    assert netsafe.public_hosts(["good.example", "meta.example", "mixed.example", "lo.example", "nx.example"]) \
        == ["good.example"]


def test_redirect_hook_blocks_private(monkeypatch):
    fake_dns(monkeypatch, {"good.example": ["93.184.216.34"], "lo.example": ["127.0.0.1"]})
    netsafe.block_private_redirects(httpx.Request("GET", "https://good.example/"))
    with pytest.raises(httpx.RequestError):
        netsafe.block_private_redirects(httpx.Request("GET", "https://lo.example/"))

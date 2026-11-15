"""TLS collector (risk factor 6): one standard handshake per host, nothing intrusive."""

import socket
import ssl
from datetime import datetime, timezone

from . import RawFinding

FACTOR = "tls"


def evaluate_certificate(host: str, not_after: datetime | None, verified: bool, protocol: str | None,
                         now: datetime | None = None) -> list[RawFinding]:
    now = now or datetime.now(timezone.utc)
    findings = []
    if not verified:
        findings.append(RawFinding(FACTOR, "cert_untrusted", "Certificate is not trusted or does not match",
                                   "high", host))
    if not_after is not None:
        days_left = (not_after - now).days
        if days_left < 0:
            findings.append(RawFinding(FACTOR, "cert_expired", "Certificate has expired", "high", host,
                                       {"not_after": not_after.isoformat()}))
        elif days_left < 14:
            findings.append(RawFinding(FACTOR, "cert_expiring", "Certificate expires within 14 days", "low", host,
                                       {"not_after": not_after.isoformat()}))
    if protocol in ("TLSv1", "TLSv1.1", "SSLv3"):
        findings.append(RawFinding(FACTOR, "tls_old_protocol", f"Server negotiated outdated {protocol}",
                                   "medium", host))
    return findings


def handshake(host: str, port: int = 443, timeout: float = 5.0) -> dict | None:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                not_after = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), timezone.utc)
                return {"verified": True, "not_after": not_after, "protocol": tls.version()}
    except ssl.SSLCertVerificationError:
        return {"verified": False, "not_after": None, "protocol": None}
    except (OSError, ssl.SSLError):
        return None  # no TLS service reachable; not a finding


def collect(hosts: list[str]) -> tuple[list[RawFinding], int]:
    findings, assessed = [], 0
    for host in hosts:
        result = handshake(host)
        if result is None:
            continue
        assessed += 1
        findings += evaluate_certificate(host, result["not_after"], result["verified"], result["protocol"])
    return findings, assessed

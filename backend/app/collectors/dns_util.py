import dns.exception
import dns.resolver

_resolver = dns.resolver.Resolver()
_resolver.lifetime = 5.0


class LookupFailed(Exception):
    """DNS could not be queried reliably, so absence of a record proves nothing."""


def resolve(name: str, rtype: str) -> list:
    try:
        return list(_resolver.resolve(name, rtype))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except (dns.resolver.NoNameservers, dns.exception.Timeout) as exc:
        raise LookupFailed(f"{rtype} {name}: {exc}") from exc


def zone_is_reachable(domain: str) -> bool:
    """True when the domain's own nameservers answer. Guards against reporting
    'missing SPF/DMARC' when the scanner's DNS is broken or filtered."""
    try:
        return bool(resolve(domain, "NS"))
    except LookupFailed:
        return False


def txt_records(name: str) -> list[str]:
    return [b"".join(r.strings).decode(errors="replace") for r in resolve(name, "TXT")]

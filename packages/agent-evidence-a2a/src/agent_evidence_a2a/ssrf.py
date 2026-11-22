"""A reference webhook SSRF judge: refuse a URL whose host is, or resolves to, a non-global address."""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable, Iterable

Resolver = Callable[[str], Iterable[str]]
"""Maps a host name to the addresses an HTTP client would connect to."""

_SCHEMES = ("http", "https")
_LOCALHOST = "localhost"


def system_resolver(host: str) -> tuple[str, ...]:
    """Resolve *host* through the operating system; raises ``OSError`` when it has no address."""
    return tuple(sorted({str(info[4][0]) for info in socket.getaddrinfo(host, None)}))


def recorded_resolver() -> Resolver:
    """Return a resolver that answers from the addresses the corpus recorded, so a run needs no network."""
    from agent_evidence_a2a.corpus import load_ssrf

    table: dict[str, tuple[str, ...]] = {}
    for case in load_ssrf():
        host = _authority_host(case.url)
        if host is not None and case.addrs:
            table.setdefault(host, case.addrs)

    def resolve(host: str) -> tuple[str, ...]:
        if host not in table:
            raise OSError(host)
        return table[host]

    return resolve


def _authority_host(url: str) -> str | None:
    """Return the lower-cased host of an http(s) URL by RFC 3986: the authority ends at ``/``, ``?`` or ``#``."""
    scheme, sep, rest = url.partition("://")
    if not sep or scheme.lower() not in _SCHEMES:
        return None
    authority = rest.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    hostport = authority.rpartition("@")[2]
    if hostport.startswith("["):
        host, close, _ = hostport[1:].partition("]")
        return host.lower() if close else None
    return hostport.partition(":")[0].lower().rstrip(".") or None


def _ipv4_part(part: str) -> int | None:
    """Parse one dotted component as decimal, ``0x`` hexadecimal or leading-zero octal."""
    try:
        if part[:2].lower() == "0x":
            return int(part[2:] or "0", 16)
        if len(part) > 1 and part[0] == "0":
            return int(part, 8)
        return int(part, 10) if part.isdigit() else None
    except ValueError:
        return None


def _ipv4_numbers(host: str) -> list[int] | None:
    """Return the numeric value of each dotted component of *host*, or None when it is not one to four numbers."""
    parts = host.split(".")
    if not 1 <= len(parts) <= 4:
        return None
    values = [_ipv4_part(p) for p in parts]
    if any(v is None for v in values):
        return None
    return [v for v in values if v is not None]


def _legacy_ipv4(host: str) -> ipaddress.IPv4Address | None:
    """Parse the short, decimal, hex and octal IPv4 forms a socket library accepts (``127.1``, ``2130706433``)."""
    numbers = _ipv4_numbers(host)
    if numbers is None:
        return None
    head, last = numbers[:-1], numbers[-1]
    if any(v > 255 for v in head) or last >= 256 ** (5 - len(numbers)):
        return None
    total = last
    for index, value in enumerate(head):
        total += value << (8 * (3 - index))
    return ipaddress.IPv4Address(total)


def _is_global(address: str) -> bool:
    parsed = ipaddress.ip_address(address)
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
        parsed = parsed.ipv4_mapped
    return parsed.is_global


def literal_address(host: str) -> str | None:
    """Return the address an IP literal names in any spelling a socket library accepts, or None for a name."""
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    legacy = _legacy_ipv4(host)
    return None if legacy is None else str(legacy)


def resolved_addresses(host: str, resolve: Resolver) -> tuple[str, ...]:
    """Return the addresses a client would connect to for *host*: the literal it spells, or the resolver's answer."""
    if host == _LOCALHOST or host.endswith(f".{_LOCALHOST}"):
        return ("127.0.0.1", "::1")
    literal = literal_address(host)
    return (literal,) if literal is not None else tuple(resolve(host))


def judge_url(url: str, resolve: Resolver = system_resolver) -> bool:
    """Return True when the webhook *url* must be refused; anything unparseable or unresolvable is refused too."""
    host = _authority_host(url)
    if host is None:
        return True
    try:
        addresses = resolved_addresses(host, resolve)
        return not addresses or any(not _is_global(a) for a in addresses)
    except (OSError, ValueError):
        return True


def recorded_judge() -> Callable[[str], bool]:
    """Return :func:`judge_url` bound to the corpus's recorded addresses, the judge the CLI scores by default."""
    resolver = recorded_resolver()
    return lambda url: judge_url(url, resolver)

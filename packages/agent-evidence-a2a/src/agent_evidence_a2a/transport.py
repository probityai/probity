"""Judge an A2A endpoint's transport posture: AUTH-TLS-001, AUTH-TLS-002 and AUTH-SERVER-001.

The a2a-tck marks these three requirements not automatable and ships no test for them.  Each one is
decided here from at most one TCP endpoint and two TLS handshakes, with no model and no heuristic:

* **AUTH-TLS-001 (MUST).**  The endpoint's scheme is ``https``.  A plaintext scheme violates it, decided
  from the URL alone; the two session requirements are then not applicable.
* **AUTH-TLS-002 (SHOULD).**  The negotiated version reaches TLS 1.3, the floor A2A section 7.1
  recommends.
* **AUTH-SERVER-001 (SHOULD).**  The server's chain verifies against the system trust store for the
  endpoint's host name.

A requirement the probe could not decide is ``not-assessed``, never ``met``: an endpoint that has no
host, refuses the connection, or names an address the caller may not dial gives no TLS session to
judge, and the probe cannot tell a server that refuses TLS from a network fault.

The URL comes from an agent card, which is untrusted, so the probe is an SSRF surface.  The handshake
dials only addresses its caller has already checked, never a name: :func:`probe` checks them with
:func:`checked_addresses`, and a host product passes the addresses its own connect guard returned.
"""

from __future__ import annotations

import ipaddress
import socket
import ssl
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Final
from urllib.parse import urlsplit

from agent_evidence_a2a.ssrf import Resolver, literal_address, resolved_addresses, system_resolver

#: The modern floor for AUTH-TLS-002: A2A 7.1 (v1.0.0 and v1.0.1) recommends TLS 1.3 or later.
MODERN_TLS_FLOOR: Final = ssl.TLSVersion.TLSv1_3

#: Seconds allowed for the TCP connect and, separately, for the TLS handshake.
DEFAULT_TIMEOUT: Final = 10.0

_DEFAULT_HTTPS_PORT: Final = 443

#: Cloud credential endpoints that stay refused even when the caller owns local targets.
_METADATA_ADDRESSES: Final = frozenset(
    {
        ipaddress.ip_address("100.100.100.200"),  # Alibaba Cloud
        ipaddress.ip_address("fd00:ec2::254"),  # AWS over IPv6
    }
)


class Requirement(StrEnum):
    """The three a2a-tck requirement ids this module decides."""

    TLS_001 = "AUTH-TLS-001"
    TLS_002 = "AUTH-TLS-002"
    SERVER_001 = "AUTH-SERVER-001"


#: The normative level of each requirement in the A2A specification.
LEVELS: Final[Mapping[Requirement, str]] = MappingProxyType(
    {
        Requirement.TLS_001: "MUST",
        Requirement.TLS_002: "SHOULD",
        Requirement.SERVER_001: "SHOULD",
    }
)

_SESSION: Final = (Requirement.TLS_002, Requirement.SERVER_001)


class Outcome(StrEnum):
    """What the probe concluded about one requirement."""

    MET = "met"
    VIOLATED = "violated"
    #: The requirement judges a TLS session and the scheme carries none.
    NOT_APPLICABLE = "not-applicable"
    #: No verdict either way; a gate reads this as blocking, never as met.
    NOT_ASSESSED = "not-assessed"


class HandshakeErrorKind(StrEnum):
    """Why a handshake attempt established no session, so an outage is never read as a weak posture."""

    NONE = "none"
    #: The TCP connection failed (refused, reset, timeout, no route): nothing about TLS is known.
    NETWORK = "network"
    #: TCP reached the server and the TLS handshake failed: a transport-posture signal.
    TLS = "tls"
    #: The connect guard refused the target and no socket was opened.
    REFUSED_TARGET = "refused_target"


@dataclass(frozen=True, slots=True)
class TlsHandshakeResult:
    """The observable outcome of one handshake: whether a session exists, its version and chain status."""

    connected: bool
    negotiated_version: ssl.TLSVersion | None
    cert_verified: bool
    #: The failure text, or the negotiated cipher on success.
    detail: str
    error_kind: HandshakeErrorKind = HandshakeErrorKind.NONE


@dataclass(frozen=True, slots=True)
class RequirementResult:
    """The probe's conclusion about one requirement, with the sentence that explains it."""

    requirement: Requirement
    outcome: Outcome
    detail: str

    @property
    def level(self) -> str:
        """``MUST`` or ``SHOULD``."""
        return LEVELS[self.requirement]


@dataclass(frozen=True, slots=True)
class TransportReport:
    """One endpoint's three results, in requirement order."""

    endpoint: str
    results: tuple[RequirementResult, ...]

    @property
    def passed(self) -> bool:
        """True only when every requirement is met or not applicable; not assessed is never a pass."""
        return all(r.outcome in {Outcome.MET, Outcome.NOT_APPLICABLE} for r in self.results)

    def to_json(self) -> dict[str, object]:
        """A JSON-ready view keyed by requirement id."""
        return {
            "endpoint": self.endpoint,
            "passed": self.passed,
            "results": [
                {"id": str(r.requirement), "level": r.level, "outcome": str(r.outcome), "detail": r.detail}
                for r in self.results
            ],
        }


@dataclass(frozen=True, slots=True)
class SessionTarget:
    """An ``https`` endpoint whose TLS session must be observed before the two SHOULDs can be judged."""

    endpoint: str
    host: str
    port: int


class TargetRefusedError(Exception):
    """The endpoint's host names or resolves to an address the caller may not dial."""


def _met_tls_001(endpoint: str) -> RequirementResult:
    return RequirementResult(Requirement.TLS_001, Outcome.MET, f"the endpoint {endpoint!r} uses https.")


def _session_results(outcome: Outcome, detail: str) -> tuple[RequirementResult, ...]:
    return tuple(RequirementResult(req, outcome, detail) for req in _SESSION)


def plan(endpoint: str) -> SessionTarget | TransportReport:
    """Decide what the URL alone decides; return the session to observe when the URL leaves anything open."""
    parts = urlsplit(endpoint)
    scheme = parts.scheme.lower()
    if scheme != "https":
        violated = RequirementResult(
            Requirement.TLS_001,
            Outcome.VIOLATED,
            f"the declared endpoint {endpoint!r} uses the plaintext {scheme!r} scheme; A2A production "
            f"deployments MUST use encrypted (TLS) transport.",
        )
        why = f"the endpoint {endpoint!r} uses the {scheme!r} scheme, which carries no TLS session to judge."
        return TransportReport(endpoint, (violated, *_session_results(Outcome.NOT_APPLICABLE, why)))
    host = parts.hostname
    try:
        port = parts.port or _DEFAULT_HTTPS_PORT
    except ValueError as exc:
        return unassessed(endpoint, f"the https endpoint {endpoint!r} has no valid port ({exc})")
    if not host:
        return unassessed(endpoint, f"the https endpoint {endpoint!r} has no host to connect to")
    return SessionTarget(endpoint, host, port)


def unassessed(endpoint: str, why: str) -> TransportReport:
    """AUTH-TLS-001 met and both session requirements not assessed, because no session could be judged."""
    detail = (
        f"{why}, so its TLS posture cannot be verified, and a posture that cannot be verified blocks rather "
        f"than passes."
    )
    return TransportReport(endpoint, (_met_tls_001(endpoint), *_session_results(Outcome.NOT_ASSESSED, detail)))


def judge(target: SessionTarget, result: TlsHandshakeResult) -> TransportReport:
    """Judge AUTH-TLS-002 and AUTH-SERVER-001 from the observed handshake."""
    endpoint = target.endpoint
    if result.error_kind is HandshakeErrorKind.REFUSED_TARGET:
        return unassessed(
            endpoint,
            f"refused to connect to {endpoint!r}: {result.detail}; the declared endpoint is a loopback, private "
            f"or cloud-metadata address (an SSRF target), so no TLS session was opened",
        )
    if not result.connected:
        return unassessed(
            endpoint,
            f"could not establish a TLS session to {endpoint!r} ({result.detail}); the probe cannot tell a "
            f"subject that refuses TLS from a network fault",
        )
    version = result.negotiated_version
    if version is None:
        tls_002 = RequirementResult(
            Requirement.TLS_002,
            Outcome.NOT_ASSESSED,
            f"the session to {endpoint!r} reported no TLS version the probe recognises, so the floor cannot be judged.",
        )
    elif version < MODERN_TLS_FLOOR:
        tls_002 = RequirementResult(
            Requirement.TLS_002,
            Outcome.VIOLATED,
            f"the endpoint {endpoint!r} negotiated {version.name}, below the modern TLS 1.3 floor; a modern TLS "
            f"configuration is recommended.",
        )
    else:
        tls_002 = RequirementResult(
            Requirement.TLS_002, Outcome.MET, f"the endpoint {endpoint!r} negotiated {version.name}."
        )
    if result.cert_verified:
        server = RequirementResult(
            Requirement.SERVER_001, Outcome.MET, f"the server at {endpoint!r} presented a chain that verifies."
        )
    else:
        server = RequirementResult(
            Requirement.SERVER_001,
            Outcome.VIOLATED,
            f"the server at {endpoint!r} did not present a cert chain that verifies against the system trust "
            f"store ({result.detail}); a client SHOULD be able to verify the server's TLS certificate.",
        )
    return TransportReport(endpoint, (_met_tls_001(endpoint), tls_002, server))


def checked_addresses(host: str, *, allow_local: bool = False, resolve: Resolver = system_resolver) -> tuple[str, ...]:
    """Resolve *host* and return its addresses, refusing any the caller may not dial.

    Without *allow_local* every address must be globally routable.  With it, loopback and private
    addresses are allowed (the caller owns the agent), but a link-local address, which covers the
    169.254.169.254 metadata service, and the other cloud metadata addresses stay refused.  Every
    spelling the socket library accepts (``2852039166``, ``0xA9FEA9FE``, ``127.1``, IPv4-mapped IPv6)
    is read as the address it names.

    Raises:
        TargetRefusedError: when any address is refused or the host does not resolve.
    """
    try:
        addresses = resolved_addresses(host, resolve)
    except (OSError, ValueError) as exc:
        raise TargetRefusedError(f"{host!r} does not resolve ({exc})") from exc
    if not addresses:
        raise TargetRefusedError(f"{host!r} resolves to no address")
    for text in addresses:
        address = ipaddress.ip_address(text)
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
            address = address.ipv4_mapped
        if address.is_link_local or address in _METADATA_ADDRESSES:
            raise TargetRefusedError(f"{host!r} names the link-local or cloud metadata address {address}")
        if not address.is_global and not allow_local:
            raise TargetRefusedError(f"{host!r} names the non-global address {address}")
    return addresses


def _dial(address: str, port: int, timeout: float) -> socket.socket:
    """Open the TCP connection; the one place a socket is created."""
    return socket.create_connection((address, port), timeout=timeout)


_VERSIONS: Final[Mapping[str, ssl.TLSVersion]] = MappingProxyType(
    {
        "SSLv3": ssl.TLSVersion.SSLv3,
        "TLSv1": ssl.TLSVersion.TLSv1,
        "TLSv1.1": ssl.TLSVersion.TLSv1_1,
        "TLSv1.2": ssl.TLSVersion.TLSv1_2,
        "TLSv1.3": ssl.TLSVersion.TLSv1_3,
    }
)


def _failed(kind: HandshakeErrorKind, exc: BaseException | None, fallback: str) -> TlsHandshakeResult:
    detail = fallback if exc is None else f"{type(exc).__name__}: {exc}"
    return TlsHandshakeResult(
        connected=False, negotiated_version=None, cert_verified=False, detail=detail, error_kind=kind
    )


def _attempt(
    addresses: tuple[str, ...], port: int, server_name: str, *, verify: bool, timeout: float
) -> TlsHandshakeResult:
    """One verifying or non-verifying handshake over the checked addresses; failure is data, never raised."""
    context = ssl.create_default_context()
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    network_failure: OSError | None = None
    for address in addresses:
        try:
            raw = _dial(address, port, timeout)
        except OSError as exc:
            network_failure = exc
            continue
        try:
            with context.wrap_socket(raw, server_hostname=server_name) as tls:
                version = _VERSIONS.get(tls.version() or "")
                cipher = tls.cipher()
        except OSError as exc:
            # TCP reached the server, so whatever ended the handshake (an alert, a non-TLS reply, a
            # reset mid-handshake, a chain that does not verify) is the server's TLS posture.
            return _failed(HandshakeErrorKind.TLS, exc, "")
        finally:
            raw.close()
        return TlsHandshakeResult(
            connected=True,
            negotiated_version=version,
            cert_verified=verify,
            detail=cipher[0] if cipher else "unknown-cipher",
        )
    return _failed(HandshakeErrorKind.NETWORK, network_failure, "no address to dial")


def handshake(
    addresses: tuple[str, ...], port: int, server_name: str, *, timeout: float = DEFAULT_TIMEOUT
) -> TlsHandshakeResult:
    """Observe the TLS posture at checked *addresses*, presenting *server_name* for SNI and the host check.

    The first pass verifies the chain against the system trust store; success settles both session
    requirements.  When it fails, a second pass without verification still observes the negotiated
    version, so a self-signed but modern server reports the chain and not a missing version.
    """
    verified = _attempt(addresses, port, server_name, verify=True, timeout=timeout)
    if verified.connected:
        return verified
    unverified = _attempt(addresses, port, server_name, verify=False, timeout=timeout)
    if unverified.connected:
        return TlsHandshakeResult(
            connected=True,
            negotiated_version=unverified.negotiated_version,
            cert_verified=False,
            detail=verified.detail,
        )
    return unverified


def server_name_for(host: str) -> str:
    """The name the handshake presents: the host itself, or the address an IP literal in any spelling names."""
    literal = literal_address(host)
    return host if literal is None else literal


Handshake = Callable[[tuple[str, ...], int, str], TlsHandshakeResult]
"""Observes one session: ``(checked addresses, port, server name) -> result``."""


def probe(
    endpoint: str,
    *,
    allow_local: bool = False,
    resolve: Resolver = system_resolver,
    observe: Handshake | None = None,
) -> TransportReport:
    """Probe one endpoint end to end: the URL, the address check, the handshake, the verdicts."""
    target = plan(endpoint)
    if isinstance(target, TransportReport):
        return target
    try:
        addresses = checked_addresses(target.host, allow_local=allow_local, resolve=resolve)
    except TargetRefusedError as exc:
        return judge(target, _failed(HandshakeErrorKind.REFUSED_TARGET, None, str(exc)))
    run = observe if observe is not None else handshake
    return judge(target, run(addresses, target.port, server_name_for(target.host)))

"""The open package's transport probe: AUTH-TLS-001/002 and AUTH-SERVER-001 against real local listeners."""

from __future__ import annotations

import datetime as dt
import json
import socket
import ssl
import threading
from typing import TYPE_CHECKING

import pytest
from agent_evidence_a2a.cli import main
from agent_evidence_a2a.transport import (
    HandshakeErrorKind,
    Outcome,
    Requirement,
    SessionTarget,
    TargetRefusedError,
    TlsHandshakeResult,
    TransportReport,
    checked_addresses,
    handshake,
    judge,
    plan,
    probe,
    server_name_for,
)
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


def _outcomes(report: TransportReport) -> dict[str, Outcome]:
    return {str(r.requirement): r.outcome for r in report.results}


def _self_signed(tmp_path: Path) -> tuple[Path, Path]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    return cert_path, key_path


def _serve(listener: socket.socket, context: ssl.SSLContext | None, stop: threading.Event) -> None:
    listener.settimeout(0.1)
    while not stop.is_set():
        try:
            conn, _ = listener.accept()
        except TimeoutError:
            continue
        with conn:
            conn.settimeout(2)
            try:
                if context is None:
                    conn.sendall(b"NOT-A-TLS-SERVERHELLO\r\n")
                else:
                    with context.wrap_socket(conn, server_side=True):
                        pass
            except OSError:
                pass


@pytest.fixture
def tls12_server(tmp_path: Path) -> Iterator[int]:
    """A self-signed local server that negotiates at most TLS 1.2; yields its port."""
    cert, key = _self_signed(tmp_path)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert, key)
    yield from _listening(context)


@pytest.fixture
def plain_server() -> Iterator[int]:
    """A local TCP server that answers a ClientHello with plain text; yields its port."""
    yield from _listening(None)


def _listening(context: ssl.SSLContext | None) -> Iterator[int]:
    listener = socket.create_server(("127.0.0.1", 0))
    stop = threading.Event()
    worker = threading.Thread(target=_serve, args=(listener, context, stop), daemon=True)
    worker.start()
    try:
        yield int(listener.getsockname()[1])
    finally:
        stop.set()
        worker.join(timeout=5)
        listener.close()


def test_a_plaintext_scheme_violates_the_must_and_needs_no_connection() -> None:
    report = plan("http://agent.example.com/a2a")
    assert isinstance(report, TransportReport)
    assert _outcomes(report) == {
        "AUTH-TLS-001": Outcome.VIOLATED,
        "AUTH-TLS-002": Outcome.NOT_APPLICABLE,
        "AUTH-SERVER-001": Outcome.NOT_APPLICABLE,
    }
    assert not report.passed


@pytest.mark.parametrize("url", ["https:///no-host", "https://agent.example.com:99999/a2a"])
def test_an_https_url_with_no_host_or_port_is_not_assessed_never_met(url: str) -> None:
    report = plan(url)
    assert isinstance(report, TransportReport)
    assert _outcomes(report)["AUTH-TLS-001"] is Outcome.MET
    assert {_outcomes(report)[r] for r in ("AUTH-TLS-002", "AUTH-SERVER-001")} == {Outcome.NOT_ASSESSED}
    assert not report.passed


def test_a_verified_tls13_session_passes_every_requirement() -> None:
    target = SessionTarget("https://agent.example.com", "agent.example.com", 443)
    session = TlsHandshakeResult(True, ssl.TLSVersion.TLSv1_3, True, "TLS_AES_256_GCM_SHA384")
    report = judge(target, session)
    assert set(_outcomes(report).values()) == {Outcome.MET}
    assert report.passed


def test_a_session_with_no_recognised_version_leaves_the_floor_unjudged() -> None:
    target = SessionTarget("https://agent.example.com", "agent.example.com", 443)
    report = judge(target, TlsHandshakeResult(True, None, True, "cipher"))
    assert _outcomes(report)["AUTH-TLS-002"] is Outcome.NOT_ASSESSED


@pytest.mark.parametrize(
    "host", ["169.254.169.254", "2852039166", "0xA9FEA9FE", "::ffff:169.254.169.254", "100.100.100.200"]
)
def test_a_metadata_address_is_refused_even_for_a_local_target(host: str) -> None:
    with pytest.raises(TargetRefusedError):
        checked_addresses(host, allow_local=True)


@pytest.mark.parametrize("host", ["127.0.0.1", "2130706433", "127.1", "localhost", "10.0.0.5"])
def test_a_loopback_or_private_address_needs_the_local_opt_in(host: str) -> None:
    with pytest.raises(TargetRefusedError):
        checked_addresses(host)
    assert checked_addresses(host, allow_local=True)


def test_a_name_resolving_anywhere_non_global_is_refused() -> None:
    def split(_host: str) -> tuple[str, ...]:
        return ("93.184.215.14", "192.168.1.9")

    with pytest.raises(TargetRefusedError):
        checked_addresses("agent.example.com", resolve=split)
    assert checked_addresses("agent.example.com", resolve=lambda _h: ("93.184.215.14",)) == ("93.184.215.14",)


def test_a_refused_target_is_never_dialled() -> None:
    dialled: list[tuple[str, ...]] = []

    def observe(addresses: tuple[str, ...], port: int, server_name: str) -> TlsHandshakeResult:
        dialled.append(addresses)
        return TlsHandshakeResult(True, ssl.TLSVersion.TLSv1_3, True, "canary")

    report = probe("https://2852039166/a2a", allow_local=True, observe=observe)
    assert dialled == []
    assert "refused to connect" in report.results[1].detail
    assert _outcomes(report)["AUTH-SERVER-001"] is Outcome.NOT_ASSESSED


def test_the_server_name_is_the_address_an_integer_literal_spells() -> None:
    assert server_name_for("2130706433") == "127.0.0.1"
    assert server_name_for("agent.example.com") == "agent.example.com"


def test_a_real_self_signed_tls12_server_violates_both_shoulds(tls12_server: int) -> None:
    report = probe(f"https://localhost:{tls12_server}/a2a", allow_local=True)
    assert _outcomes(report) == {
        "AUTH-TLS-001": Outcome.MET,
        "AUTH-TLS-002": Outcome.VIOLATED,
        "AUTH-SERVER-001": Outcome.VIOLATED,
    }
    assert "TLSv1_2" in report.results[1].detail
    assert "system trust store" in report.results[2].detail


def test_a_closed_port_is_a_network_failure_not_a_tls_verdict() -> None:
    probe_socket = socket.create_server(("127.0.0.1", 0))
    port = int(probe_socket.getsockname()[1])
    probe_socket.close()
    result = handshake(("127.0.0.1",), port, "127.0.0.1", timeout=2)
    assert result.error_kind is HandshakeErrorKind.NETWORK
    assert not result.connected


def test_a_server_that_speaks_no_tls_is_a_tls_failure(plain_server: int) -> None:
    result = handshake(("127.0.0.1",), plain_server, "127.0.0.1", timeout=2)
    assert result.error_kind is HandshakeErrorKind.TLS


def test_the_cli_prints_every_requirement_and_exits_1_on_a_violation(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["tls", "http://agent.example.com/a2a"]) == 1
    (report,) = json.loads(capsys.readouterr().out)
    assert report["passed"] is False
    assert [(r["id"], r["level"], r["outcome"]) for r in report["results"]] == [
        (str(Requirement.TLS_001), "MUST", "violated"),
        (str(Requirement.TLS_002), "SHOULD", "not-applicable"),
        (str(Requirement.SERVER_001), "SHOULD", "not-applicable"),
    ]

"""The observer records the declared side (discovery) and the acted side (calls) in one witnessed trajectory."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from probity_observer import (
    SigningKey,
    TrajectoryWitness,
    VerificationError,
    verify_trajectory,
)
from probity_observer.resolution import ResolutionObserver

SVCB = ['_a2a._agents.example.com. 300 IN SVCB 1 agent.example.com. alpn="a2a" port=443']
JWKS = b'{"keys":[{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}]}'
CHAIN = b"\x00\x01dnssec-chain-wire-bytes"


def _witness(tmp_path: Path) -> TrajectoryWitness:
    """A witness under an ephemeral key with its registry in the test directory."""
    return TrajectoryWitness(SigningKey.generate(), tmp_path / "registry")


def _three_calls(path: Path, witness: TrajectoryWitness) -> ResolutionObserver:
    observer = ResolutionObserver(path, trajectory_id="run-1", witness=witness)
    seq = observer.resolved(name="_a2a._agents.example.com", svcb=SVCB, sig="eyJhbGciOiJFZERTQSJ9..sig",
                            jwks_url="https://example.com/.well-known/jwks.json", jwks_bytes=JWKS,
                            dnssec_chain=CHAIN, at="2026-11-15T20:00:00Z")
    observer.called(endpoint="https://agent.example.com:443", at="2026-11-15T20:00:01Z", resolution=seq)
    observer.called(endpoint="https://elsewhere.example.net:443", at="2026-11-15T20:00:02Z", resolution=seq)
    observer.called(endpoint="https://agent.example.com:443", at="2026-11-16T20:00:03Z", resolution=seq)
    return observer


def test_three_call_trajectory_verifies_and_binds_bytes(tmp_path: Path) -> None:
    path = tmp_path / "observed.jsonl"
    witness = _witness(tmp_path)
    observer = _three_calls(path, witness)
    head = observer.trajectory.close()
    assert verify_trajectory(path, head, witness.public_hex, trajectory_id="run-1")["count"] == 4
    events = [json.loads(line)["event"] for line in path.read_bytes().splitlines()]
    assert [event["kind"] for event in events] == ["resolution", "call", "call", "call"]
    assert events[0]["jwks"]["sha256"] == hashlib.sha256(JWKS).hexdigest()
    assert events[0]["dnssec_chain_sha256"] == hashlib.sha256(CHAIN).hexdigest()
    assert events[0]["svcb"] == SVCB
    assert {event["resolution"] for event in events[1:]} == {1}


def test_unchained_resolution_records_null(tmp_path: Path) -> None:
    observer = ResolutionObserver(tmp_path / "o.jsonl", trajectory_id="run-1", witness=_witness(tmp_path))
    observer.resolved(name="a.example", svcb=["a.example. 60 IN SVCB 1 ."], at="2026-11-15T20:00:00Z")
    event = json.loads((tmp_path / "o.jsonl").read_bytes().splitlines()[0])["event"]
    assert event["dnssec_chain_sha256"] is None and event["jwks"] is None and event["sig"] is None


def test_call_without_discovery_is_recorded_as_such(tmp_path: Path) -> None:
    observer = ResolutionObserver(tmp_path / "o.jsonl", trajectory_id="run-1", witness=_witness(tmp_path))
    observer.called(endpoint="https://direct.example", at="2026-11-15T20:00:00Z", resolution=None)
    event = json.loads((tmp_path / "o.jsonl").read_bytes().splitlines()[0])["event"]
    assert event["resolution"] is None


@pytest.mark.parametrize("kwargs, message", [
    ({"svcb": []}, "at least one record"),
    ({"jwks_url": "https://example.com/jwks"}, "go together"),
    ({"at": "2026-11-15 20:00:00"}, "RFC 3339"),
    ({"at": "\u0662\u0660\u0662\u0666-11-15T20:00:00Z"}, "RFC 3339"),
    ({"at": "2026-13-45T25:61:61Z"}, "not a calendar time"),
    ({"at": "2016-12-31T23:59:60Z"}, "not a calendar time"),
    ({"name": ""}, "non-empty ASCII"),
    ({"dnssec_chain": "text not bytes"}, "bytes as received"),
])
def test_resolution_refusals(tmp_path: Path, kwargs: dict, message: str) -> None:
    observer = ResolutionObserver(tmp_path / "o.jsonl", trajectory_id="run-1", witness=_witness(tmp_path))
    arguments = {"name": "a.example", "svcb": ["a.example. 60 IN SVCB 1 ."], "at": "2026-11-15T20:00:00Z", **kwargs}
    with pytest.raises(VerificationError, match=message):
        observer.resolved(**arguments)
    assert observer.trajectory.count == 0


def test_call_cannot_name_an_unrecorded_resolution(tmp_path: Path) -> None:
    observer = ResolutionObserver(tmp_path / "o.jsonl", trajectory_id="run-1", witness=_witness(tmp_path))
    with pytest.raises(VerificationError, match="recorded earlier"):
        observer.called(endpoint="https://x.example", at="2026-11-15T20:00:00Z", resolution=1)


@pytest.mark.parametrize("resolution", [True, 1.0, "1"])
def test_call_names_its_resolution_by_integer_seq(tmp_path: Path, resolution: object) -> None:
    """Counter-example: True == 1 in Python, so a membership test alone wrote "resolution": true."""
    observer = ResolutionObserver(tmp_path / "o.jsonl", trajectory_id="run-1", witness=_witness(tmp_path))
    observer.resolved(name="a.example", svcb=["a.example. 60 IN SVCB 1 ."], at="2026-11-15T20:00:00Z")
    with pytest.raises(VerificationError, match="integer seq"):
        observer.called(endpoint="https://x.example", at="2026-11-15T20:00:01Z", resolution=resolution)  # type: ignore[arg-type]
    assert observer.trajectory.count == 1

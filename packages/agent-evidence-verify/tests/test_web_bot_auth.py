"""web_bot_auth/v1: one signed request, judged under a pinned signer, directory, authority and clock.

The signing helper writes the signature base by hand from the component list, so the adapter's own base
builder is never the oracle for a request it also signed. The draft's Appendix E.2.1 request (the one signed
with RFC 9421's published test key) is the independent check that the adapter's base matches the specification.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import pytest
from agent_evidence_verify import adjudicate
from agent_evidence_verify.adapters import _sf as sf
from agent_evidence_verify.adapters import web_bot_auth as wba
from agent_evidence_verify.common import CaseError
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def key_of(seed: int) -> tuple[Ed25519PrivateKey, dict[str, str]]:
    private = Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)
    x = b64url(private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
    thumbprint = hashlib.sha256(json.dumps({"crv": "Ed25519", "kty": "OKP", "x": x}, separators=(",", ":"),
                                           sort_keys=True).encode()).digest()
    return private, {"kty": "OKP", "crv": "Ed25519", "x": x, "kid": b64url(thumbprint)}


KEY, JWK = key_of(7)
OTHER, OTHER_JWK = key_of(9)
AGENT = "https://agent.example/.well-known/http-message-signatures-directory"
AUTHORITY = "api.example"
URL = "https://api.example/v1/run?x=1"
BODY = b'{"task":"deploy"}'
NOW = int(datetime(2026, 11, 21, 12, 0, 0, tzinfo=UTC).timestamp())
AT = "2026-11-21T12:00:00Z"
COMPONENTS = ('"@method"', '"@authority"', '"content-digest"', '"signature-agent";key="agent1"')


def derived(identifier: str, method: str, url: str, headers: dict[str, str]) -> str:
    name = identifier.split(";")[0].strip('"')
    parts = urlsplit(url)
    if name == "@method":
        return method
    if name == "@authority":
        host = parts.netloc.lower()
        suffix = {"http": ":80", "https": ":443"}[parts.scheme]
        return host.removesuffix(suffix)
    if name == "@path":
        return parts.path
    if name == "signature-agent":
        return headers["signature-agent"].split("=", 1)[1]
    return headers[name]


def signed_request(*, method: str = "POST", url: str = URL, body: bytes | None = BODY, created: int = NOW - 30,
                   expires: int = NOW + 270, components: tuple[str, ...] = COMPONENTS, agent: str = AGENT,
                   key: Ed25519PrivateKey = KEY, keyid: str | None = None, label: str = "sig1",
                   tag: str = "web-bot-auth", alg: str | None = "ed25519") -> dict[str, Any]:
    headers = {"signature-agent": f'agent1="{agent}"'}
    if body is not None:
        headers["content-digest"] = f"sha-256=:{base64.b64encode(hashlib.sha256(body).digest()).decode()}:"
    params = f'({" ".join(components)});created={created};expires={expires};keyid="{keyid or JWK["kid"]}"'
    params += (f';alg="{alg}"' if alg else "") + f';nonce="n-1";tag="{tag}"'
    lines = [f"{c}: {derived(c, method, url, headers)}" for c in components]
    base = "\n".join([*lines, f'"@signature-params": {params}'])
    signature = base64.b64encode(key.sign(base.encode("ascii"))).decode("ascii")
    pairs = [["Host", urlsplit(url).netloc], ["Signature-Agent", headers["signature-agent"]]]
    if "content-digest" in headers:
        pairs.append(["Content-Digest", headers["content-digest"]])
    pairs += [["Signature-Input", f"{label}={params}"], ["Signature", f"{label}=:{signature}:"]]
    return {"method": method, "url": url, "headers": pairs}


def judge(root: Path, request: dict | bytes | None, *, directory: dict | bytes | None = None,
          body: bytes | None = BODY, **overrides: Any) -> dict:
    """Write the bound artifacts and adjudicate. ``overrides`` replace assessment members; ``None`` drops one."""
    artifacts: dict[str, dict] = {}

    def bind(name: str, data: bytes | None) -> str | None:
        if data is None:
            return None
        (root / name).write_bytes(data)
        artifacts[name] = {"path": name, "length": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        return name

    def encode(value: dict | bytes | None) -> bytes | None:
        return value if value is None or isinstance(value, bytes) else json.dumps(value).encode()

    directory_bytes = encode(directory if directory is not None else {"keys": [JWK]})
    assert directory_bytes is not None
    assessment: dict[str, Any] = {
        "claim_type": wba.CLAIM_TYPE, "request": bind("request", encode(request)) or "request",
        "directory": bind("directory", directory_bytes), "directory_sha256": hashlib.sha256(directory_bytes).hexdigest(),
        "signature_agent": AGENT, "authority": AUTHORITY, "at": AT,
    }
    if body is not None:
        assessment["body"] = bind("body", body)
    for name, value in overrides.items():
        if value is None:
            assessment.pop(name, None)
        else:
            assessment[name] = value
    case = {"schema_version": "probity-case/v1", "case_id": "c", "artifacts": artifacts}
    policy = {"schema_version": "probity-policy/v1", "assessments": {"c": assessment}}
    return adjudicate(case, policy, root)


def verdict(result: dict) -> tuple[str, str]:
    return result["decision"], result["reason"]


def test_signed_request_is_supported(tmp_path: Path) -> None:
    result = judge(tmp_path, signed_request())
    assert verdict(result) == ("supported", "request_signed_by_pinned_agent")
    assert all(check["status"] == "met" for check in result["checks"])
    assert result["scope"]["record"]["keyid"] == JWK["kid"]


def test_bodyless_request_needs_no_content_digest(tmp_path: Path) -> None:
    request = signed_request(method="GET", body=None, components=('"@method"', '"@authority"',
                                                                    '"signature-agent";key="agent1"'))
    assert verdict(judge(tmp_path, request, body=None)) == ("supported", "request_signed_by_pinned_agent")


# -- the draft's own example, signed with RFC 9421's published test key: an oracle that is not our signer -----

DRAFT_REQUEST = {
    "method": "POST", "url": "https://example.com/foo?param=Value&Pet=dog",
    "headers": [
        ["Host", "example.com"], ["Date", "Tue, 20 Apr 2021 02:07:55 GMT"], ["Content-Type", "application/json"],
        ["Signature-Agent", 'agent2="https://signature-agent.test"'],
        ["Signature-Input", ('sig2=("@authority" "signature-agent";key="agent2");created=1735689600;'
                             'keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=4889289600;'
                             'nonce="n9p433xm+NJ3ph3upfBIGmsuwHw387YV7Q/F+6BSpGCVjYCqQw6rznNA8PVVLySrAWsv0hQtFioQb6E1YsauiA==";'
                             'tag="web-bot-auth"')],
        ["Signature", "sig2=:RdNFx5Bj6au3YgAMQL/RzmUlZE8QZLIaXGRpw985hWnwPfMxT228NMk6ehRS1PSl4e8PhbNZACSanGdhEwYCCg==:"],
    ],
}
DRAFT_DIRECTORY = {"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U",
                             "x": "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs", "use": "sig"}]}
DRAFT_BASE = ('"@authority": example.com\n"signature-agent";key="agent2": "https://signature-agent.test"\n'
              '"@signature-params": ("@authority" "signature-agent";key="agent2");created=1735689600;'
              'keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=4889289600;'
              'nonce="n9p433xm+NJ3ph3upfBIGmsuwHw387YV7Q/F+6BSpGCVjYCqQw6rznNA8PVVLySrAWsv0hQtFioQb6E1YsauiA==";'
              'tag="web-bot-auth"')
DRAFT_ASSESSMENT = {"signature_agent": "https://signature-agent.test", "authority": "example.com",
                    "at": "2026-10-14T12:00:00Z"}


def test_signature_base_matches_the_drafts_example() -> None:
    request = wba._request(json.dumps(DRAFT_REQUEST).encode())
    inner = sf.parse_dictionary(request.field_value("signature-input") or "")["sig2"]
    assert isinstance(inner, sf.InnerList)
    assert wba.signature_base(request, inner) == DRAFT_BASE


def test_the_drafts_example_verifies_only_when_the_test_key_is_allowed(tmp_path: Path) -> None:
    refused = judge(tmp_path, DRAFT_REQUEST, directory=DRAFT_DIRECTORY, body=None, **DRAFT_ASSESSMENT)
    assert verdict(refused) == ("contradicted", "test_key_refused")
    allowed = judge(tmp_path, DRAFT_REQUEST, directory=DRAFT_DIRECTORY, body=None, allow_test_keys=True,
                    **DRAFT_ASSESSMENT)
    assert verdict(allowed) == ("supported", "request_signed_by_pinned_agent")


# -- adversarial: each of these must fail closed, and each names why ---------------------------------------------


def edit(request: dict, name: str, value: str | None) -> dict:
    """The request with every line of header ``name`` replaced by one line ``value`` (dropped when ``None``)."""
    out = copy.deepcopy(request)
    out["headers"] = [h for h in out["headers"] if h[0].lower() != name.lower()]
    if value is not None:
        out["headers"].append([name, value])
    return out


FORGERIES = {
    "forged signature, victim keyid": (signed_request(key=OTHER), ("contradicted", "signature_invalid")),
    "unknown key, own keyid": (signed_request(key=OTHER, keyid=OTHER_JWK["kid"]),
                               ("not_established", "key_not_in_directory")),
    "expired": (signed_request(created=NOW - 600, expires=NOW - 300), ("contradicted", "signature_expired")),
    "expires exactly now": (signed_request(expires=NOW), ("contradicted", "signature_expired")),
    "created in the future": (signed_request(created=NOW + 120, expires=NOW + 400),
                              ("contradicted", "signature_created_in_future")),
    "expires before created": (signed_request(created=NOW - 10, expires=NOW - 20),
                               ("contradicted", "signature_parameters_invalid")),
    "other signer in Signature-Agent": (signed_request(agent="https://evil.example/.well-known/http-message-signatures-directory"),
                                        ("contradicted", "signature_agent_mismatch")),
    "replayed to another authority": (signed_request(url="https://other.example/v1/run?x=1"),
                                      ("contradicted", "authority_mismatch")),
    "wrong tag": (signed_request(tag="other"), ("contradicted", "signature_absent")),
    "alg downgrade": (signed_request(alg="rsa-pss-sha512"), ("contradicted", "signature_parameters_invalid")),
    "signature-agent not covered": (signed_request(components=('"@method"', '"@authority"', '"content-digest"')),
                                    ("contradicted", "component_not_covered")),
    "authority not covered": (signed_request(components=('"@method"', '"content-digest"', '"signature-agent";key="agent1"')),
                              ("contradicted", "component_not_covered")),
    "body not covered": (signed_request(components=('"@method"', '"@authority"', '"signature-agent";key="agent1"')),
                         ("contradicted", "body_not_covered")),
}


@pytest.mark.parametrize("name", sorted(FORGERIES))
def test_forged_replayed_and_downgraded_requests_fail_closed(tmp_path: Path, name: str) -> None:
    request, expected = FORGERIES[name]
    assert verdict(judge(tmp_path, request)) == expected


def test_replaced_body_is_contradicted_even_though_the_signature_verifies(tmp_path: Path) -> None:
    result = judge(tmp_path, signed_request(), body=b'{"task":"delete everything"}')
    assert verdict(result) == ("contradicted", "content_digest_mismatch")
    # The same request with the body it was signed over is supported: the signature itself was fine.
    assert verdict(judge(tmp_path, signed_request())) == ("supported", "request_signed_by_pinned_agent")


def test_content_digest_header_rewritten_to_match_a_new_body_breaks_the_signature(tmp_path: Path) -> None:
    new = b'{"task":"delete everything"}'
    digest = f"sha-256=:{base64.b64encode(hashlib.sha256(new).digest()).decode()}:"
    forged = edit(signed_request(), "Content-Digest", digest)
    assert verdict(judge(tmp_path, forged, body=new)) == ("contradicted", "signature_invalid")


def test_missing_content_digest_header_when_covered(tmp_path: Path) -> None:
    result = judge(tmp_path, edit(signed_request(), "Content-Digest", None))
    assert verdict(result)[0] == "contradicted"


def test_content_digest_with_only_unsupported_algorithms_is_contradicted(tmp_path: Path) -> None:
    request = edit(signed_request(), "Content-Digest", "md5=:AAAA:")
    assert verdict(judge(tmp_path, request)) == ("contradicted", "content_digest_unsupported")


def test_sha512_content_digest_is_checked(tmp_path: Path) -> None:
    request = signed_request()
    good = f"sha-512=:{base64.b64encode(hashlib.sha512(BODY).digest()).decode()}:"
    # Rewriting the covered header changes the signature base, so sign again over the new header value.
    headers = {"signature-agent": f'agent1="{AGENT}"', "content-digest": good}
    params = (f'("@method" "@authority" "content-digest" "signature-agent";key="agent1");created={NOW - 30};'
              f'expires={NOW + 270};keyid="{JWK["kid"]}";alg="ed25519";nonce="n-1";tag="web-bot-auth"')
    base = "\n".join([f"{c}: {derived(c, 'POST', URL, headers)}" for c in COMPONENTS]
                     + [f'"@signature-params": {params}'])
    request = edit(edit(edit(request, "Content-Digest", good), "Signature-Input", f"sig1={params}"),
                   "Signature", f"sig1=:{base64.b64encode(KEY.sign(base.encode())).decode()}:")
    assert verdict(judge(tmp_path, request)) == ("supported", "request_signed_by_pinned_agent")
    bad = edit(request, "Content-Digest", f"sha-512=:{base64.b64encode(hashlib.sha512(b'x').digest()).decode()}:")
    assert verdict(judge(tmp_path, bad))[0] == "contradicted"


@pytest.mark.parametrize(("header", "value", "reason"), [
    ("Signature-Input", "sig1=(", "signature_headers_malformed"),
    ("Signature-Input", None, "signature_absent"),
    ("Signature", None, "signature_absent"),
    ("Signature", "sig1=\"not-bytes\"", "signature_headers_malformed"),
    ("Signature", "other=:AAAA:", "signature_headers_malformed"),
    ("Signature-Agent", None, "signature_agent_mismatch"),
    ("Signature-Agent", 'agent1="https://agent.example/.well-known/http-message-signatures-directory";x=1',
     "signature_agent_mismatch"),
    ("Signature-Agent", "agent1=token-not-a-string", "signature_agent_mismatch"),
])
def test_malformed_or_absent_signature_headers_are_contradicted(tmp_path: Path, header: str, value: str | None,
                                                                reason: str) -> None:
    assert verdict(judge(tmp_path, edit(signed_request(), header, value))) == ("contradicted", reason)


def test_two_signature_input_lines_with_one_label_are_ambiguous_and_refused(tmp_path: Path) -> None:
    request = signed_request()
    request["headers"].append(["Signature-Input", dict(request["headers"])["Signature-Input"]])
    assert verdict(judge(tmp_path, request)) == ("contradicted", "signature_headers_malformed")


def test_a_signature_with_another_tag_is_skipped_and_the_web_bot_auth_one_is_read(tmp_path: Path) -> None:
    request = signed_request(label="sig2")
    request = edit(request, "Signature-Input", 'sig1=("@method");created=1;tag="other", '
                   + dict(request["headers"])["Signature-Input"])
    request = edit(request, "Signature", "sig1=:AAAA:, " + dict(signed_request(label="sig2")["headers"])["Signature"])
    assert verdict(judge(tmp_path, request)) == ("supported", "request_signed_by_pinned_agent")
    assert verdict(judge(tmp_path, request, label="sig1")) == ("contradicted", "signature_parameters_invalid")


def test_consumer_label_must_exist(tmp_path: Path) -> None:
    assert verdict(judge(tmp_path, signed_request(), label="nope")) == ("contradicted", "signature_absent")


# -- the consumer's own pins --------------------------------------------------------------------------------------


def test_a_different_directory_is_not_the_pinned_one(tmp_path: Path) -> None:
    other = {"keys": [JWK, OTHER_JWK]}
    pinned = hashlib.sha256(json.dumps({"keys": [JWK]}).encode()).hexdigest()
    result = judge(tmp_path, signed_request(), directory=other, directory_sha256=pinned)
    assert verdict(result) == ("not_established", "directory_not_pinned")


def test_key_the_directory_lacks_is_not_a_forgery_finding(tmp_path: Path) -> None:
    assert verdict(judge(tmp_path, signed_request(), directory={"keys": [OTHER_JWK]})) == (
        "not_established", "key_not_in_directory")


def test_keys_of_other_algorithms_in_the_directory_are_ignored(tmp_path: Path) -> None:
    directory = {"keys": [{"kty": "RSA", "n": "AQAB", "e": "AQAB", "kid": "r"}, JWK]}
    assert verdict(judge(tmp_path, signed_request(), directory=directory))[0] == "supported"


def test_unavailable_artifacts_are_not_established(tmp_path: Path) -> None:
    case = {"schema_version": "probity-case/v1", "case_id": "c",
            "artifacts": {"request": {"path": "gone", "length": 1, "sha256": "0" * 64}}}
    policy = {"schema_version": "probity-policy/v1", "assessments": {"c": {
        "claim_type": wba.CLAIM_TYPE, "request": "request", "directory": "request", "directory_sha256": "0" * 64,
        "signature_agent": AGENT, "authority": AUTHORITY, "at": AT}}}
    assert verdict(adjudicate(case, policy, tmp_path)) == ("not_established", "request_unavailable")


def test_required_components_are_enforced(tmp_path: Path) -> None:
    ok = judge(tmp_path, signed_request(), required_components=["@method", "content-digest"])
    assert ok["decision"] == "supported"
    result = judge(tmp_path, signed_request(), required_components=["@path"])
    assert verdict(result) == ("contradicted", "component_not_covered")


def test_age_and_window_limits(tmp_path: Path) -> None:
    assert verdict(judge(tmp_path, signed_request(), max_age_seconds=10)) == ("contradicted", "signature_too_old")
    assert verdict(judge(tmp_path, signed_request(), max_validity_seconds=100)) == (
        "contradicted", "validity_window_too_long")
    assert judge(tmp_path, signed_request(), max_age_seconds=30, max_validity_seconds=300)["decision"] == "supported"


def test_the_consumer_clock_decides_expiry_not_the_machine_clock(tmp_path: Path) -> None:
    assert judge(tmp_path, signed_request(), at="2026-11-21T12:04:00Z")["decision"] == "supported"
    assert verdict(judge(tmp_path, signed_request(), at="2026-11-21T12:05:00Z")) == (
        "contradicted", "signature_expired")


@pytest.mark.parametrize(("url", "authority", "default_port"), [
    ("http://api.example/v1", "api.example", True),
    ("http://api.example:80/v1", "api.example", True),
    ("https://api.example:443/v1", "api.example", True),
    ("https://api.example:8443/v1", "api.example:8443", False),
    ("https://API.Example/v1", "api.example", True),
    ("https://[2001:db8::1]:8443/v1", "[2001:db8::1]:8443", False),
])
def test_authority_follows_the_scheme_default_port(tmp_path: Path, url: str, authority: str,
                                                   default_port: bool) -> None:
    components = ('"@authority"', '"signature-agent";key="agent1"')
    request = signed_request(method="GET", url=url, body=None, components=components)
    result = judge(tmp_path, request, body=None, authority=authority)
    assert result["decision"] == "supported", (result["reason"], default_port)


def test_query_param_component(tmp_path: Path) -> None:
    components = ('"@authority"', '"@query-param";name="x"', '"signature-agent";key="agent1"')
    headers = {"signature-agent": f'agent1="{AGENT}"'}
    params = (f'({" ".join(components)});created={NOW - 30};expires={NOW + 270};keyid="{JWK["kid"]}";'
              f'alg="ed25519";nonce="n-1";tag="web-bot-auth"')
    base = "\n".join(['"@authority": api.example', '"@query-param";name="x": 1',
                      f'"signature-agent";key="agent1": "{AGENT}"', f'"@signature-params": {params}'])
    request = {"method": "GET", "url": URL, "headers": [
        ["Signature-Agent", headers["signature-agent"]], ["Signature-Input", f"sig1={params}"],
        ["Signature", f"sig1=:{base64.b64encode(KEY.sign(base.encode())).decode()}:"]]}
    assert verdict(judge(tmp_path, request, body=None)) == ("supported", "request_signed_by_pinned_agent")
    moved = {**request, "url": "https://api.example/v1/run?x=2"}
    assert verdict(judge(tmp_path, moved, body=None)) == ("contradicted", "signature_invalid")


def test_changed_method_breaks_the_signature(tmp_path: Path) -> None:
    request = signed_request()
    assert verdict(judge(tmp_path, {**request, "method": "PUT"})) == ("contradicted", "signature_invalid")


# -- invalid input is exit 2, never a verdict ---------------------------------------------------------------------


@pytest.mark.parametrize("mutate", [
    lambda r: {**r, "extra": 1},
    lambda r: {k: v for k, v in r.items() if k != "method"},
    lambda r: {**r, "method": "PO ST"},
    lambda r: {**r, "url": "/relative"},
    lambda r: {**r, "url": "https://user@api.example/"},
    lambda r: {**r, "url": "https://api.example:99999999/"},
    lambda r: {**r, "url": "https://api.example/#frag"},
    lambda r: {**r, "headers": "nope"},
    lambda r: {**r, "headers": [["only-one"]]},
    lambda r: {**r, "headers": [["bad name", "v"]]},
    lambda r: {**r, "headers": [["x", "a\r\nb: c"]]},
    lambda r: {**r, "headers": [["x", 1]]},
])
def test_malformed_request_capture_raises(tmp_path: Path, mutate) -> None:
    with pytest.raises(CaseError):
        judge(tmp_path, mutate(signed_request()))


def test_request_that_is_not_strict_json_raises(tmp_path: Path) -> None:
    with pytest.raises(CaseError):
        judge(tmp_path, b'{"method":"GET","method":"POST","url":"https://a.example/","headers":[]}')


@pytest.mark.parametrize("directory", [
    b"not json",
    {"keys": "nope"},
    {"keys": [{**JWK, "kid": "not-the-thumbprint"}]},
    {"keys": [JWK, JWK]},
    {"keys": [{**JWK, "x": "AAAA"}]},
    {"keys": [{**JWK, "x": JWK["x"] + "="}]},
])
def test_malformed_directory_raises(tmp_path: Path, directory: Any) -> None:
    with pytest.raises(CaseError):
        judge(tmp_path, signed_request(), directory=directory)


@pytest.mark.parametrize(("name", "value"), [
    ("signature_agent", "http://agent.example/.well-known/http-message-signatures-directory"),
    ("signature_agent", "https://u@agent.example/x"),
    ("authority", "API.example"),
    ("authority", "api.example/path"),
    ("at", "2026-11-21 12:00:00"),
    ("at", "2026-11-21T12:00:00+00:00"),
    ("required_components", ["b", "a"]),
    ("required_components", ["a", "a"]),
    ("required_components", "a"),
    ("max_age_seconds", 0),
    ("max_age_seconds", True),
    ("max_validity_seconds", -5),
    ("allow_test_keys", "yes"),
    ("directory_sha256", "ABC"),
    ("label", ""),
])
def test_malformed_policy_raises(tmp_path: Path, name: str, value: Any) -> None:
    with pytest.raises(CaseError):
        judge(tmp_path, signed_request(), **{name: value})


def test_unknown_assessment_member_raises(tmp_path: Path) -> None:
    with pytest.raises(CaseError):
        judge(tmp_path, signed_request(), signature_key="ab" * 32)


def test_the_directory_pin_is_required(tmp_path: Path) -> None:
    with pytest.raises(CaseError):
        judge(tmp_path, signed_request(), directory_sha256=None)


def test_decision_envelope_carries_the_limit_and_the_pins(tmp_path: Path) -> None:
    result = judge(tmp_path, signed_request())
    assert result["claim_type"] == "web_bot_auth/v1"
    assert "replayed" in result["scope"]["limit"]
    assert result["scope"]["signature_agent"] == AGENT and result["scope"]["authority"] == AUTHORITY

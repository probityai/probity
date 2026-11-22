"""Attacks on web_bot_auth/v1 (branch lane/wf1-wba-lift at b91b678e).

Each test asserts what a correct verifier must answer. A FAILED test is an attack that LANDS; a passing
test is an attack the adapter blocks. The verdict the adapter actually gave is printed as ATTACK lines.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest
from agent_evidence_verify.adapters import web_bot_auth as wba
from test_web_bot_auth import (
    AGENT,
    JWK,
    KEY,
    NOW,
    OTHER,
    OTHER_JWK,
    URL,
    b64url,
    judge,
    signed_request,
    verdict,
)


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def sign_raw(*, method: str, url: str, headers: list[list[str]], lines: list[str], params: str,
             key=KEY, label: str = "sig1") -> dict:
    """Sign a hand-written signature base: ``lines`` are the component lines, verbatim."""
    base = "\n".join([*lines, f'"@signature-params": {params}'])
    sig = b64(key.sign(base.encode("ascii")))
    return {"method": method, "url": url,
            "headers": [*headers, ["Signature-Input", f"{label}={params}"], ["Signature", f"{label}=:{sig}:"]]}


def params_for(components: str, *, created: int = NOW - 30, expires: int = NOW + 270, kid: str | None = None) -> str:
    return f'({components});created={created};expires={expires};keyid="{kid or JWK["kid"]}";alg="ed25519";tag="web-bot-auth"'


def report(name: str, result: dict) -> tuple[str, str]:
    v = verdict(result)
    print(f"ATTACK {name}: {v[0]} {v[1]}")
    return v


# -- W1: body substitution through an uncovered Content-Digest member ---------------------------------------------

def test_w1_uncovered_digest_member_does_not_bind_the_body(tmp_path: Path) -> None:
    """The signer covers only the crc32c member; the attacker swaps the body and adds an uncovered sha-256 member."""
    original_crc = "crc32c=:AAAAAA==:"
    params = params_for('"@method" "@authority" "content-digest";key="crc32c" "signature-agent";key="agent1"')
    lines = ['"@method": POST', '"@authority": api.example', '"content-digest";key="crc32c": :AAAAAA==:',
             f'"signature-agent";key="agent1": "{AGENT}"']
    new_body = b'{"task":"wipe"}'
    headers = [["Host", "api.example"], ["Signature-Agent", f'agent1="{AGENT}"'],
               ["Content-Digest", f"{original_crc}, sha-256=:{b64(hashlib.sha256(new_body).digest())}:"]]
    request = sign_raw(method="POST", url=URL, headers=headers, lines=lines, params=params)
    v = report("W1 uncovered-digest-member", judge(tmp_path, request, body=new_body))
    assert v[0] != "supported"


# -- W2: a request with a body, judged with no body bound -----------------------------------------------------------

def test_w2a_body_present_on_the_wire_but_not_bound_and_not_covered(tmp_path: Path) -> None:
    request = signed_request(method="POST", body=None,
                             components=('"@method"', '"@authority"', '"signature-agent";key="agent1"'))
    request["headers"].insert(1, ["Content-Length", "17"])
    request["headers"].insert(2, ["Content-Type", "application/json"])
    v = report("W2a body-not-bound", judge(tmp_path, request, body=None))
    assert v[0] != "supported"


def test_w2b_covered_digest_with_no_body_bound_is_a_missing_artifact_not_a_forgery(tmp_path: Path) -> None:
    v = report("W2b covered-digest-no-body", judge(tmp_path, signed_request(), body=None))
    assert v == ("not_established", "body_unavailable")


# -- W3: @method case (RFC 9421 section 2.2.1: no case transformation) ---------------------------------------------

def test_w3a_signature_over_POST_does_not_cover_a_post_request(tmp_path: Path) -> None:
    good = signed_request(method="POST")
    good["method"] = "post"  # a different method under HTTP section 9.1, same signature
    v = report("W3a method-case-admits", judge(tmp_path, good))
    assert v[0] != "supported"


def test_w3b_a_lowercase_method_signed_as_is_verifies(tmp_path: Path) -> None:
    request = signed_request(method="post")  # the helper signs the method verbatim, as RFC 9421 says
    v = report("W3b method-case-refuses", judge(tmp_path, request))
    assert v[0] == "supported"


# -- W4: minimal coverage (the draft's own floor) replayed to another method and path -------------------------------

def test_w4_authority_only_signature_is_supported_for_any_method_and_path(tmp_path: Path) -> None:
    request = signed_request(method="GET", url="https://api.example/public", body=None,
                             components=('"@authority"', '"signature-agent";key="agent1"'))
    request["method"], request["url"] = "DELETE", "https://api.example/admin/users/1"
    result = judge(tmp_path, request, body=None)
    v = report("W4 authority-only-replay", result)
    # The claim reads "signed this request"; the record must at least say which request parts were not covered.
    assert v[0] != "supported" or "uncovered" in json.dumps(result["scope"])


# -- W5: two Web Bot Auth signatures (draft section 5.2.2: each validated independently) ---------------------------

def _two_signatures(first_key, first_kid: str, first_agent: str) -> dict:
    """sig0 from another party (a remote browser, an intermediary) first, then the pinned agent's sig1."""
    pinned = signed_request()
    other_params = params_for('"@authority" "signature-agent";key="agent0"', kid=first_kid)
    other_lines = ['"@authority": api.example', f'"signature-agent";key="agent0": "{first_agent}"']
    other_base = "\n".join([*other_lines, f'"@signature-params": {other_params}'])
    other_sig = b64(first_key.sign(other_base.encode("ascii")))
    h = dict(pinned["headers"])
    headers = [["Host", "api.example"], ["Signature-Agent", f'agent0="{first_agent}", {h["Signature-Agent"]}'],
               ["Content-Digest", h["Content-Digest"]],
               ["Signature-Input", f"sig0={other_params}, {h['Signature-Input']}"],
               ["Signature", f"sig0=:{other_sig}:, {h['Signature']}"]]
    return {"method": pinned["method"], "url": pinned["url"], "headers": headers}


def test_w5a_a_second_signer_ahead_of_the_pinned_agent(tmp_path: Path) -> None:
    request = _two_signatures(OTHER, OTHER_JWK["kid"], "https://browser.example/.well-known/http-message-signatures-directory")
    v = report("W5a other-signer-first", judge(tmp_path, request))
    assert v[0] == "supported"


def test_w5b_a_junk_signature_under_the_pinned_keyid_ahead_of_a_valid_one(tmp_path: Path) -> None:
    request = _two_signatures(OTHER, JWK["kid"], AGENT)  # signed by the wrong key under the victim's keyid
    v = report("W5b junk-first", judge(tmp_path, request))
    assert v[0] == "supported"


# -- W6: the pinned directory's own key metadata -------------------------------------------------------------------

def test_w6a_a_key_the_directory_says_has_expired(tmp_path: Path) -> None:
    jwk = {**JWK, "use": "sig", "nbf": NOW - 90 * 86400, "exp": NOW - 86400}  # the draft's own directory example shape
    v = report("W6a key-exp-passed", judge(tmp_path, signed_request(), directory={"keys": [jwk]}))
    assert v[0] != "supported"


def test_w6b_a_key_not_yet_valid(tmp_path: Path) -> None:
    jwk = {**JWK, "nbf": NOW + 86400, "exp": NOW + 90 * 86400}
    v = report("W6b key-nbf-future", judge(tmp_path, signed_request(), directory={"keys": [jwk]}))
    assert v[0] != "supported"


def test_w6c_a_key_marked_for_encryption(tmp_path: Path) -> None:
    jwk = {**JWK, "use": "enc"}
    v = report("W6c key-use-enc", judge(tmp_path, signed_request(), directory={"keys": [jwk]}))
    assert v[0] != "supported"


def test_w6d_a_directory_that_publishes_the_private_key(tmp_path: Path) -> None:
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
    )
    d = b64url(KEY.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))
    jwk = {**JWK, "d": d}  # anyone who read the directory can sign as this agent
    v = report("W6d private-key-published", judge(tmp_path, signed_request(), directory={"keys": [jwk]}))
    assert v[0] != "supported"


# -- W7: a validity window the draft says should not exceed 24 hours ------------------------------------------------

def test_w7_a_ten_year_signature_with_no_window_pinned(tmp_path: Path) -> None:
    request = signed_request(created=NOW - 30, expires=NOW + 10 * 365 * 86400)
    v = report("W7 ten-year-window", judge(tmp_path, request))
    assert v[0] != "supported"


# -- W8: RFC 9421 section 2.2.8's own @query-param example ---------------------------------------------------------

@pytest.mark.parametrize(("name", "expected"), [
    ("var", "this%20is%20a%20big%0Amultiline%20value"),
    ("bar", "with%20plus%20whitespace"),
    ("fa%C3%A7ade%22%3A%20", "something"),
])
def test_w8_query_param_matches_the_rfc_example(name: str, expected: str) -> None:
    request = wba.Request("GET", "https://www.example.com/parameters?var=this%20is%20a%20big%0Amultiline%20value&"
                          "bar=with+plus+whitespace&fa%C3%A7ade%22%3A%20=something", ())
    try:
        got = wba._derived(request, "@query-param", {"name": name})
    except wba._Fail as failure:
        got = f"FAIL {failure.reason}: {failure.detail}"
    print(f"ATTACK W8 query-param {name!r}: {got}")
    assert got == expected


@pytest.mark.parametrize(("value", "expected"), [("a~b", "a%7Eb"), ("a*b", "a*b")])
def test_w8b_query_param_uses_the_form_urlencoded_set(value: str, expected: str) -> None:
    request = wba.Request("GET", f"https://api.example/?q={value}", ())
    got = wba._derived(request, "@query-param", {"name": "q"})
    print(f"ATTACK W8b query-param value {value!r}: {got}")
    assert got == expected


# -- W9: ;sf on a field the adapter cannot type ----------------------------------------------------------------------

def test_w9a_sf_inner_list_is_reserialized() -> None:
    request = wba.Request("GET", URL, (("x-list", "(a  b)"),))
    got = wba._field(request, "x-list", {"sf": True})
    print(f"ATTACK W9a sf-inner-list: {got!r}")
    assert got == "(a b)"


def test_w9b_sf_inner_list_garbage_is_not_passed_through() -> None:
    request = wba.Request("GET", URL, (("x-list", "(unterminated"),))
    try:
        got = wba._field(request, "x-list", {"sf": True})
    except wba._Fail as failure:
        got = f"FAIL {failure.reason}"
    print(f"ATTACK W9b sf-garbage: {got!r}")
    assert got.startswith("FAIL")


# -- W10: unpadded base64 in the Signature header (RFC 8941 section 4.2.7: SHOULD NOT fail) ------------------------

def test_w10_unpadded_signature_bytes(tmp_path: Path) -> None:
    request = signed_request()
    request["headers"] = [[n, v.replace("==:", ":")] if n == "Signature" else [n, v] for n, v in request["headers"]]
    v = report("W10 unpadded-signature", judge(tmp_path, request))
    assert v[0] == "supported"


# -- Controls the adapter should keep blocking ----------------------------------------------------------------------

def test_c1_duplicate_signature_agent_member_is_refused(tmp_path: Path) -> None:
    request = signed_request()
    request["headers"].append(["Signature-Agent", 'agent1="https://evil.example/d"'])
    v = report("C1 dup-agent-member", judge(tmp_path, request))
    assert v[0] == "contradicted"


def test_c2_signature_agent_member_with_parameters_is_refused(tmp_path: Path) -> None:
    request = signed_request()
    request["headers"] = [[n, v + ";x=1"] if n == "Signature-Agent" else [n, v] for n, v in request["headers"]]
    v = report("C2 agent-member-params", judge(tmp_path, request))
    assert v[0] == "contradicted"


def test_c3_newline_injection_into_a_covered_field_is_refused(tmp_path: Path) -> None:
    request = signed_request()
    request["headers"].append(["X-Evil", 'a\n"@authority": api.example'])
    from agent_evidence_verify.common import CaseError
    with pytest.raises(CaseError):
        judge(tmp_path, request)
    print("ATTACK C3 newline-injection: CaseError")


def test_c4_host_header_disagreeing_with_url_is_judged_from_the_url(tmp_path: Path) -> None:
    request = signed_request()
    request["headers"] = [[n, "evil.example"] if n == "Host" else [n, v] for n, v in request["headers"]]
    v = report("C4 host-vs-url", judge(tmp_path, request))
    assert v[0] == "supported"  # documents current behaviour; the capture's URL is the authority


def test_c5_token_component_identifier_is_refused(tmp_path: Path) -> None:
    request = signed_request()
    request["headers"] = [[n, v.replace('"@method"', "method")] if n == "Signature-Input" else [n, v]
                          for n, v in request["headers"]]
    v = report("C5 token-identifier", judge(tmp_path, request))
    assert v[0] == "contradicted"


def test_c6_signature_agent_member_key_differs_from_label_relabel_is_allowed(tmp_path: Path) -> None:
    request = signed_request(label="relabelled")
    v = report("C6 relabel", judge(tmp_path, request))
    assert v[0] == "supported"

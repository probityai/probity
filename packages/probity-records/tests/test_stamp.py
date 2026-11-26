"""The agent stamp as an RFC 9421 signature: one request, one key the verifier pins, refused when any covered part of
the request differs from what was signed, when the key is swapped, and when the stamp outlives five minutes."""

from __future__ import annotations

import pytest
from agent_evidence_verify import structured_fields as sf
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from probity_records.canonical_identity import CanonicalIdentity, Ref
from probity_records.stamp import (
    COVERED,
    MAX_TTL_SECONDS,
    SIGNATURE_HEADER,
    Stamp,
    StampRefused,
    authority,
    content_digest,
    presented_key_id,
    sign_stamp,
    stamp_fields,
    stamp_key_id,
    verify_stamp,
)

SEED, OTHER = bytes(range(32)), bytes(range(1, 33))
PUBLIC = Ed25519PrivateKey.from_private_bytes(SEED).public_key().public_bytes_raw()
OTHER_PUBLIC = (
    Ed25519PrivateKey.from_private_bytes(OTHER).public_key().public_bytes_raw()
)
URL, BODY, CREATED = (
    "https://billing.example.com/mcp/refund",
    b'{"id":1}',
    1_795_000_000,
)
IDENTITY = CanonicalIdentity(kind="agent", user=Ref("user", "prod", "https://idp.example.com", "alice"),
                             chain=(Ref("agent", "prod", "https://idp.example.com", "agent-refunds"),)).render()  # fmt: skip
STAMP = Stamp.of(IDENTITY, client="agent-refunds", principals="sha256:" + "a" * 64)


def _signed(**kw: object) -> dict[str, str]:
    args: dict[str, object] = {"seed": SEED, "method": "POST", "target_uri": URL, "body": BODY, "created": CREATED,
                               "ttl_seconds": 60, "nonce": "n-1", **kw}  # fmt: skip
    return sign_stamp(STAMP, **args)  # type: ignore[arg-type]


def _verify(headers: object, **kw: object) -> object:
    args: dict[str, object] = {"method": "POST", "target_uri": URL, "body": BODY, "public_raw": PUBLIC,
                               "now": (CREATED + 5) * 10**9, **kw}  # fmt: skip
    return verify_stamp(headers, **args)  # type: ignore[arg-type]


def _code(headers: object, **kw: object) -> str:
    with pytest.raises(StampRefused) as err:
        _verify(headers, **kw)
    return err.value.code


def test_a_stamp_verifies_over_the_request_it_was_signed_for_and_returns_its_spend_values() -> (
    None
):
    found = _verify(_signed())
    assert (
        found.stamp == STAMP and found.nonce == "n-1" and found.expires == CREATED + 60
    )  # type: ignore[attr-defined]
    assert found.stamp.digest == STAMP.digest  # type: ignore[attr-defined]


def test_the_header_lines_may_be_pairs_and_field_names_compare_without_case() -> None:
    lines = [(name.upper(), value) for name, value in _signed().items()]
    assert _verify(lines).stamp == STAMP  # type: ignore[attr-defined]


@pytest.mark.parametrize(("change", "code"), [
    ({"method": "GET"}, "stamp_forged"),
    ({"target_uri": "https://billing.example.com/mcp/payout"}, "stamp_forged"),
    ({"target_uri": "https://evil.example.com/mcp/refund"}, "stamp_forged"),
    ({"body": b'{"id":2}'}, "stamp_request_mismatch"),
    ({"body": None}, "stamp_request_mismatch"),
    ({"public_raw": OTHER_PUBLIC}, "stamp_key_mismatch"),
    ({"now": (CREATED + 60) * 10**9}, "stamp_expired"),
    ({"now": (CREATED - 1) * 10**9}, "stamp_not_yet_valid"),
])  # fmt: skip
def test_every_covered_part_of_the_request_and_the_clock_are_checked(
    change: dict[str, object], code: str
) -> None:
    assert _code(_signed(), **change) == code


def test_a_key_id_naming_the_pinned_key_does_not_let_another_key_sign() -> None:
    forged = sign_stamp(
        STAMP,
        seed=OTHER,
        method="POST",
        target_uri=URL,
        body=BODY,
        created=CREATED,
        ttl_seconds=60,
    )
    params = sf.parse_dictionary(forged["signature-input"])["probity"]
    assert isinstance(params, sf.InnerList)
    params.params["keyid"] = stamp_key_id(PUBLIC)
    forged["signature-input"] = sf.serialize_dictionary({"probity": params})
    assert presented_key_id(forged) == stamp_key_id(PUBLIC)
    assert _code(forged) == "stamp_forged"


def test_the_signer_refuses_a_lifetime_over_five_minutes() -> None:
    for ttl in (0, MAX_TTL_SECONDS + 1, True):
        with pytest.raises(ValueError):
            _signed(ttl_seconds=ttl)


def test_absent_partial_and_repeated_stamps_are_told_apart() -> None:
    assert stamp_fields({"accept": "*/*"}) is None
    assert _code({"accept": "*/*"}) == "stamp_dropped"
    partial = {k: v for k, v in _signed().items() if k != SIGNATURE_HEADER}
    assert _code(partial) == "stamp_malformed"
    assert (
        _code([*_signed().items(), ("Signature", "probity=:AAAA:")]) == "stamp_repeated"
    )
    other_signer = {
        "signature-input": 'sig1=("@method");created=1',
        "signature": "sig1=:AAAA:",
    }
    assert stamp_fields(other_signer) is None


def test_the_stamp_names_an_agent_acting_for_a_user_and_nothing_else() -> None:
    alone = CanonicalIdentity(
        kind="unknown", user=Ref("user", "prod", "https://idp.example.com", "alice")
    ).render()
    no_user = CanonicalIdentity(kind="agent", chain=(Ref("agent", "prod", "https://idp.example.com", "a"),),
                                sponsor=Ref("sponsor", "prod", "https://idp.example.com", "owner")).render()  # fmt: skip
    for identity, code in ((alone, "stamp_downgraded"), (no_user, "stamp_no_user"),
                           ("not an identity", "stamp_identity_mismatch")):  # fmt: skip
        with pytest.raises(StampRefused) as err:
            Stamp.of(identity, client="agent-refunds", principals="sha256:" + "a" * 64)
        assert err.value.code == code
    for kw in ({"client": ""}, {"principals": "a" * 64}):
        with pytest.raises(StampRefused) as err:
            Stamp.of(
                IDENTITY,
                **{"client": "agent-refunds", "principals": "sha256:" + "a" * 64, **kw},
            )
        assert err.value.code == "stamp_malformed"


def test_the_principals_field_round_trips_and_refuses_any_other_shape() -> None:
    assert Stamp.from_field(STAMP.field()) == STAMP
    for value in (
        'id="x"',
        STAMP.field() + ', scope="admin"',
        'id=x, client="c", principals="p"',
        "((",
    ):
        with pytest.raises(StampRefused) as err:
            Stamp.from_field(value)
        assert err.value.code == "stamp_malformed"


def test_the_covered_set_is_fixed_and_the_content_digest_is_rfc_9530() -> None:
    assert COVERED == (
        "@method",
        "@target-uri",
        "@authority",
        "content-digest",
        "probity-principals",
    )
    assert (
        content_digest(b"")
        == content_digest(None)
        == "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:"
    )


@pytest.mark.parametrize(("uri", "expected"), [
    ("https://Billing.Example.com:443/a", "billing.example.com"),
    ("http://h.example:80/", "h.example"),
    ("https://h.example:8443/", "h.example:8443"),
    ("https://[::1]:9/", "[::1]:9"),
])  # fmt: skip
def test_the_authority_drops_only_the_default_port(uri: str, expected: str) -> None:
    assert authority(uri) == expected


@pytest.mark.parametrize(
    "uri",
    ["ftp://h.example/", "https://u@h.example/", "https://h.example/#f", "/relative"],
)
def test_a_target_that_is_not_an_absolute_http_uri_cannot_be_stamped(uri: str) -> None:
    with pytest.raises(ValueError):
        authority(uri)

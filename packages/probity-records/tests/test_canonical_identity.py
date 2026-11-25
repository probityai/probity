"""The canonical identity string: one form per identity, refused when it is not that form, never a user alone by
default."""

from __future__ import annotations

import json
import random
from pathlib import Path

import pytest
from probity_records.canonical_identity import (
    DOCUMENT_VERSION,
    KINDS,
    MARKER,
    CanonicalIdentity,
    Evidence,
    IdentityStringError,
    Ref,
)
from probity_records.canonical_identity_vectors import (
    ACCEPTED,
    ALICE,
    FINANCE,
    OWNER,
    REFUNDS,
    check,
    judge,
    vectors,
)

SHARED = Path(__file__).resolve().parents[1] / "vectors" / "shared" / "canonical_identity.json"
ALPHABET = "aZ09-._~ %/@:;=>!?&,\"\\\u00e9\u4e2d\U0001f600"


def test_every_vector_judges_as_expected_and_the_shared_file_is_current() -> None:
    rows = vectors()
    assert check(rows) == []
    assert rows == vectors()
    assert json.loads(SHARED.read_text()) == json.loads(json.dumps(rows))


def _text(rng: random.Random) -> str:
    return "".join(rng.choice(ALPHABET) for _ in range(rng.randint(1, 12)))


def _ref(rng: random.Random, kind: str) -> Ref:
    env = rng.choice(["prod", "staging", "eu-1", "a"])
    return Ref(type=kind, environment=env, domain=_text(rng), subject=_text(rng))


def _identity(rng: random.Random) -> CanonicalIdentity:
    kind = rng.choice(KINDS)
    digest = "sha256:" + "".join(rng.choice("0123456789abcdef") for _ in range(64))
    if kind == "transport":
        return CanonicalIdentity(kind=kind, service=_ref(rng, "service"))
    if kind == "unknown":
        return CanonicalIdentity(kind=kind, user=_ref(rng, "user"))
    if kind == "human-attested":
        approver = _ref(rng, "approver") if rng.random() < 0.5 else None
        method = "approval" if approver else "presence"
        return CanonicalIdentity(kind=kind, user=_ref(rng, "user"), approver=approver,
                                 evidence=Evidence(method, digest), grants=digest if rng.random() < 0.3 else None)
    user = _ref(rng, "user") if rng.random() < 0.8 else None
    chain = tuple({_ref(rng, "agent"): None for _ in range(rng.randint(1, 4))})
    count = rng.randint(1, 4) if user is None else rng.choice((0, 0, 1, 2, 3))
    sponsors = tuple(sorted({_ref(rng, "sponsor") for _ in range(count)}, key=Ref.render))
    return CanonicalIdentity(kind=kind, user=user, chain=chain, sponsors=sponsors,
                             act=digest if user is not None and rng.random() < 0.5 else None)


def test_parse_render_is_a_bijection_over_random_identities() -> None:
    rng = random.Random(20261121)
    for _ in range(3000):
        identity = _identity(rng)
        text = identity.render()
        assert CanonicalIdentity.parse(text) == identity
        assert CanonicalIdentity.parse(text).render() == text
        assert CanonicalIdentity.from_document(identity.document()) == identity
        assert not any(c in text for c in "\"\\ ,") and text.isascii() and text.isprintable()


def test_an_agent_acting_for_a_user_never_matches_the_users_legacy_entry() -> None:
    agent = ACCEPTED[0][2]
    entry = ALICE.render()
    assert agent.render() != entry and agent.acl_key() != entry
    assert not agent.render().startswith(entry) and not agent.render().startswith("user:")
    with pytest.raises(IdentityStringError) as caught:
        Ref.parse(agent.render())
    assert caught.value.code == "identity_ref_malformed"
    with pytest.raises(IdentityStringError) as caught:
        agent.plain_user()
    assert caught.value.code == "identity_not_human_attested"


def test_only_a_human_attested_identity_renders_the_plain_user_form() -> None:
    human = CanonicalIdentity(kind="human-attested", user=ALICE, evidence=Evidence("presence", "sha256:" + "0" * 64))
    assert human.plain_user() == human.acl_key() == ALICE.render()
    assert human.render().startswith(MARKER)
    unknown = CanonicalIdentity(kind="unknown", user=ALICE)
    assert unknown.acl_key() == unknown.render() != ALICE.render()
    with pytest.raises(IdentityStringError):
        unknown.plain_user()


def test_strict_refuses_an_unknown_actor_and_basic_admits_it() -> None:
    unknown = CanonicalIdentity(kind="unknown", user=ALICE)
    unknown.check("basic")
    with pytest.raises(IdentityStringError) as caught:
        unknown.check("strict")
    assert caught.value.code == "identity_actor_unknown"
    with pytest.raises(IdentityStringError):
        unknown.check("lenient")


def test_a_sub_agent_shows_its_parent_and_the_acting_agent_is_last() -> None:
    orch = Ref(type="agent", environment="prod", domain=REFUNDS.domain, subject="orchestrator")
    sub = CanonicalIdentity(kind="agent", user=ALICE, chain=(orch, REFUNDS), sponsors=(OWNER,))
    assert sub.agent == REFUNDS
    assert f"chain={orch.render()}>{REFUNDS.render()}" in sub.render()
    assert sub != CanonicalIdentity(kind="agent", user=ALICE, chain=(REFUNDS,), sponsors=(OWNER,))


@pytest.mark.parametrize("vector", [v for v in vectors() if "refused" in v["expected"]], ids=lambda v: v["id"])
def test_each_refusal_is_its_stated_code(vector: dict) -> None:
    assert judge(vector["direction"], vector["input"]) == vector["expected"]


def test_the_spec_lists_exactly_the_refusal_codes_the_reader_raises() -> None:
    import re

    package = Path(__file__).resolve().parents[1]
    source = (package / "src" / "probity_records" / "canonical_identity.py").read_text()
    raised = set(re.findall(r'IdentityStringError\(\s*"(identity_[a-z_]+)"', source))
    raised |= set(re.findall(r'"(identity_[a-z_]+)" if ', source))
    spec = (package / "docs" / "canonical-identity.md").read_text().split("## Refusal codes", 1)[1]
    assert raised == set(re.findall(r"`(identity_[a-z_]+)`", spec))


def _code(build) -> str:
    with pytest.raises(IdentityStringError) as caught:
        build()
    return caught.value.code


def test_sponsors_are_a_sorted_tuple_with_no_entry_twice() -> None:
    assert _code(lambda: CanonicalIdentity(kind="agent", chain=(REFUNDS,), sponsors=(OWNER, FINANCE))) == (
        "identity_sponsor_order")
    assert _code(lambda: CanonicalIdentity(kind="agent", chain=(REFUNDS,), sponsors=(OWNER, OWNER))) == (
        "identity_sponsor_repeated")
    assert _code(lambda: CanonicalIdentity(kind="agent", chain=(REFUNDS,), sponsors=[FINANCE, OWNER])) == (
        "identity_sponsor_malformed")
    assert _code(lambda: CanonicalIdentity(kind="agent", chain=(REFUNDS,), sponsors=(FINANCE, ALICE))) == (
        "identity_ref_type_mismatch")
    assert _code(lambda: CanonicalIdentity(kind="unknown", user=ALICE, sponsors=(OWNER,))) == (
        "identity_attribute_not_allowed")


def test_an_empty_sponsor_tuple_is_no_sponsor_and_is_refused_where_a_sponsor_is_required() -> None:
    assert _code(lambda: CanonicalIdentity(kind="agent", chain=(REFUNDS,), sponsors=())) == (
        "identity_attribute_missing")
    with_user = CanonicalIdentity(kind="agent", user=ALICE, chain=(REFUNDS,), sponsors=())
    assert with_user == CanonicalIdentity(kind="agent", user=ALICE, chain=(REFUNDS,))
    assert ";sponsor=" not in with_user.render() and "sponsor" not in with_user.document()


def test_several_sponsors_round_trip_through_the_string_and_the_document() -> None:
    identity = CanonicalIdentity(kind="agent", user=ALICE, chain=(REFUNDS,), sponsors=(FINANCE, OWNER))
    text = identity.render()
    assert f";sponsor={FINANCE.render()}+{OWNER.render()}" in text
    assert CanonicalIdentity.parse(text) == identity and CanonicalIdentity.parse(text).render() == text
    doc = identity.document()
    assert doc["sponsor"] == [FINANCE.document(), OWNER.document()]
    assert CanonicalIdentity.from_document(json.loads(json.dumps(doc))) == identity
    assert identity.sponsors == (FINANCE, OWNER)


def test_one_sponsor_renders_the_bytes_it_rendered_before_the_list() -> None:
    one = CanonicalIdentity(kind="agent", chain=(REFUNDS,), sponsors=(OWNER,))
    assert one.render() == "aid1!agent;chain=" + REFUNDS.render() + ";sponsor=" + OWNER.render()


def test_a_rule_that_denies_one_sponsor_fires_whatever_other_sponsors_are_named() -> None:
    denied = OWNER.render()
    for sponsors in ((OWNER,), (FINANCE, OWNER)):
        identity = CanonicalIdentity.parse(CanonicalIdentity(kind="agent", chain=(REFUNDS,),
                                                             sponsors=sponsors).render())  # fmt: skip
        assert any(ref.render() == denied for ref in identity.sponsors)
        assert any(ref["id"] == denied for ref in identity.document()["sponsor"])


def test_a_two_sponsor_string_never_parses_as_one_sponsor_and_a_ref_never_holds_a_raw_plus() -> None:
    two = CanonicalIdentity.parse(CanonicalIdentity(kind="agent", chain=(REFUNDS,), sponsors=(FINANCE, OWNER)).render())
    assert two.sponsors == (FINANCE, OWNER)
    plus = Ref(type="sponsor", environment="prod", domain="idp", subject="ops+oncall")
    assert plus.render() == "sponsor:prod/idp/ops%2Boncall" and Ref.parse(plus.render()) == plus
    one = CanonicalIdentity(kind="agent", chain=(REFUNDS,), sponsors=(plus,))
    assert CanonicalIdentity.parse(one.render()).sponsors == (plus,)
    assert _code(lambda: Ref.parse("sponsor:prod/idp/ops+oncall")) == "identity_component_not_canonical"
    assert _code(lambda: Ref.parse("sponsor:prod/id+p/ops")) == "identity_component_not_canonical"
    assert _code(lambda: Ref.parse("spon+sor:prod/idp/ops")) == "identity_ref_type_unknown"
    assert _code(lambda: Ref.parse("sponsor:pr+od/idp/ops")) == "identity_environment_malformed"


def test_every_structured_identity_declares_the_document_version_and_a_version_1_document_is_refused() -> None:
    rng = random.Random(20261125)
    documents = [_identity(rng).document() for _ in range(500)] + [identity.document() for _, _, identity in ACCEPTED]
    assert DOCUMENT_VERSION == 2 and all(doc["version"] == DOCUMENT_VERSION for doc in documents)
    old = {**ACCEPTED[6][2].document(), "version": 1}
    old["sponsor"] = old["sponsor"][0]
    assert _code(lambda: CanonicalIdentity.from_document(old)) == "identity_version_unknown"
    assert _code(lambda: CanonicalIdentity.from_document({**ACCEPTED[0][2].document(), "version": 1})) == (
        "identity_version_unknown")

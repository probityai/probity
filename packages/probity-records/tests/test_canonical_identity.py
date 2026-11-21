"""The canonical identity string: one form per identity, refused when it is not that form, never a user alone by
default."""

from __future__ import annotations

import json
import random
from pathlib import Path

import pytest
from probity_records.canonical_identity import (
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
    return CanonicalIdentity(kind=kind, user=user, chain=chain,
                             sponsor=_ref(rng, "sponsor") if user is None or rng.random() < 0.5 else None,
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
    sub = CanonicalIdentity(kind="agent", user=ALICE, chain=(orch, REFUNDS), sponsor=OWNER)
    assert sub.agent == REFUNDS
    assert f"chain={orch.render()}>{REFUNDS.render()}" in sub.render()
    assert sub != CanonicalIdentity(kind="agent", user=ALICE, chain=(REFUNDS,), sponsor=OWNER)


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

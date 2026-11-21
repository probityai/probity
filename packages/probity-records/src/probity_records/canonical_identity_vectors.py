"""Conformance vectors for the canonical identity string (``canonical_identity``).

Each vector is ``{"id", "description", "direction", "input", "expected"}``. ``direction`` is ``string`` (``input`` is a
string to parse) or ``document`` (``input`` is a structured identity to admit). ``expected`` is ``{"refused": code}`` or
``{"document", "aclKey", "plainUser", "strict"}``, where ``plainUser`` is null for every kind but ``human-attested`` and
``strict`` is the refusal code the strict profile gives, or null. A conforming reader reports exactly these.
"""

from __future__ import annotations

from typing import Any

from .canonical_identity import CanonicalIdentity, Evidence, IdentityStringError, Ref

ISSUER = "https://idp.example.com/realms/agents"
OTHER_ISSUER = "https://login.example.org/tenant-b"
SPIFFE = "spiffe://mesh.example.org"
ACT = "sha256:" + "a1" * 32
GRANTS = "sha256:" + "b2" * 32
PRESENCE = "sha256:" + "c3" * 32
APPROVAL = "sha256:" + "d4" * 32


def ref(kind: str, subject: str, env: str = "prod", domain: str = ISSUER) -> Ref:
    return Ref(type=kind, environment=env, domain=domain, subject=subject)


ALICE = ref("user", "alice@example.com")
ORCH = ref("agent", "orchestrator")
REFUNDS = ref("agent", "agent-refunds")
OWNER = ref("sponsor", "owner@example.com")
BOB = ref("approver", "bob@example.com")

ACCEPTED: list[tuple[str, str, CanonicalIdentity]] = [
    ("CI1", "an agent acts for a user, with sponsor, approver, act claim and grant chain",
     CanonicalIdentity(kind="agent", user=ALICE, chain=(REFUNDS,), sponsor=OWNER, approver=BOB, act=ACT,
                       grants=GRANTS)),
    ("CI2", "a sub-agent acts: the chain shows its parent, root first",
     CanonicalIdentity(kind="agent", user=ALICE, chain=(ORCH, REFUNDS), sponsor=OWNER, act=ACT)),
    ("CI3", "a human acted, attested by a fresh user-presence proof",
     CanonicalIdentity(kind="human-attested", user=ALICE, evidence=Evidence("presence", PRESENCE))),
    ("CI4", "a human acted, attested by the approval bound to the request",
     CanonicalIdentity(kind="human-attested", user=ALICE, approver=BOB, evidence=Evidence("approval", APPROVAL))),
    ("CI5", "the actor could not be established: kind unknown, refused by strict",
     CanonicalIdentity(kind="unknown", user=ALICE)),
    ("CI6", "the transport identity of a mutual-TLS peer under a pinned SPIFFE trust domain",
     CanonicalIdentity(kind="transport", service=ref("service", "billing", domain=SPIFFE))),
    ("CI7", "an agent acting for no user names its sponsor",
     CanonicalIdentity(kind="agent", chain=(REFUNDS,), sponsor=OWNER)),
    ("CI8", "the same names in staging are a different identity",
     CanonicalIdentity(kind="agent", user=ref("user", "alice@example.com", env="staging"),
                       chain=(ref("agent", "agent-refunds", env="staging"),))),
    ("CI9", "the same local name under another issuer is a different identity",
     CanonicalIdentity(kind="agent", user=ref("user", "alice@example.com", domain=OTHER_ISSUER),
                       chain=(ref("agent", "agent-refunds", domain=OTHER_ISSUER),))),
    ("CI10", "non-ASCII and reserved characters are escaped once, uppercase hex",
     CanonicalIdentity(kind="agent", user=ref("user", "jörg/ops;x=y>z!"), chain=(ref("agent", "a b%c"),))),
]

PLAIN_USER = ALICE.render()
AGENT_FOR_ALICE = ACCEPTED[0][2].render()

REFUSED_STRINGS: list[tuple[str, str, str]] = [
    ("CR1", "a plain user ref is not a canonical identity", PLAIN_USER),
    ("CR2", "an unknown grammar version", "aid2!" + AGENT_FOR_ALICE[len("aid1!"):]),
    ("CR3", "no critical marker", AGENT_FOR_ALICE[len("aid1!"):]),
    ("CR4", "an unknown kind", "aid1!robot;user=" + PLAIN_USER),
    ("CR5", "an unknown attribute", AGENT_FOR_ALICE + ";tier=gold"),
    ("CR6", "attributes out of order", "aid1!agent;chain=" + REFUNDS.render() + ";user=" + PLAIN_USER),
    ("CR7", "an attribute repeated", "aid1!unknown;user=" + PLAIN_USER + ";user=" + PLAIN_USER),
    ("CR8", "an agent identity with no chain", "aid1!agent;user=" + PLAIN_USER),
    ("CR9", "a human-attested identity without its evidence", "aid1!human-attested;user=" + PLAIN_USER),
    ("CR10", "approval evidence without the approver",
     "aid1!human-attested;user=" + PLAIN_USER + ";evidence=approval:" + APPROVAL),
    ("CR11", "a chain entry that is not an agent",
     "aid1!agent;user=" + PLAIN_USER + ";chain=" + PLAIN_USER),
    ("CR12", "a sponsor slot carrying a user ref",
     "aid1!agent;user=" + PLAIN_USER + ";chain=" + REFUNDS.render() + ";sponsor=" + PLAIN_USER),
    ("CR13", "lowercase percent-encoding", PLAIN_USER.replace("%40", "%4a").join(["aid1!unknown;user=", ""])),
    ("CR14", "an unreserved octet encoded", "aid1!unknown;user=user:prod/" + ALICE.render().split("/", 1)[1]
     .replace("alice", "%61lice")),
    ("CR15", "a raw reserved octet inside a component", "aid1!unknown;user=user:prod/x@y/alice"),
    ("CR16", "an encoding that is not UTF-8", "aid1!unknown;user=user:prod/idp/%FF"),
    ("CR17", "an uppercase environment", "aid1!unknown;user=" + PLAIN_USER.replace(":prod/", ":Prod/")),
    ("CR18", "an uppercase digest", "aid1!agent;user=" + PLAIN_USER + ";chain=" + REFUNDS.render() + ";act=sha256:"
     + "A1" * 32),
    ("CR19", "an agent acting for no user and no sponsor", "aid1!agent;chain=" + REFUNDS.render()),
    ("CR20", "act without the user whose credential carries it",
     "aid1!agent;chain=" + REFUNDS.render() + ";sponsor=" + OWNER.render() + ";act=" + ACT),
    ("CR21", "an agent twice in one chain",
     "aid1!agent;user=" + PLAIN_USER + ";chain=" + REFUNDS.render() + ">" + REFUNDS.render()),
    ("CR22", "an empty chain entry", "aid1!agent;user=" + PLAIN_USER + ";chain=" + REFUNDS.render() + ">"),
    ("CR23", "a transport identity carrying a user", "aid1!transport;user=" + PLAIN_USER + ";service="
     + ref("service", "billing", domain=SPIFFE).render()),
    ("CR24", "an unknown-actor identity carrying a chain", "aid1!unknown;user=" + PLAIN_USER + ";chain="
     + REFUNDS.render()),
    ("CR25", "a non-ASCII octet", "aid1!unknown;user=user:prod/idp/é"),
    ("CR26", "longer than 8192 octets", "aid1!unknown;user=user:prod/idp/" + "a" * 8200),
    ("CR27", "an empty attribute value", "aid1!unknown;user="),
    ("CR28", "a chain deeper than 32 agents", "aid1!agent;user=" + PLAIN_USER + ";chain="
     + ">".join(ref("agent", f"a{i}").render() for i in range(33))),
]

EXPECTED_CODES = {
    "CR1": "identity_string_malformed", "CR2": "identity_version_unknown", "CR3": "identity_string_malformed",
    "CR4": "identity_kind_unknown", "CR5": "identity_attribute_unknown", "CR6": "identity_attribute_order",
    "CR7": "identity_attribute_order", "CR8": "identity_attribute_missing", "CR9": "identity_attribute_missing",
    "CR10": "identity_attribute_missing", "CR11": "identity_ref_type_mismatch", "CR12": "identity_ref_type_mismatch",
    "CR13": "identity_component_not_canonical", "CR14": "identity_component_not_canonical",
    "CR15": "identity_component_not_canonical", "CR16": "identity_value_not_utf8",
    "CR17": "identity_environment_malformed", "CR18": "identity_digest_malformed",
    "CR19": "identity_attribute_missing", "CR20": "identity_attribute_missing", "CR21": "identity_chain_repeats_agent",
    "CR22": "identity_ref_malformed", "CR23": "identity_attribute_not_allowed",
    "CR24": "identity_attribute_not_allowed", "CR25": "identity_string_malformed", "CR26": "identity_too_long",
    "CR27": "identity_attribute_empty", "CR28": "identity_chain_too_deep",
}  # fmt: skip


def _refused_documents() -> list[tuple[str, str, Any]]:
    doc = ACCEPTED[0][2].document()
    swapped = {**doc, "user": ref("user", "mallory@example.com").document()}
    forged_ref = {**doc, "user": {**doc["user"], "subject": "mallory@example.com"}}
    unknown = {**doc, "tier": "gold"}
    return [
        ("CD1", "the parts name mallory while the id names alice", swapped),
        ("CD2", "a ref whose id disagrees with its subject", forged_ref),
        ("CD3", "an unknown member", unknown),
        ("CD4", "version true is not version 1", {**doc, "version": True}),
    ]


DOCUMENT_CODES = {"CD1": "identity_document_id_mismatch", "CD2": "identity_document_id_mismatch",
                  "CD3": "identity_attribute_unknown", "CD4": "identity_version_unknown"}  # fmt: skip


def outcome(identity: CanonicalIdentity) -> dict[str, Any]:
    try:
        identity.check("strict")
        strict = None
    except IdentityStringError as exc:
        strict = exc.code
    plain = identity.plain_user() if identity.kind == "human-attested" else None
    return {"document": identity.document(), "aclKey": identity.acl_key(), "plainUser": plain, "strict": strict}


def judge(direction: str, value: Any) -> dict[str, Any]:
    """What this package reports for one vector input."""
    try:
        parse = CanonicalIdentity.parse if direction == "string" else CanonicalIdentity.from_document
        return outcome(parse(value))
    except IdentityStringError as exc:
        return {"refused": exc.code}


def vectors() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for vid, description, identity in ACCEPTED:
        rows.append({"id": vid, "description": description, "direction": "string", "input": identity.render(),
                     "expected": outcome(identity)})
        rows.append({"id": vid + "D", "description": description + " (document)", "direction": "document",
                     "input": identity.document(), "expected": outcome(identity)})
    for vid, description, text in REFUSED_STRINGS:
        rows.append({"id": vid, "description": description, "direction": "string", "input": text,
                     "expected": {"refused": EXPECTED_CODES[vid]}})
    for vid, description, doc in _refused_documents():
        rows.append({"id": vid, "description": description, "direction": "document", "input": doc,
                     "expected": {"refused": DOCUMENT_CODES[vid]}})
    return rows


def check(rows: list[dict[str, Any]]) -> list[str]:
    """The ids of vectors whose input this package judges differently from their expected outcome."""
    return [row["id"] for row in rows if judge(row["direction"], row["input"]) != row["expected"]]

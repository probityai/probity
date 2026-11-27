"""Record envelope v2: a signed record whose committed bytes stay verifiable after its subject's key is destroyed.

A v1 record signs its fields in clear and names its subject by a plain digest of the call; every witness leaf is
`SHA-256(0x00 || line)` over that clear line. Nothing in it can be erased without breaking the chain and the witness
proofs, so a verifier labels a v1 journal "not erasable".

A v2 record splits every field of the record, by a declared schema, into one of three retention classes:

- `kept`: the field stays in clear in the signed statement. Only structural metadata may be kept (sequence,
  previous-line digest, record kind, times, verdict, tool name, policy and authority digests). A personal field, or
  a digest computed over personal content, may never be kept (`lint_schema`, and `seal` refuses at write time).
- `pseudonym`: the clear value is encrypted with the payload; the signed statement carries a per-leaf keyed tag
  `HMAC(k, JCS(value))` with `k = HKDF(subject key, "pseudonym", leaf id, field path)`. While the subject key lives,
  its holder recomputes the tag for a known value and joins the timeline (session, user subject, token digests);
  after the key is destroyed no one can, and two leaves of one subject carry unrelated tags.
- `payload`: the clear value is encrypted under the subject key; with `commit` the signed statement also carries a
  per-leaf keyed commitment `HMAC(k_field, JCS(value))`, so one field can be disclosed by releasing `k_field` alone
  (`disclose`) without revealing the subject key or any other field, and equal values do not link across leaves.

Every non-kept field names the data subject whose key covers it (a role: user, agent, sponsor, approver, session).
A schema declares which approver fields list several people (``Rule.members``: an approval several people gave; it
is required on ``principals.approver``). A list under such a rule is sealed per member: member ``n`` is the field
``<path>.<n>`` under its own subject ``approver.<n>`` and its own key, and erasing one approver leaves every other
one readable. ``seal`` refuses such a list when a member has no key of its own, when two members share one key, or
when the record also seals a field under the one ``approver`` key (``field_names_several_subjects``), rather than
put several people under one key. A list under an approver rule without the flag is one approver's own value (the
roles they voted in, say) and seals whole under the ``approver`` key.
The payload is encrypted per subject and per class (AES-256-GCM, a key derived per leaf, the AAD binding the format,
leaf id, schema, subject and class, the plaintext padded to a multiple of 256 bytes, or to one exact size for a
class the schema fixes, so a length cannot tell two values or two subjects apart). The signed statement carries only
the SHA-256 of each ciphertext; the ciphertext lives in a separate payload store. So the witnessed leaf is a
commitment over (structural metadata, ciphertext digests, keyed tags) and stays verifiable when the ciphertext is
deleted or its key destroyed. The statement's in-toto subject is a salted commitment to the call under the subject
key, not a plain digest of it.

Nothing here holds or chooses a key: callers pass subject keys (the custodian, the one party that holds them,
creates and destroys them). `reference` gives a subject-keyed handle for a value inside a body the subject signs, which
cannot be pseudonymised after signing; `personal_traces` checks signed bytes for known personal values, in clear or
under a plain digest. A schema travels as JSON (`Schema.to_json`, `Schema.from_json`), so another
implementation seals and opens the same bytes; the shared vectors (`vectors/shared/erasure.json`, from
`erasure_vectors`) fix keys, leaf ids and nonces. Spec: docs/erasure.md.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Final

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .core import canonical

FORMAT: Final = "probity-record-envelope/v2"
KEPT: Final = "kept"
PSEUDONYM: Final = "pseudonym"
PAYLOAD: Final = "payload"
CLASSES: Final = (KEPT, PSEUDONYM, PAYLOAD)
ROLES: Final = ("user", "agent", "sponsor", "approver", "session")
PAD: Final = 256
NOT_ERASABLE: Final = "not erasable"
ERASED: Final = "commitment only, content erased at {at}"
LEAF_BYTES: Final = 16
KEY_BYTES: Final = 32
NONCE_BYTES: Final = 12
TAG_BYTES: Final = 16  # the AES-GCM tag after the ciphertext
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_HEX32 = re.compile(r"[0-9a-f]{32}\Z")
#: Field names that look like digests; a kept one must be declared structural (`Schema.structural`).
_DIGEST_NAME = re.compile(r"(sha256|digest|hash|thumbprint)", re.IGNORECASE)
#: The role whose field may hold a list of people (an approval several gave); each member is its own data subject.
LIST_ROLE: Final = "approver"
#: The subject of member n of an approver list, and the path segment of its field: ``approver.<n>``, ``<path>.<n>``.
_MEMBER = re.compile(r"approver\.(0|[1-9][0-9]*)\Z")


def member_subject(n: int) -> str:
    """The data subject of member ``n`` of an approver list: ``approver.<n>``, the name its key goes by."""
    return f"{LIST_ROLE}.{n}"


def _subject_ok(subject: Any) -> bool:
    return subject in ROLES or (isinstance(subject, str) and _MEMBER.fullmatch(subject) is not None)


class EnvelopeError(ValueError):
    """A schema, record or envelope that is refused; `code` names the reason."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


# ---- schema ---------------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class Rule:
    """The retention class of one field path (dots separate the keys of nested objects)."""

    path: str
    cls: str
    subject: str | None = None  # the role whose key covers a pseudonym or payload field
    personal: bool = False  # the value can carry personal data
    digest_of_personal: bool = False  # the value is a digest computed over personal content
    commit: bool = False  # a payload field also gets a keyed commitment in the signed statement
    members: bool = False  # an approver field whose list value names several people, one subject per member


@dataclass(frozen=True)
class Schema:
    """Every field a record of this kind may carry, closed: a field no rule names is refused at seal time."""

    name: str
    rules: tuple[Rule, ...]
    structural: frozenset[str] = frozenset()  # kept fields that are digests over payload-blind data
    #: Classes whose every plaintext is padded to one exact size, so a ciphertext length says nothing of whose it is
    #: (an approver's vote: the name inside would otherwise set the length); a larger plaintext is refused.
    fixed: tuple[tuple[str, int], ...] = ()

    @property
    def ident(self) -> str:
        return self.name

    def rule(self, path: str) -> Rule | None:
        for r in self.rules:
            if r.path == path:
                return r
        return None

    def split(self) -> frozenset[str]:
        """Paths that are objects split into declared children (the parent itself has no rule)."""
        return frozenset(r.path.rsplit(".", 1)[0] for r in self.rules if "." in r.path)

    def kept(self) -> tuple[str, ...]:
        return tuple(r.path for r in self.rules if r.cls == KEPT)

    def size(self, cls: str) -> int | None:
        """The exact plaintext size of every ciphertext of `cls`, or None when it is padded to a multiple of PAD."""
        return dict(self.fixed).get(cls)

    def to_json(self) -> dict[str, Any]:
        """The schema as JSON, the form the shared vectors and other implementations read."""
        return {"name": self.name, "structural": sorted(self.structural), "fixed": dict(sorted(self.fixed)),
                "rules": [_rule_json(r) for r in self.rules]}

    @classmethod
    def from_json(cls, doc: Mapping[str, Any]) -> Schema:
        """A schema from its JSON form; EnvelopeError when a member is missing or of the wrong type."""
        def text(value: Any) -> str:
            if not isinstance(value, str):
                raise EnvelopeError("schema_malformed", repr(value))
            return value

        def flag(value: Any) -> bool:
            if not isinstance(value, bool):
                raise EnvelopeError("schema_malformed", repr(value))
            return value

        def count(value: Any) -> int:
            if isinstance(value, bool) or not isinstance(value, int):
                raise EnvelopeError("schema_malformed", repr(value))
            return value

        try:
            rules = tuple(Rule(text(r["path"]), text(r["class"]), None if r["subject"] is None else text(r["subject"]),
                               flag(r["personal"]), flag(r["digestOfPersonal"]), flag(r["commit"]),
                               flag(r.get("members", False)))
                          for r in doc["rules"])  # fmt: skip
            if not isinstance(doc["fixed"], Mapping):
                raise EnvelopeError("schema_malformed", "fixed is not an object")
            fixed = tuple(sorted((text(c), count(n)) for c, n in doc["fixed"].items()))
            return cls(text(doc["name"]), rules, frozenset(text(p) for p in doc["structural"]), fixed)
        except (KeyError, TypeError) as exc:
            raise EnvelopeError("schema_malformed", str(exc)) from exc


def _rule_json(r: Rule) -> dict[str, Any]:
    """A rule as JSON. ``members`` appears only when set, so a schema with no approver list serializes as before."""
    out: dict[str, Any] = {"path": r.path, "class": r.cls, "subject": r.subject, "personal": r.personal,
                           "digestOfPersonal": r.digest_of_personal, "commit": r.commit}
    if r.members:
        out["members"] = True
    return out


#: The field the identity profile defines as one principal or a list of several: its rule must say so.
APPROVER_PRINCIPALS: Final = "principals.approver"


def lint_schema(schema: Schema) -> list[str]:
    """Why `schema` may not seal records; [] when it may. A plain digest of personal content never enters
    committed data: a personal field or a digest over personal content cannot be kept, and a kept field whose name
    reads as a digest must be declared structural (a digest over payload-blind data)."""
    problems: list[str] = []
    seen: set[str] = set()
    split = schema.split()
    for r in schema.rules:
        if r.path in seen:
            problems.append(f"duplicate_rule:{r.path}")
        seen.add(r.path)
        if r.path in split:
            problems.append(f"rule_on_split_object:{r.path}")
        if r.cls not in CLASSES:
            problems.append(f"unknown_class:{r.path}:{r.cls}")
            continue
        if r.cls == KEPT:
            if r.personal:
                problems.append(f"personal_field_kept:{r.path}")
            if r.digest_of_personal:
                problems.append(f"plain_digest_of_personal:{r.path}")
            if _DIGEST_NAME.search(r.path.rsplit(".", 1)[-1]) and r.path not in schema.structural:
                problems.append(f"undeclared_digest_kept:{r.path}")
            if r.subject is not None or r.commit:
                problems.append(f"kept_field_names_a_key:{r.path}")
        else:
            if r.subject not in ROLES:
                problems.append(f"no_subject_role:{r.path}")
            if r.cls == PSEUDONYM and r.commit:
                problems.append(f"pseudonym_with_commitment:{r.path}")
            if r.path == APPROVER_PRINCIPALS and r.subject == LIST_ROLE and not r.members:
                problems.append(f"approver_list_undeclared:{r.path}")
        if r.members and (r.cls == KEPT or r.subject != LIST_ROLE):
            problems.append(f"members_outside_approver:{r.path}")
        if r.path in schema.structural and r.cls != KEPT:
            problems.append(f"structural_not_kept:{r.path}")
    for parent in split:
        if "." in parent:
            problems.append(f"split_deeper_than_two:{parent}")
    sized: set[str] = set()
    for cls, size in schema.fixed:
        if cls in sized:
            problems.append(f"fixed_size_duplicate:{cls}")
        sized.add(cls)
        if (cls not in (PSEUDONYM, PAYLOAD) or isinstance(size, bool) or not isinstance(size, int) or size <= 0
                or size % PAD):
            problems.append(f"fixed_size_malformed:{cls}:{size}")
    if schema.fixed:
        # One fixed class beside a padded one leaves the padded ciphertext's length as the channel the fix closed.
        used = {r.cls for r in schema.rules if r.cls in (PSEUDONYM, PAYLOAD)}
        problems.extend(f"fixed_size_partial:{cls}" for cls in sorted(used - sized))
    return problems


# ---- key derivation -------------------------------------------------------------------------------------------
def derive(subject_key: bytes, label: str, leaf: bytes, path: str) -> bytes:
    """HKDF-SHA256(subject key, salt = FORMAT, info = label 0x00 leaf-id 0x00 path), 32 bytes."""
    if len(subject_key) != KEY_BYTES:
        raise EnvelopeError("subject_key_length")
    if len(leaf) != LEAF_BYTES:
        raise EnvelopeError("leaf_id_length")
    info = label.encode("ascii") + b"\x00" + leaf + b"\x00" + path.encode("utf-8")
    kdf = HKDF(algorithm=hashes.SHA256(), length=KEY_BYTES, salt=FORMAT.encode("ascii"), info=info)
    return kdf.derive(subject_key)


def tag(key: bytes, value: Any) -> str:
    return hmac.new(key, canonical(value), hashlib.sha256).hexdigest()


def field_key(subject_key: bytes, leaf: bytes, path: str) -> bytes:
    """`k_field` of one committed payload field; releasing it discloses that field and nothing else."""
    return derive(subject_key, "field-commitment", leaf, path)


def pseudonym(subject_key: bytes, leaf: bytes, path: str, value: Any) -> str:
    return tag(derive(subject_key, "pseudonym", leaf, path), value)


def reference(subject_key: bytes, label: str, leaf: bytes, value: Any) -> str:
    """A keyed reference to `value` for one leaf, for a value inside a body the subject signs (an approver named in
    its own signed vote cannot be pseudonymised after signing). The same for one (key, label, leaf, value),
    unrelated across leaves and labels, and impossible to recompute or to test against a guessed value once the
    subject key is destroyed. HKDF label `reference/<label>`, empty path."""
    return tag(derive(subject_key, "reference/" + label, leaf, ""), value)


def subject_commitment(subject_key: bytes, leaf: bytes, value: Any) -> str:
    """The in-toto subject digest of a v2 record: the call committed under the subject key (salted by the key and
    the leaf), so a dictionary of calls does not find the record and two records of one call do not link."""
    return tag(derive(subject_key, "subject-commitment", leaf, ""), value)


def _aad(leaf: bytes, schema: str, subject: str, cls: str) -> bytes:
    return canonical({"class": cls, "format": FORMAT, "leaf": leaf.hex(), "schema": schema, "subject": subject})


def _pad(data: bytes, size: int | None = None) -> bytes:
    """`data` padded with spaces to a multiple of PAD, or to exactly `size`; a plaintext over `size` is refused.
    JSON ignores trailing whitespace, so the plaintext stays one JCS object plus blanks."""
    if size is None:
        return data + b" " * (-len(data) % PAD)
    if len(data) > size:
        raise EnvelopeError("payload_over_fixed_size", f"{len(data)} > {size}")
    return data + b" " * (size - len(data))


# ---- sealing --------------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class Sealed:
    """One record sealed: the `kept` fields and the `erasure` block go into the signed statement; `blobs`
    (ciphertext digest -> nonce || ciphertext) go into the payload store; `subject_digest` is the statement's
    in-toto subject digest."""

    kept: dict[str, Any]
    erasure: dict[str, Any]
    blobs: dict[str, bytes]
    subject_digest: str


def _get(record: Mapping[str, Any], path: str) -> tuple[bool, Any]:
    node: Any = record
    for part in path.split("."):
        if not isinstance(node, Mapping) or part not in node:
            return False, None
        node = node[part]
    return True, node


def _paths(record: Mapping[str, Any], schema: Schema) -> list[str]:
    """Every leaf path of `record` under the schema's split objects; a split object must be an object or null."""
    split = schema.split()
    out: list[str] = []
    for key, value in record.items():
        if key in split:
            if value is None:
                continue
            if not isinstance(value, Mapping):
                raise EnvelopeError("split_field_not_an_object", key)
            out.extend(f"{key}.{child}" for child in value)
        else:
            out.append(key)
    return out


def _seal_members(path: str, rule: Rule, members: list[Any], keys: Mapping[str, bytes], leaf: bytes,
                  into: tuple[dict[str, str], dict[str, str], dict[tuple[str, str], dict[str, Any]], dict[str, str],
                              dict[str, str]]) -> None:  # fmt: skip
    """Seal an approver list member by member: member ``n`` is the field ``<path>.<n>``, covered by subject
    ``approver.<n>`` and its own key, in its own ciphertext. One key over the list would put several people under one
    subject, so a member with no key of its own refuses the record."""
    classes, roles, groups, pseudonyms, commitments = into
    if not members:
        raise EnvelopeError("approver_list_empty", path)
    for n, value in enumerate(members):
        subject, at = member_subject(n), f"{path}.{n}"
        key = keys.get(subject)
        if key is None:
            raise EnvelopeError("field_names_several_subjects",
                                f"{path} lists {len(members)} approvers; member {n} needs its own {subject} key")
        classes[at] = rule.cls
        roles[at] = subject
        groups.setdefault((subject, rule.cls), {})[at] = value
        if rule.cls == PSEUDONYM:
            pseudonyms[at] = pseudonym(key, leaf, at, value)
        elif rule.commit:
            commitments[at] = tag(field_key(key, leaf, at), value)


def _one_person_per_key(roles: Mapping[str, str], keys: Mapping[str, bytes], subject_role: str | None) -> None:
    """A record that seals an approver list names each approver under a key of their own: every list has the same
    members (member n of each is one person), no two members share key bytes, and no field rests on the one
    ``approver`` key, which in such a record covers nobody in particular."""
    sizes = _member_lists(roles)
    if not sizes:
        return
    if len(set(sizes.values())) > 1:
        raise EnvelopeError("field_names_several_subjects",
                            "approver lists of different lengths: " + ", ".join(f"{p} lists {n}" for p, n in
                                                                                 sorted(sizes.items())))
    plain = sorted(p for p, r in roles.items() if r == LIST_ROLE)
    if plain or subject_role == LIST_ROLE:
        raise EnvelopeError("field_names_several_subjects",
                            f"the record lists several approvers; {', '.join(plain) or 'its subject'} names the one "
                            f"{LIST_ROLE} key, which is nobody in particular")
    owner: dict[bytes, str] = {}
    for subject in sorted({r for r in roles.values() if _MEMBER.fullmatch(r)}):
        other = owner.setdefault(keys[subject], subject)
        if other != subject:
            raise EnvelopeError("field_names_several_subjects", f"{other} and {subject} have one key")


def seal(
    schema: Schema,
    record: Mapping[str, Any],
    keys: Mapping[str, bytes],
    subject_value: Any,
    subject_role: str | None,
    *,
    leaf: bytes | None = None,
    nonce: Mapping[tuple[str, str], bytes] | None = None,
) -> Sealed:
    """Seal `record` under `keys` (subject -> subject key: a role, or ``approver.<n>`` for member n of an approver
    list, which is sealed per member). `subject_value` is what the v1 statement named by plain
    digest (the call); it is committed under `keys[subject_role]`. With `subject_role` None the record has no data
    subject, every field must be kept, and `subject_digest` is empty (the caller names a structural subject). A
    null value of a non-kept field whose role has no key is kept as null: there is nothing in it to erase. `leaf`
    and `nonce` are fixed only by vectors."""
    problems = lint_schema(schema)
    if problems:
        raise EnvelopeError("schema_refused", "; ".join(problems))
    leaf = os.urandom(LEAF_BYTES) if leaf is None else leaf
    if len(leaf) != LEAF_BYTES:
        raise EnvelopeError("leaf_id_length")
    kept: dict[str, Any] = {}
    classes: dict[str, str] = {}
    roles: dict[str, str] = {}
    commitments: dict[str, str] = {}
    pseudonyms: dict[str, str] = {}
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    for path in _paths(record, schema):
        rule = schema.rule(path)
        if rule is None:
            raise EnvelopeError("field_undeclared", path)
        _, value = _get(record, path)
        if rule.members and isinstance(value, list):
            # Several people, as the schema declares: each member is its own field and subject; the list's path
            # itself carries no class.
            _seal_members(path, rule, value, keys, leaf, (classes, roles, groups, pseudonyms, commitments))
            continue
        classes[path] = rule.cls
        if rule.cls == KEPT:
            if isinstance(value, str) and _HEX64.fullmatch(value.removeprefix("sha256:")) and path not in schema.structural:
                raise EnvelopeError("plain_digest_in_kept_field", path)
            kept[path] = value
            continue
        assert rule.subject is not None
        key = keys.get(rule.subject)
        if key is None and value is None:
            classes[path] = KEPT
            kept[path] = None
            continue
        if key is None:
            raise EnvelopeError("subject_key_missing", f"{path} needs the {rule.subject} key")
        roles[path] = rule.subject
        groups.setdefault((rule.subject, rule.cls), {})[path] = value
        if rule.cls == PSEUDONYM:
            pseudonyms[path] = pseudonym(key, leaf, path, value)
        elif rule.commit:
            commitments[path] = tag(field_key(key, leaf, path), value)
    if subject_role is not None and subject_role not in keys:
        raise EnvelopeError("subject_key_missing", f"the statement subject needs the {subject_role} key")
    _one_person_per_key(roles, keys, subject_role)
    if subject_role is None and groups:
        raise EnvelopeError("subject_role_missing", "a record with personal fields names its data subject")
    ciphertexts: list[dict[str, Any]] = []
    blobs: dict[str, bytes] = {}
    for (role, cls), fields in sorted(groups.items()):
        pkey = derive(keys[role], "payload/" + cls, leaf, role)
        iv = os.urandom(NONCE_BYTES) if nonce is None else nonce[(role, cls)]
        blob = iv + AESGCM(pkey).encrypt(iv, _pad(canonical(fields), schema.size(cls)), _aad(leaf, schema.ident, role, cls))
        digest = hashlib.sha256(blob).hexdigest()
        blobs[digest] = blob
        ciphertexts.append({"bytes": len(blob), "class": cls, "sha256": digest, "subject": role})
    erasure = {
        "format": FORMAT,
        "leaf": leaf.hex(),
        "schema": schema.ident,
        "classes": dict(sorted(classes.items())),
        "roles": dict(sorted(roles.items())),
        "commitments": dict(sorted(commitments.items())),
        "pseudonyms": dict(sorted(pseudonyms.items())),
        "ciphertexts": ciphertexts,
        "subjectRole": subject_role,
    }
    if subject_role is None:
        del erasure["subjectRole"]
    digest = "" if subject_role is None else subject_commitment(keys[subject_role], leaf, subject_value)
    return Sealed(kept, erasure, blobs, digest)


def _set(out: dict[str, Any], path: str, value: Any) -> None:
    head, _, rest = path.partition(".")
    if rest:
        out.setdefault(head, {})[rest] = value
    else:
        out[head] = value


@dataclass(frozen=True)
class Opened:
    """A v2 record read back: `fields` holds every field whose key was available; `erased` lists the paths of the
    fields whose subject key is gone (each reads `ERASED`), `missing` those whose ciphertext is not in the store."""

    fields: dict[str, Any]
    erased: tuple[str, ...]
    missing: tuple[str, ...]


def open_sealed(
    kept: Mapping[str, Any],
    erasure: Mapping[str, Any],
    blobs: Mapping[str, bytes],
    keys: Mapping[str, bytes],
) -> Opened:
    """Decrypt what `keys` can open, checking every ciphertext digest, the AEAD binding and every keyed tag; an
    EnvelopeError at the first mismatch (a swapped blob, a blob of another leaf, a tampered tag)."""
    check_block(erasure)
    leaf = bytes.fromhex(erasure["leaf"])
    out: dict[str, Any] = {}
    for path, value in kept.items():
        _set(out, path, value)
    erased: list[str] = []
    missing: list[str] = []
    members: dict[str, dict[int, Any]] = {}  # approver list path -> member index -> value
    classes: Mapping[str, str] = erasure["classes"]
    for entry in erasure["ciphertexts"]:
        role, cls, digest = entry["subject"], entry["class"], entry["sha256"]
        paths = [p for p, c in classes.items() if c == cls and erasure["roles"][p] == role]
        key = keys.get(role)
        if key is None:
            erased.extend(paths)
            continue
        blob = blobs.get(digest)
        if blob is None:
            missing.extend(paths)
            continue
        if hashlib.sha256(blob).hexdigest() != digest:
            raise EnvelopeError("ciphertext_digest_mismatch", digest)
        if len(blob) != entry["bytes"]:
            raise EnvelopeError("ciphertext_length_mismatch", f"{role}/{cls}")
        pkey = derive(key, "payload/" + cls, leaf, role)
        try:
            plain = AESGCM(pkey).decrypt(blob[:NONCE_BYTES], blob[NONCE_BYTES:], _aad(leaf, erasure["schema"], role, cls))
        except InvalidTag as exc:
            raise EnvelopeError("ciphertext_refused", f"{role}/{cls}") from exc
        fields = json.loads(plain)
        for path, value in fields.items():
            if classes.get(path) != cls or erasure["roles"].get(path) != role:
                raise EnvelopeError("ciphertext_field_undeclared", path)
            if cls == PSEUDONYM and erasure["pseudonyms"].get(path) != pseudonym(key, leaf, path, value):
                raise EnvelopeError("pseudonym_mismatch", path)
            if path in erasure["commitments"] and erasure["commitments"][path] != tag(field_key(key, leaf, path), value):
                raise EnvelopeError("commitment_mismatch", path)
            if _MEMBER.fullmatch(role):
                base, _, n = path.rpartition(".")
                members.setdefault(base, {})[int(n)] = value
            else:
                _set(out, path, value)
    # An approver list opens with every member whose key is present; an erased or missing member reads as null in
    # its place, so the others keep their positions.
    sizes = _member_lists(erasure["roles"])
    for base, opened in members.items():
        _set(out, base, [opened.get(n) for n in range(sizes[base])])
    return Opened(out, tuple(sorted(erased)), tuple(sorted(missing)))


def _member_lists(roles: Mapping[str, str]) -> dict[str, int]:
    """Each approver list a block seals per member, with its size; EnvelopeError ``roles_malformed`` unless member
    ``n`` of a list is the field ``<path>.<n>`` under subject ``approver.<n>`` and the members are 0 to N-1."""
    found: dict[str, set[int]] = {}
    for path, role in roles.items():
        match = _MEMBER.fullmatch(role)
        if match is None:
            continue
        base, _, n = path.rpartition(".")
        if not base or n != match.group(1):
            raise EnvelopeError("roles_malformed", f"{path} is not member {match.group(1)} of a list")
        found.setdefault(base, set()).add(int(n))
    for base, ns in found.items():
        if ns != set(range(len(ns))):
            raise EnvelopeError("roles_malformed", f"{base} does not list members 0 to {len(ns) - 1}")
    return {base: len(ns) for base, ns in found.items()}


def check_block(erasure: Mapping[str, Any]) -> None:
    """The erasure block is well formed and payload-blind: hex tags and digests only, every class known."""
    if erasure.get("format") != FORMAT:
        raise EnvelopeError("not_envelope_v2")
    if not isinstance(erasure.get("leaf"), str) or not _HEX32.fullmatch(erasure["leaf"]):
        raise EnvelopeError("leaf_id_malformed")
    classes = erasure.get("classes")
    if not isinstance(classes, Mapping) or any(c not in CLASSES for c in classes.values()):
        raise EnvelopeError("classes_malformed")
    roles = erasure.get("roles")
    if (not isinstance(roles, Mapping) or set(roles) != {p for p, c in classes.items() if c != KEPT}
            or not all(_subject_ok(r) for r in roles.values())):
        raise EnvelopeError("roles_malformed")
    _member_lists(roles)
    for name in ("commitments", "pseudonyms"):
        block = erasure.get(name)
        if not isinstance(block, Mapping) or not all(isinstance(v, str) and _HEX64.fullmatch(v) for v in block.values()):
            raise EnvelopeError(f"{name}_malformed")
        want = PAYLOAD if name == "commitments" else PSEUDONYM
        if any(classes.get(p) != want for p in block):
            raise EnvelopeError(f"{name}_class_mismatch")
    if set(erasure["pseudonyms"]) != {p for p, c in classes.items() if c == PSEUDONYM}:
        raise EnvelopeError("pseudonym_missing")
    entries = erasure.get("ciphertexts")
    if not isinstance(entries, list):
        raise EnvelopeError("ciphertexts_malformed")
    seen: set[tuple[str, str]] = set()
    for e in entries:
        if (not isinstance(e, Mapping) or e.get("class") not in (PSEUDONYM, PAYLOAD) or not _subject_ok(e.get("subject"))
                or not isinstance(e.get("sha256"), str) or not _HEX64.fullmatch(e["sha256"])
                or isinstance(e.get("bytes"), bool) or not isinstance(e.get("bytes"), int)
                or e["bytes"] < NONCE_BYTES + TAG_BYTES):
            raise EnvelopeError("ciphertexts_malformed")
        if (e["subject"], e["class"]) in seen:
            raise EnvelopeError("ciphertexts_duplicate")
        seen.add((e["subject"], e["class"]))
    if seen != {(roles[p], c) for p, c in classes.items() if c != KEPT}:
        raise EnvelopeError("ciphertexts_do_not_cover_fields")


def check_padding(schema: Schema, erasure: Mapping[str, Any]) -> list[str]:
    """Why the ciphertext sizes in a well-formed `erasure` block let a length identify a value; [] when none do.
    Run by a reader that holds the schema: every ciphertext of a class the schema fixes holds exactly that many
    plaintext bytes, every other one a multiple of PAD. A writer that skipped the padding is found here from the
    signed block alone, without any key."""
    check_block(erasure)
    if erasure["schema"] != schema.ident:
        return [f"schema_mismatch:{erasure['schema']}"]
    problems: list[str] = []
    for entry in erasure["ciphertexts"]:
        plain = entry["bytes"] - NONCE_BYTES - TAG_BYTES
        size = schema.size(entry["class"])
        where = f"{entry['subject']}/{entry['class']}:{plain}"
        if size is not None and plain != size:
            problems.append(f"ciphertext_size_not_fixed:{where}")
        elif size is None and (plain <= 0 or plain % PAD):
            problems.append(f"ciphertext_not_padded:{where}")
    return problems


# ---- disclosure -----------------------------------------------------------------------------------------------
def disclose(subject_key: bytes, erasure: Mapping[str, Any], path: str, value: Any) -> dict[str, Any]:
    """Release one committed field: its value and `k_field`, never the subject key."""
    if path not in erasure["commitments"]:
        raise EnvelopeError("field_not_committed", path)
    leaf = bytes.fromhex(erasure["leaf"])
    return {"leaf": erasure["leaf"], "path": path, "value": value, "fieldKey": field_key(subject_key, leaf, path).hex()}


def verify_disclosure(erasure: Mapping[str, Any], disclosure: Mapping[str, Any]) -> bool:
    if disclosure.get("leaf") != erasure.get("leaf"):
        return False
    want = erasure.get("commitments", {}).get(disclosure.get("path"))
    if want is None:
        return False
    try:
        got = tag(bytes.fromhex(disclosure["fieldKey"]), disclosure["value"])
    except (KeyError, ValueError, TypeError):
        return False
    return hmac.compare_digest(got, want)


# ---- what a verifier prints -----------------------------------------------------------------------------------
@dataclass(frozen=True)
class Erasability:
    """A journal's erasure posture as a verifier prints it, from the signed statements alone."""

    records: int
    v1: int
    v2: int
    kept: tuple[str, ...]  # every field path kept in clear by any v2 record, sorted

    @property
    def label(self) -> str:
        if self.records == 0:
            return "empty"
        return NOT_ERASABLE if self.v1 else "erasable"

    def lines(self) -> list[str]:
        out = [f"erasure: {self.label} ({self.v2} of {self.records} records in envelope v2, {self.v1} in v1)"]
        if self.v1:
            out.append("v1 records commit their fields and subject by plain digest over clear content: not erasable")
        out.append("kept in clear (retention class kept): " + (", ".join(self.kept) if self.kept else "none"))
        return out


def erasability(predicates: Iterable[Mapping[str, Any]]) -> Erasability:
    """Count v1 and v2 records and collect the kept class; each v2 erasure block is checked as it is counted."""
    records = v1 = v2 = 0
    kept: set[str] = set()
    for predicate in predicates:
        records += 1
        block = predicate.get("erasure")
        if block is None:
            v1 += 1
            continue
        check_block(block)
        v2 += 1
        kept.update(p for p, c in block["classes"].items() if c == KEPT)
    return Erasability(records, v1, v2, tuple(sorted(kept)))


def erased_reading(at: str) -> str:
    """How a verifier reads an assertion whose subject key was shredded at `at`: its grade stands on the
    commitment, its content is gone."""
    return ERASED.format(at=at)


# ---- the canary lint ------------------------------------------------------------------------------------------
def _digest_forms(digest: bytes) -> list[str]:
    raw = [base64.b64encode(digest).decode("ascii"), base64.urlsafe_b64encode(digest).decode("ascii")]
    return [form for b64 in raw for form in (b64, b64.rstrip("="))]


def personal_traces(signed: bytes, personal: Iterable[Any]) -> list[str]:
    """Each way a known personal value shows in `signed` (the bytes a writer signed, after any DSSE base64 is decoded):
    in clear (as JSON text, escaped either way for non-ASCII, a non-string value as its JCS text), or as a plain
    SHA-256 of its UTF-8 bytes (a string) or its JCS bytes, in hex of either case (with or without `sha256:`) or in
    base64 or base64url, padded or not. [] when none does. A schema lint judges declared rules; this judges what a
    writer actually signed, so a field declared kept that carries a name is found too. Run it with canary values."""
    lower = signed.lower()
    found: list[str] = []
    for value in personal:
        if isinstance(value, str):
            clear = {json.dumps(value, ensure_ascii=False)[1:-1], json.dumps(value, ensure_ascii=True)[1:-1]}
        else:
            clear = {canonical(value).decode("utf-8")}
        digests = {"sha256(jcs)": hashlib.sha256(canonical(value)).digest()}
        if isinstance(value, str):
            digests = {"sha256(utf8)": hashlib.sha256(value.encode("utf-8")).digest(), **digests}
        hits: list[str] = []
        if any(text and text.lower().encode("utf-8") in lower for text in clear):
            hits.append("clear")
        for name, digest in digests.items():
            if digest.hex().encode("ascii") in lower:
                hits.append(name)
            elif any(form.encode("ascii") in signed for form in _digest_forms(digest)):
                hits.append(name + ":base64")
        found.extend(f"{hit}:{value!r}" for hit in dict.fromkeys(hits))
    return found

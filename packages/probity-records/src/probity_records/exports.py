"""Seal a governance platform's JSON export so a party who distrusts the platform can re-check it.

Many governance systems keep approvals, workflow stages and activity logs as mutable rows (created
by, last modified by, nothing signed), and their exports expire. ``seal_export`` reads one export
(entities, workflow stages or an activity log), computes a dated census with denominators (how many
records, of what type, at which stage, how many carry each audit field, duplicate and missing ids)
and a per-record digest list, and signs it outside the platform as an in-toto statement whose
subject is the export's bytes. ``verify_export_seal`` recomputes everything from the export and the
public key alone; ``compare_seals`` shows which records were added, removed or silently changed
between two sealed exports.
"""

from __future__ import annotations

import base64
import json
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass
from typing import Any

from .core import Signer, load_public, open_envelope, sha256_hex, sign_envelope, statement, canonical
from .journal import now

EXPORT_SEAL = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/export-seal"
EXPORT_KINDS = ("entities", "stages", "activity")
LIST_KEYS = ("content", "data", "entities", "items", "records", "results", "rows")


@dataclass(frozen=True)
class FieldMap:
    """Where each audit field lives in one exported record (dotted paths)."""

    id: str = "id"
    type: str = "type"
    stage: str = "stage"
    created_by: str = "createdBy"
    modified_by: str = "lastModifiedBy"
    created_at: str = "createdDate"
    modified_at: str = "lastUpdatedDate"


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("export_has_duplicate_keys")
    return dict(pairs)


def parse_export(data: bytes) -> list[Any]:
    """The records of an export: a top-level list, or the list under a common envelope key."""
    doc = json.loads(data.decode("utf-8"), object_pairs_hook=_no_duplicate_keys)
    if isinstance(doc, list):
        return doc
    if isinstance(doc, dict):
        for key in LIST_KEYS:
            if isinstance(doc.get(key), list):
                return doc[key]
    raise ValueError("export_has_no_record_list")


def _get(record: Any, path: str) -> Any:
    for part in path.split("."):
        if not isinstance(record, Mapping) or part not in record:
            return None
        record = record[part]
    return record


def census(records: list[Any], fields: FieldMap) -> dict[str, Any]:
    """Counts with their denominators, and the digest of every record keyed by its id."""
    total = len(records)
    ids = [_get(r, fields.id) for r in records]
    present = {name: sum(1 for r in records if _get(r, path) not in (None, ""))
               for name, path in asdict(fields).items()}
    counted = Counter(str(i) for i in ids if i is not None)
    digests = sorted(({"id": None if i is None else str(i), "sha256": sha256_hex(canonical(r))}
                      for i, r in zip(ids, records, strict=True)), key=lambda d: (d["id"] is None, d["id"] or "",
                                                                                  d["sha256"]))
    return {
        "byStage": dict(sorted(Counter(str(_get(r, fields.stage)) for r in records).items())),
        "byType": dict(sorted(Counter(str(_get(r, fields.type)) for r in records).items())),
        "duplicateIds": sorted(i for i, n in counted.items() if n > 1),
        "fieldsPresent": {name: {"of": total, "present": n} for name, n in sorted(present.items())},
        "missingIds": sum(1 for i in ids if i is None),
        "records": total,
        "recordDigests": digests,
        "recordsRoot": sha256_hex(canonical(digests)),
    }


def seal_export(signer: Signer, data: bytes, *, source: str, kind: str, captured_at: str,
                fields: FieldMap | None = None, sealed_at: str | None = None) -> dict[str, Any]:
    """A DSSE envelope over an in-toto statement sealing one export's bytes and census."""
    if kind not in EXPORT_KINDS:
        raise ValueError(f"kind must be one of {EXPORT_KINDS}")
    fields = fields or FieldMap()
    predicate = {"capturedAt": captured_at, "census": census(parse_export(data), fields), "fieldMap": asdict(fields),
                 "kind": kind, "rawBytes": len(data), "sealedAt": sealed_at or now(), "source": source}
    body = statement(f"export:{kind}", sha256_hex(data), EXPORT_SEAL, predicate)
    return sign_envelope(signer, canonical(body))


def verify_export_seal(envelope: Mapping[str, Any], data: bytes, public_pems: Iterable[bytes]) -> dict[str, Any]:
    """``{"verdict": "PASS"|"FAIL", "failures": [...], "census": ...}`` from the export and keys alone."""
    failures: list[str] = []
    try:
        payload, _ = open_envelope(dict(envelope), [load_public(p) for p in public_pems])
        body = json.loads(payload)
    except (ValueError, TypeError) as exc:
        return {"verdict": "FAIL", "failures": [f"seal:{exc}"], "census": None}
    pred = body.get("predicate", {})
    if body.get("predicateType") != EXPORT_SEAL:
        failures.append("seal_predicate_type_unexpected")
    if body.get("subject", [{}])[0].get("digest", {}).get("sha256") != sha256_hex(data):
        failures.append("export_bytes_differ_from_seal")
    if pred.get("rawBytes") != len(data):
        failures.append("export_length_differs_from_seal")
    try:
        fresh = census(parse_export(data), FieldMap(**pred.get("fieldMap", {})))
    except (ValueError, TypeError) as exc:
        failures.append(f"export_unreadable:{exc}")
        fresh = None
    if fresh is not None and fresh != pred.get("census"):
        failures.append("census_differs_from_seal")
    return {"verdict": "FAIL" if failures else "PASS", "failures": failures, "census": pred.get("census")}


def compare_seals(older: Mapping[str, Any], newer: Mapping[str, Any]) -> dict[str, list[str]]:
    """Ids added, removed or changed between two sealed exports (envelopes already verified)."""

    def table(env: Mapping[str, Any]) -> dict[str, str]:
        census_ = json.loads(base64.b64decode(env["payload"]))["predicate"]["census"]
        return {d["id"]: d["sha256"] for d in census_["recordDigests"] if d["id"] is not None}

    a, b = table(older), table(newer)
    return {"added": sorted(b.keys() - a.keys()), "changed": sorted(k for k in a.keys() & b.keys() if a[k] != b[k]),
            "removed": sorted(a.keys() - b.keys())}

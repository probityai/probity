"""Index replayable decisions, challenges, and supersessions in SQLite."""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
import tempfile
import zipfile
from contextlib import closing
from pathlib import Path
from typing import Any

from .bundle import _BUNDLE_LIMIT, replay_bundle
from .common import CaseError
from .core import canonical_json

_SCHEMA = "probity-index-event/v1"
_DECISIONS = {"supported", "contradicted", "not_established"}
_FIELDS = {
    "decision": {"schema_version", "kind", "bundle_sha256", "case_id",
                 "claim_type", "decision", "policy_sha256"},
    "challenge": {"schema_version", "kind", "target", "counter", "basis"},
    "supersession": {"schema_version", "kind", "target", "replacement", "basis"},
}


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _entry_id(event: dict[str, Any]) -> str:
    return f"sha256:{_digest(canonical_json(event))}"


def _replay_bytes(data: bytes) -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as directory:
        staged = Path(directory) / "decision.zip"
        staged.write_bytes(data)
        return replay_bundle(staged)


def _read_bundle(path: Path) -> tuple[bytes, dict[str, Any]]:
    """Read bounded ZIP bytes and replay them."""
    with path.open("rb") as stream:
        data = stream.read(_BUNDLE_LIMIT + 1)
    if len(data) > _BUNDLE_LIMIT:
        raise CaseError("bundle exceeds size limit")
    return data, _replay_bytes(data)


def _create_schema(connection: sqlite3.Connection) -> None:
    if connection.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table'"
    ).fetchone():
        raise CaseError("index has no supported schema version")
    connection.execute(
        "CREATE TABLE bundles (digest TEXT PRIMARY KEY, content BLOB NOT NULL)"
    )
    connection.execute(
        "CREATE TABLE events (sequence INTEGER PRIMARY KEY, "
        "id TEXT UNIQUE NOT NULL, payload BLOB NOT NULL)"
    )
    connection.execute("PRAGMA user_version = 1")
    connection.commit()


def _check_schema(connection: sqlite3.Connection, *, create: bool) -> None:
    version = connection.execute("PRAGMA user_version").fetchone()[0]
    if version == 1:
        return
    if version != 0 or not create:
        raise CaseError("unsupported index schema version")
    _create_schema(connection)


def _open(path: Path, *, create: bool) -> sqlite3.Connection:
    if not create and not path.is_file():
        raise CaseError(f"index does not exist: {path}")
    if create:
        path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    try:
        _check_schema(connection, create=create)
        return connection
    except BaseException:
        connection.close()
        raise


def _strings(event: dict[str, Any], fields: tuple[str, ...]) -> bool:
    return all(isinstance(event[key], str) and bool(event[key]) for key in fields)


def _check_decision(event: dict[str, Any]) -> None:
    fields = ("bundle_sha256", "case_id", "claim_type", "policy_sha256")
    if not _strings(event, fields):
        raise CaseError("invalid decision event")
    if event["decision"] not in _DECISIONS:
        raise CaseError("invalid decision event")


def _check_relation(event: dict[str, Any], fields: tuple[str, ...]) -> None:
    if not _strings(event, fields):
        raise CaseError(f"invalid {event['kind']} event")
    if not 1 <= len(event["basis"]) <= 1000:
        raise CaseError(f"invalid {event['kind']} event")


def _check_challenge(event: dict[str, Any]) -> None:
    _check_relation(event, ("target", "counter", "basis"))


def _check_supersession(event: dict[str, Any]) -> None:
    _check_relation(event, ("target", "replacement", "basis"))


_VALIDATORS = {
    "decision": _check_decision,
    "challenge": _check_challenge,
    "supersession": _check_supersession,
}


def _event_fields(event: dict[str, Any]) -> tuple[str, set[str]]:
    kind = event.get("kind")
    if not isinstance(kind, str):
        raise CaseError("invalid index event fields")
    fields = _FIELDS.get(kind)
    if fields is None:
        raise CaseError("invalid index event fields")
    return kind, fields


def _validate_shape(event: Any) -> dict[str, Any]:
    if not isinstance(event, dict):
        raise CaseError("invalid index event schema")
    if event.get("schema_version") != _SCHEMA:
        raise CaseError("invalid index event schema")
    kind, fields = _event_fields(event)
    if set(event) != fields:
        raise CaseError("invalid index event fields")
    _VALIDATORS[kind](event)
    return event


def _decision_event(data: bytes, result: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": _SCHEMA,
        "kind": "decision",
        "bundle_sha256": _digest(data),
        "case_id": result["case_id"],
        "claim_type": result["claim_type"],
        "decision": result["decision"],
        "policy_sha256": result["policy_sha256"],
    }


def _bundle_bytes(connection: sqlite3.Connection, digest: str) -> bytes:
    row = connection.execute(
        "SELECT content FROM bundles WHERE digest = ?", (digest,)
    ).fetchone()
    if row is None:
        raise CaseError("indexed bundle is missing or changed")
    data = row[0]
    if not isinstance(data, bytes):
        raise CaseError("indexed bundle is missing or changed")
    if len(data) > _BUNDLE_LIMIT:
        raise CaseError("indexed bundle is missing or changed")
    if _digest(data) != digest:
        raise CaseError("indexed bundle is missing or changed")
    return data


def _verify_decision(
    connection: sqlite3.Connection, event: dict[str, Any]
) -> None:
    data = _bundle_bytes(connection, event["bundle_sha256"])
    if _decision_event(data, _replay_bytes(data)) != event:
        raise CaseError("indexed decision differs from bundle replay")


def _decision_pair(
    event: dict[str, Any], seen: dict[str, dict[str, Any]], right: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    old = seen.get(event["target"], {})
    new = seen.get(event[right], {})
    if old.get("kind") != "decision" or new.get("kind") != "decision":
        raise CaseError(f"{event['kind']} must cite earlier decisions")
    return old, new


def _verify_challenge(event: dict[str, Any], seen: dict[str, dict[str, Any]]) -> None:
    _decision_pair(event, seen, "counter")
    if event["target"] == event["counter"]:
        raise CaseError("challenge cannot cite itself as counterevidence")


def _verify_supersession(event: dict[str, Any], seen: dict[str, dict[str, Any]]) -> None:
    old, new = _decision_pair(event, seen, "replacement")
    if event["target"] == event["replacement"]:
        raise CaseError("supersession requires a different decision")
    if (old["case_id"], old["claim_type"]) != (new["case_id"], new["claim_type"]):
        raise CaseError("supersession requires the same case and claim type")
    if old["sequence"] >= new["sequence"]:
        raise CaseError("replacement must be a later decision")


def _verify_reference(event: dict[str, Any], seen: dict[str, dict[str, Any]]) -> None:
    if event["kind"] == "challenge":
        _verify_challenge(event, seen)
    else:
        _verify_supersession(event, seen)


def _parse_event(event_id: str, payload: bytes) -> dict[str, Any]:
    try:
        event = _validate_shape(json.loads(payload))
    except (ValueError, TypeError) as exc:
        raise CaseError("invalid index event JSON") from exc
    if payload != canonical_json(event) or event_id != _entry_id(event):
        raise CaseError("indexed event ID or canonical bytes changed")
    return event


def _verify_all(connection: sqlite3.Connection) -> list[dict[str, Any]]:
    seen: dict[str, dict[str, Any]] = {}
    entries: list[dict[str, Any]] = []
    for sequence, event_id, payload in connection.execute(
        "SELECT sequence, id, payload FROM events ORDER BY sequence"
    ):
        event = _parse_event(event_id, payload)
        if event_id in seen:
            raise CaseError("duplicate index event")
        if event["kind"] == "decision":
            _verify_decision(connection, event)
        else:
            _verify_reference(event, seen)
        seen[event_id] = {"sequence": sequence, **event}
        entries.append({"sequence": sequence, "id": event_id, **event})
    return entries


def verify_index(path: Path) -> list[dict[str, Any]]:
    """Replay bundles and check event IDs and references in insertion order."""
    with closing(_open(path, create=False)) as connection:
        connection.execute("BEGIN")
        return _verify_all(connection)


def _append(
    path: Path, event: dict[str, Any], *, bundle: bytes | None = None
) -> str:
    event = _validate_shape(event)
    with closing(_open(path, create=bundle is not None)) as connection:
        with connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = _verify_all(connection)
            seen = {item["id"]: item for item in existing}
            if event["kind"] != "decision":
                _verify_reference(event, seen)
            if bundle is not None:
                connection.execute(
                    "INSERT OR IGNORE INTO bundles (digest, content) VALUES (?, ?)",
                    (_digest(bundle), bundle),
                )
            event_id = _entry_id(event)
            if event_id in seen:
                raise CaseError("index event already exists")
            connection.execute(
                "INSERT INTO events (id, payload) VALUES (?, ?)",
                (event_id, canonical_json(event)),
            )
    return event_id


def add_decision(path: Path, bundle_path: Path) -> str:
    """Replay a bundle and retain its content-derived decision event."""
    data, result = _read_bundle(bundle_path)
    return _append(path, _decision_event(data, result), bundle=data)


def add_challenge(path: Path, target: str, counter: str, basis: str) -> str:
    """Cite an earlier counterdecision without changing the target verdict."""
    return _append(path, {
        "schema_version": _SCHEMA, "kind": "challenge",
        "target": target, "counter": counter, "basis": basis,
    })


def add_supersession(path: Path, target: str, replacement: str, basis: str) -> str:
    """Link an earlier decision to a later one for the same case and claim type."""
    return _append(path, {
        "schema_version": _SCHEMA, "kind": "supersession",
        "target": target, "replacement": replacement, "basis": basis,
    })


def _run_command(args: argparse.Namespace) -> str | dict[str, Any]:
    if args.command == "add":
        return add_decision(args.index, args.bundle)
    if args.command == "challenge":
        return add_challenge(args.index, args.target, args.counter, args.basis)
    if args.command == "supersede":
        return add_supersession(
            args.index, args.target, args.replacement, args.basis
        )
    return {"entries": verify_index(args.index)}


def main(argv: list[str] | None = None) -> int:
    """Run the index CLI and report invalid input with exit status 2."""
    parser = argparse.ArgumentParser(prog="probity-index")
    commands = parser.add_subparsers(dest="command", required=True)
    add = commands.add_parser("add")
    add.add_argument("index", type=Path)
    add.add_argument("bundle", type=Path)
    challenge = commands.add_parser("challenge")
    challenge.add_argument("index", type=Path)
    challenge.add_argument("--target", required=True)
    challenge.add_argument("--counter", required=True)
    challenge.add_argument("--basis", required=True)
    supersede = commands.add_parser("supersede")
    supersede.add_argument("index", type=Path)
    supersede.add_argument("--target", required=True)
    supersede.add_argument("--replacement", required=True)
    supersede.add_argument("--basis", required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("index", type=Path)
    args = parser.parse_args(argv)
    try:
        output = _run_command(args)
    except (OSError, sqlite3.DatabaseError, zipfile.BadZipFile,
            CaseError, ValueError) as exc:
        print(f"probity-index: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(output, sort_keys=True) if isinstance(output, dict) else output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

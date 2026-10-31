"""Create and replay portable offline decision bundles.

A bundle carries the exact case, consumer policy, bound artifacts, and decision.
It is a replay format, not a signature or an assertion about who captured the
artifacts. A recipient must establish the policy and witness provenance.

Since 0.3.0 a bundle also carries ``bundle.json``, which names the verifier
release that wrote it. Replay compares the bundled decision byte for byte with
its own, and on a difference that record separates two cases: a bundle written
by another release, whose decisions may legitimately differ, and an altered
bundle. Bundles from before 0.3.0 carry no record; they replay when their
decision is the one this release computes in the decision shape of the release
that wrote it (see ``_LEGACY_SHAPES``).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
import tempfile
import zipfile
from collections.abc import Callable, Mapping
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _distribution_version
from pathlib import Path, PurePosixPath
from typing import Any

from .cli import _load
from .common import MAX_ARTIFACT_BYTES, CaseError, _artifact
from .core import REFERENCE_VERIFIER_ID, adjudicate, canonical_json, render_packet
from .json_input import parse_json

_CONTROL_LIMIT = 1024 * 1024
_BUNDLE_LIMIT = 64 * 1024 * 1024
_MEMBER_LIMIT = 128
_CONTROLS = {"case.json", "policy.json", "decision.json"}
_PRODUCER = "bundle.json"
_PRODUCER_SCHEMA = "probity-bundle/v1"
_RELEASE = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")


def _without_reference(decision: dict) -> dict:
    """The decision envelope of releases up to 0.2.2, which had no ``reference``."""
    return {key: value for key, value in decision.items() if key != "reference"}


#: Decision shapes of releases that wrote no ``bundle.json``, other than the
#: current shape, which 0.2.3 and 0.2.4 wrote. A bundle without that record
#: replays only when its decision equals this release's decision byte for byte,
#: in the current shape or in one of these, so the verdict, reason, checks and
#: every other field still have to match exactly.
_LEGACY_SHAPES: tuple[tuple[str, Callable[[dict], dict]], ...] = (
    ("0.2.2 or earlier", _without_reference),
)


def _release() -> str:
    """The installed release of this verifier, recorded in every new bundle."""
    try:
        return _distribution_version("probity-verify")
    except PackageNotFoundError as exc:
        raise CaseError("probity-verify is not installed, so its release is unknown") from exc


def _producer_record() -> dict:
    return {"schema_version": _PRODUCER_SCHEMA,
            "verifier": {"id": REFERENCE_VERIFIER_ID, "version": _release()}}


def _consumer_adapters(
    adapters: Mapping[str, Callable[[Any, Any, Path], dict]] | None,
) -> dict[str, Callable[[Any, Any, Path], dict]] | None:
    """Keep one explicit code selection throughout bundle creation/replay."""
    if adapters is None:
        return None
    if not isinstance(adapters, Mapping):
        raise CaseError("adapters must be a mapping")
    return dict(adapters)


def _safe_member(name: str, label: str) -> str:
    path = PurePosixPath(name)
    if (not name or path.is_absolute() or name != str(path) or
            "\\" in name or "\x00" in name or
            any(part in {".", ".."} for part in name.split("/"))):
        raise CaseError(f"{label}.path: must be a normalized relative path")
    return f"artifacts/{name}"


def _artifact_member(artifact_id: Any, metadata: Any) -> str:
    if not isinstance(artifact_id, str) or not artifact_id:
        raise CaseError("artifact id: expected nonempty string")
    if not isinstance(metadata, dict) or not isinstance(metadata.get("path"), str):
        raise CaseError(f"artifacts.{artifact_id}.path: expected string")
    return _safe_member(metadata["path"], f"artifacts.{artifact_id}")


def _artifact_paths(case: Any) -> dict[str, dict]:
    """Map safe archive members to case artifact metadata.

    Parameters
    ----------
    case : Any
        Parsed case JSON.

    Returns
    -------
    dict[str, dict]
        Archive member names and their binding metadata.

    Raises
    ------
    CaseError
        If an artifact path is ambiguous or cannot be safely staged.
    """
    artifacts = case.get("artifacts") if isinstance(case, dict) else None
    if not isinstance(artifacts, dict) or not artifacts:
        raise CaseError("case.artifacts: expected nonempty object")
    paths: dict[str, dict] = {}
    for artifact_id, metadata in artifacts.items():
        member = _artifact_member(artifact_id, metadata)
        if member in paths:
            raise CaseError(f"duplicate artifact path: {metadata['path']}")
        paths[member] = metadata
    return paths


def _bound_files(case: dict, root: Path) -> dict[str, bytes]:
    """Read each case artifact only after its declared binding verifies."""
    by_path = _artifact_paths(case)
    by_id = {f"artifacts/{meta['path']}": artifact_id
             for artifact_id, meta in case["artifacts"].items()}
    files: dict[str, bytes] = {}
    for member, metadata in by_path.items():
        artifact_id = by_id[member]
        data, check = _artifact(root, metadata, f"artifacts.{artifact_id}")
        if data is None:
            raise CaseError(f"artifacts.{artifact_id}: cannot bundle {check['status']} artifact")
        files[member] = data
    return files


def _zip_entry(name: str, data: bytes) -> tuple[zipfile.ZipInfo, bytes]:
    """Set fixed metadata so identical inputs produce identical ZIP bytes."""
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | 0o644) << 16
    info.compress_type = zipfile.ZIP_STORED
    return info, data


def _write_bundle(path: Path, entries: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for name in sorted(entries):
            info, data = _zip_entry(name, entries[name])
            archive.writestr(info, data)


def create_bundle(
    case_path: Path, policy_path: Path, output: Path, artifact_root: Path | None = None,
    *, adapters: Mapping[str, Callable[[Any, Any, Path], dict]] | None = None,
) -> dict:
    """Write a deterministic bundle for a fully bound case.

    Parameters
    ----------
    case_path, policy_path : Path
        The case and separately held consumer policy.
    output : Path
        New ZIP path. Existing files are never replaced.
    artifact_root : Path | None
        Base directory for case artifact paths. Defaults to the case directory.
    adapters : Mapping | None
        Explicit consumer adapter selection for both creation and replay.

    Returns
    -------
    dict
        The decision recomputed from the bytes inside the bundle.

    Raises
    ------
    CaseError
        If a referenced artifact is missing, unbound, unsafe, or the replay
        differs from the decision made before packaging.
    """
    adapters = _consumer_adapters(adapters)
    if output.exists() or output.is_symlink():
        raise CaseError(f"bundle already exists: {output}")
    case = _load(case_path)
    policy = _load(policy_path)
    files = _bound_files(case, artifact_root or case_path.parent)
    with tempfile.TemporaryDirectory() as directory:
        staged = Path(directory)
        for member, data in files.items():
            target = staged / member
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        result = adjudicate(case, policy, staged / "artifacts", adapters=adapters)
    entries = {
        "case.json": canonical_json(case),
        "policy.json": canonical_json(policy),
        "decision.json": canonical_json(result),
        _PRODUCER: canonical_json(_producer_record()),
        **files,
    }
    with tempfile.NamedTemporaryFile(dir=output.parent, suffix=".zip", delete=False) as stream:
        temporary = Path(stream.name)
    try:
        _write_bundle(temporary, entries)
        if replay_bundle(temporary, adapters=adapters) != result:
            raise CaseError("bundled decision differs from replay")
        os.link(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)
    return result


def _read_member(archive: zipfile.ZipFile, info: zipfile.ZipInfo, limit: int) -> bytes:
    if (info.is_dir() or info.compress_type != zipfile.ZIP_STORED or
            stat.S_IFMT(info.external_attr >> 16) not in {0, stat.S_IFREG} or
            info.file_size > limit):
        raise CaseError(f"unsafe or oversized bundle member: {info.filename}")
    with archive.open(info) as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise CaseError(f"oversized bundle member: {info.filename}")
    return data


def _read_bundle(path: Path) -> dict[str, bytes]:
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        names = [info.filename for info in infos]
        if len(names) > _MEMBER_LIMIT:
            raise CaseError("bundle has too many members")
        if len(names) != len(set(names)) or not _CONTROLS.issubset(names):
            raise CaseError("bundle has duplicate or missing control members")
        if sum(info.file_size for info in infos) > _BUNDLE_LIMIT:
            raise CaseError("bundle exceeds size limit")
        controls = _CONTROLS | {_PRODUCER}
        return {info.filename: _read_member(
            archive, info, _CONTROL_LIMIT if info.filename in controls else MAX_ARTIFACT_BYTES
        ) for info in infos}


def _parse_json(data: bytes, label: str) -> Any:
    try:
        return parse_json(data, max_bytes=_CONTROL_LIMIT, max_depth=32, max_nodes=32768)
    except CaseError as exc:
        raise CaseError(f"{label}: {exc}") from exc


def _producer_release(entries: dict[str, bytes]) -> str | None:
    """The release named by ``bundle.json``, or None for a bundle from before 0.3.0."""
    if _PRODUCER not in entries:
        return None
    data = entries[_PRODUCER]
    record = _parse_json(data, _PRODUCER)
    if data != canonical_json(record):
        raise CaseError(f"{_PRODUCER}: must use canonical JSON")
    verifier = record.get("verifier") if isinstance(record, dict) else None
    if (not isinstance(record, dict) or set(record) != {"schema_version", "verifier"} or
            record["schema_version"] != _PRODUCER_SCHEMA or
            not isinstance(verifier, dict) or set(verifier) != {"id", "version"}):
        raise CaseError(f"{_PRODUCER}: expected {_PRODUCER_SCHEMA} with verifier id and version")
    if verifier["id"] != REFERENCE_VERIFIER_ID:
        raise CaseError(f"{_PRODUCER}: written by another verifier, {verifier['id']!r}")
    release = verifier["version"]
    if not isinstance(release, str) or not _RELEASE.fullmatch(release):
        raise CaseError(f"{_PRODUCER}: verifier.version must be a release number X.Y.Z")
    return release


def _check_decision(stored: bytes, result: dict, producer: str | None) -> None:
    """Refuse a bundled decision that is not this release's replay of the bundle.

    A bundle that names its release must match byte for byte. When it does not,
    the refusal says whether another release wrote it, because a decision from
    another release may differ honestly; a mismatch under the same release means
    the bundle was altered. A bundle from before 0.3.0 must match byte for byte
    in the decision shape of one of the releases that wrote no record.
    """
    if stored == canonical_json(result):
        return
    current = _release()
    if producer is None:
        if any(stored == canonical_json(shape(result)) for _, shape in _LEGACY_SHAPES):
            return
        shapes = ", ".join(["0.2.3 or 0.2.4", *(name for name, _ in _LEGACY_SHAPES)])
        raise CaseError(
            "bundled decision differs from replay: the bundle names no verifier release "
            f"(it predates 0.3.0), and its decision is not this release's ({current}) decision "
            f"in any shape an earlier release wrote ({shapes})")
    if producer != current:
        raise CaseError(
            f"bundled decision differs from replay: the bundle was written by probity-verify "
            f"{producer} and this is {current}; rebuild it with {current}, or replay it with "
            f"{producer} to check it against the release that wrote it")
    raise CaseError("bundled decision differs from replay")


def replay_bundle(
    path: Path, *, adapters: Mapping[str, Callable[[Any, Any, Path], dict]] | None = None,
) -> dict:
    """Recompute a bundled decision from only the carried policy and bytes.

    Parameters
    ----------
    path : Path
        Bundle created by :func:`create_bundle`.
    adapters : Mapping | None
        Consumer-selected code. Bundle contents never select or import code.

    Returns
    -------
    dict
        Decision recomputed from the staged artifacts.

    Raises
    ------
    CaseError
        If bundle members are unsafe, incomplete, or disagree with the carried
        decision. Replay does not authenticate the policy or capture source.
    """
    adapters = _consumer_adapters(adapters)
    entries = _read_bundle(path)
    case = _parse_json(entries["case.json"], "case.json")
    policy = _parse_json(entries["policy.json"], "policy.json")
    if (entries["case.json"] != canonical_json(case) or
            entries["policy.json"] != canonical_json(policy)):
        raise CaseError("case and policy must use canonical JSON")
    producer = _producer_release(entries)
    controls = _CONTROLS | ({_PRODUCER} if producer is not None else set())
    expected = controls | set(_artifact_paths(case))
    if set(entries) != expected:
        raise CaseError("bundle members do not match case artifacts")
    with tempfile.TemporaryDirectory() as directory:
        staged = Path(directory)
        for member in sorted(expected - controls):
            target = staged / member
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(entries[member])
        _bound_files(case, staged / "artifacts")
        result = adjudicate(case, policy, staged / "artifacts", adapters=adapters)
    _check_decision(entries["decision.json"], result, producer)
    return result


def main(argv: list[str] | None = None) -> int:
    """Run the offline create or replay command."""
    parser = argparse.ArgumentParser(prog="probity-bundle")
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create")
    create.add_argument("case", type=Path)
    create.add_argument("--policy", type=Path, required=True)
    create.add_argument("--output", type=Path, required=True)
    create.add_argument("--artifact-root", type=Path)
    replay = commands.add_parser("replay")
    replay.add_argument("bundle", type=Path)
    for command in (create, replay):
        command.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        result = (create_bundle(args.case, args.policy, args.output, args.artifact_root)
                  if args.command == "create" else replay_bundle(args.bundle))
    except (OSError, json.JSONDecodeError, zipfile.BadZipFile, CaseError) as exc:
        print(f"probity-bundle: {exc}", file=sys.stderr)
        return 2
    if args.json:
        sys.stdout.buffer.write(canonical_json(result))
    else:
        print(render_packet(result), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

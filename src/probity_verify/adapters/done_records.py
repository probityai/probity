"""Records shared by the done-receipt adapters.

The done contract is sealed before an agent runs. The tree, observation and
grade records come from producers outside the agent. Each adapter pins every
record through the consumer policy; this module only parses and compares.
"""

from __future__ import annotations

import hashlib
from pathlib import Path, PurePosixPath
from typing import Any

from ..common import CaseError, _digest, _instant, _object, _string
from .event_absence import _record, _scope, _witness

MUTATION_TYPES = frozenset(
    {"write", "create", "rename", "link", "unlink", "truncate", "chmod"})
EXEC_TYPE = "exec"
SCOPES = ("PEER", "EXTERNAL")
VANTAGES = ("independent", "self_reported")


def path(value: Any, label: str) -> str:
    """A normalized workspace-relative POSIX path."""
    name = _string(value, label)
    if ("\x00" in name or name.startswith("/") or name.endswith("/")
            or any(part in ("", ".", "..") for part in name.split("/"))
            or str(PurePosixPath(name)) != name):
        raise CaseError(f"{label}: expected a normalized relative path")
    return name


def under(name: str, prefix: str) -> bool:
    return name == prefix or name.startswith(prefix + "/")


def protects(entry: dict, name: str) -> bool:
    """Whether a protected entry covers a path, after its excluded segment names."""
    if not under(name, entry["path"]):
        return False
    below = name[len(entry["path"]) + 1:].split("/") if name != entry["path"] else []
    return not set(below) & set(entry.get("exclude", ()))


def tree_digest(files: dict[str, str]) -> str:
    """SHA-256 over sorted ``"<sha256>  <path>\\n"`` lines, as sha256sum prints them."""
    lines = "".join(f"{files[name]}  {name}\n"
                    for name in sorted(files, key=lambda item: item.encode("utf-8")))
    return hashlib.sha256(lines.encode("utf-8")).hexdigest()


def _argv(value: Any, label: str) -> list[str]:
    if (not isinstance(value, list) or not value
            or any(not isinstance(item, str) for item in value) or not value[0]):
        raise CaseError(f"{label}: expected a nonempty list of strings")
    return value


def _count(value: Any, label: str) -> int:
    if type(value) is not int or value < 0:
        raise CaseError(f"{label}: expected a nonnegative integer")
    return value


def _exit(value: Any, label: str) -> int:
    if type(value) is not int or not -255 <= value <= 255:
        raise CaseError(f"{label}: expected an integer exit status")
    return value


def _choice(value: Any, label: str, allowed: tuple[str, ...]) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise CaseError(f"{label}: unsupported value")
    return value


def contract(data: bytes) -> dict:
    record = _record(data, "contract",
                     {"schema_version", "contract_id", "protected_paths", "acceptance",
                      "adequacy"},
                     {"task", "heldout_split_sha256", "mutant_set_sha256", "authority_sha256"})
    if record["schema_version"] != "probity-done-contract/v1":
        raise CaseError("unsupported contract schema_version")
    _string(record["contract_id"], "contract.contract_id")
    if "task" in record:
        _string(record["task"], "contract.task")
    for key in ("heldout_split_sha256", "mutant_set_sha256", "authority_sha256"):
        if key in record:
            _digest(record[key], f"contract.{key}")
    protected = record["protected_paths"]
    if not isinstance(protected, list):
        raise CaseError("contract.protected_paths: expected list")
    seen: set[str] = set()
    for index, item in enumerate(protected):
        label = f"contract.protected_paths[{index}]"
        entry = _object(item, label, {"path", "kind", "sha256"}, {"exclude"})
        name = path(entry["path"], f"{label}.path")
        kind = _choice(entry["kind"], f"{label}.kind", ("file", "directory"))
        _digest(entry["sha256"], f"{label}.sha256")
        if "exclude" in entry:
            names = entry["exclude"]
            if (kind != "directory" or not isinstance(names, list) or not names
                    or len(set(map(str, names))) != len(names)
                    or any(not isinstance(item, str) or item in ("", ".", "..")
                           or "/" in item or "\x00" in item for item in names)):
                raise CaseError(f"{label}.exclude: expected distinct path segment "
                                "names on a directory")
        if name in seen:
            raise CaseError("contract.protected_paths: duplicate path")
        seen.add(name)
    acceptance = record["acceptance"]
    if not isinstance(acceptance, list) or not acceptance:
        raise CaseError("contract.acceptance: expected a nonempty list")
    ids: set[str] = set()
    for index, item in enumerate(acceptance):
        label = f"contract.acceptance[{index}]"
        entry = _object(item, label, {"id", "argv"})
        command_id = _string(entry["id"], f"{label}.id")
        _argv(entry["argv"], f"{label}.argv")
        if command_id in ids:
            raise CaseError("contract.acceptance: duplicate id")
        ids.add(command_id)
    adequacy = _object(record["adequacy"], "contract.adequacy", {"mutants", "killed"})
    mutants = _count(adequacy["mutants"], "contract.adequacy.mutants")
    if _count(adequacy["killed"], "contract.adequacy.killed") > mutants:
        raise CaseError("contract.adequacy: more mutants killed than generated")
    return record


def _origin_fields(record: dict, label: str) -> None:
    _string(record["claim_id"], f"{label}.claim_id")
    _string(record["invocation_id"], f"{label}.invocation_id")
    _string(record["producer"], f"{label}.producer")
    _choice(record["vantage"], f"{label}.vantage", VANTAGES)
    _choice(record["witness_scope"], f"{label}.witness_scope", SCOPES)


ORIGIN = {"claim_id", "invocation_id", "producer", "vantage", "witness_scope"}


def tree(data: bytes) -> dict:
    record = _record(data, "tree", {"schema_version", "tree_sha256", "files"} | ORIGIN)
    if record["schema_version"] != "probity-tree/v1":
        raise CaseError("unsupported tree schema_version")
    _origin_fields(record, "tree")
    files = record["files"]
    if not isinstance(files, dict):
        raise CaseError("tree.files: expected object")
    for name, digest in files.items():
        path(name, "tree.files key")
        _digest(digest, f"tree.files[{name}]")
    if tree_digest(files) != _digest(record["tree_sha256"], "tree.tree_sha256"):
        raise CaseError("tree.tree_sha256: does not match the listed files")
    return record


def _event(item: Any, index: int, exec_ids: set[str]) -> dict:
    label = f"events[{index}]"
    event = _object(item, label, {"id", "type", "time", "step"},
                    {"path", "target", "argv", "exit", "origin"})
    _string(event["id"], f"{label}.id")
    kind = _string(event["type"], f"{label}.type")
    _count(event["step"], f"{label}.step")
    if "origin" in event and event["origin"] not in exec_ids:
        raise CaseError(f"{label}.origin: expected an earlier exec event id")
    if kind == EXEC_TYPE:
        _argv(event.get("argv"), f"{label}.argv")
        if "exit" in event:
            _exit(event["exit"], f"{label}.exit")
        if "path" in event or "target" in event:
            raise CaseError(f"{label}: exec events carry argv, not paths")
        return event
    if "argv" in event or "exit" in event:
        raise CaseError(f"{label}: only exec events carry argv and exit")
    if kind in MUTATION_TYPES and "path" not in event:
        raise CaseError(f"{label}.path: mutation events require a path")
    if "path" in event:
        path(event["path"], f"{label}.path")
    if "target" in event:
        if kind not in ("rename", "link"):
            raise CaseError(f"{label}.target: only rename and link name a target")
        path(event["target"], f"{label}.target")
    return event


def observation(data: bytes) -> dict:
    record = _record(data, "observation", {"schema_version", "scope", "coverage"} | ORIGIN,
                     {"events", "gaps"})
    if record["schema_version"] != "probity-observation/v2":
        raise CaseError("unsupported observation schema_version")
    _origin_fields(record, "observation")
    _scope(record["scope"], "observation.scope")
    coverage = _choice(record["coverage"], "observation.coverage",
                       ("complete", "incomplete", "unknown"))
    gaps = record.get("gaps", [])
    if coverage == "incomplete":
        if not isinstance(gaps, list) or not gaps:
            raise CaseError("observation.gaps: incomplete coverage requires named gaps")
    elif "gaps" in record:
        raise CaseError("observation.gaps: only incomplete coverage can name gaps")
    start = _instant(record["scope"]["start"], "observation.scope.start")
    end = _instant(record["scope"]["end"], "observation.scope.end")
    for index, item in enumerate(gaps):
        gap = _object(item, f"gaps[{index}]", {"start", "end"})
        if not start <= _instant(gap["start"], f"gaps[{index}].start") < _instant(
                gap["end"], f"gaps[{index}].end") <= end:
            raise CaseError("observation.gaps: gap outside scope or empty")
    events = record.get("events", [])
    if not isinstance(events, list):
        raise CaseError("observation.events: expected list")
    seen: set[str] = set()
    exec_ids: set[str] = set()
    previous = -1
    for index, item in enumerate(events):
        event = _event(item, index, exec_ids)
        instant = _instant(event["time"], f"events[{index}].time")
        if event["id"] in seen or not start <= instant <= end:
            raise CaseError("observation.events: duplicate or out-of-scope event")
        if event["step"] <= previous:
            raise CaseError("observation.events: steps must increase in record order")
        previous = event["step"]
        seen.add(event["id"])
        if event["type"] == EXEC_TYPE:
            exec_ids.add(event["id"])
    return record


def grade(data: bytes) -> dict:
    record = _record(data, "grade",
                     {"schema_version", "contract_sha256", "tree_sha256", "results"} | ORIGIN)
    if record["schema_version"] != "probity-acceptance-grade/v1":
        raise CaseError("unsupported grade schema_version")
    _origin_fields(record, "grade")
    _digest(record["contract_sha256"], "grade.contract_sha256")
    _digest(record["tree_sha256"], "grade.tree_sha256")
    results = record["results"]
    if not isinstance(results, list):
        raise CaseError("grade.results: expected list")
    ids: set[str] = set()
    for index, item in enumerate(results):
        label = f"grade.results[{index}]"
        entry = _object(item, label, {"id", "argv", "exit"})
        result_id = _string(entry["id"], f"{label}.id")
        _argv(entry["argv"], f"{label}.argv")
        _exit(entry["exit"], f"{label}.exit")
        if result_id in ids:
            raise CaseError("grade.results: duplicate id")
        ids.add(result_id)
    return record


def start(case: Any, policy: Any, claim_type: str, fields: set[str]) -> tuple[str, dict]:
    """Validate the case and policy envelopes and return the case's assessment."""
    case = _object(case, "case", {"schema_version", "case_id", "artifacts"})
    policy = _object(policy, "policy", {"schema_version", "witnesses", "assessments"})
    if (case["schema_version"] != "probity-case/v1"
            or policy["schema_version"] != "probity-policy/v1"):
        raise CaseError("unsupported schema_version")
    case_id = _string(case["case_id"], "case_id")
    if not isinstance(case["artifacts"], dict) or not isinstance(policy["witnesses"], dict):
        raise CaseError("artifacts and witnesses: expected objects")
    assessments = policy["assessments"]
    if not isinstance(assessments, dict) or case_id not in assessments:
        raise CaseError("case_id has no consumer assessment")
    assessment = _object(assessments[case_id], "assessment", fields)
    if assessment["claim_type"] != claim_type:
        raise CaseError("unsupported claim_type")
    return case_id, assessment


def witnesses(case: dict, policy: dict, assessment: dict, root: Path,
              roles: dict[str, bool]) -> dict[str, tuple[bytes | None, dict]]:
    """Bind each named witness role; ``True`` roles need producer, vantage and scope pins."""
    ids = {role: _string(assessment[f"{role}_witness"], f"{role}_witness") for role in roles}
    if len(set(ids.values())) != len(ids):
        raise CaseError("each witness role requires a separate witness")
    bound = {role: _witness(case, policy, ids[role], root, require_vantage=observed,
                            require_scope=observed)
             for role, observed in roles.items()}
    if len({pin["artifact"] for _, pin in bound.values()}) != len(bound):
        raise CaseError("each witness role requires a separate artifact")
    return bound


def independent(record: dict, pin: dict, observed_party: str) -> bool:
    """The consumer pin and the record agree on an independent producer."""
    return (record["vantage"] == pin["vantage"] == "independent"
            and record["producer"] == pin["producer"]
            and record["producer"] != observed_party)


def scope_of(*pairs: tuple[dict, dict]) -> str:
    """EXTERNAL only when every record and its consumer pin both say EXTERNAL."""
    external = all(record["witness_scope"] == pin["witness_scope"] == "EXTERNAL"
                   for record, pin in pairs)
    return "EXTERNAL" if external else "PEER"

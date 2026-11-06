"""Attach witness bundles and the consumer's witness pins to a built done-receipt case."""

from __future__ import annotations

import hashlib
from pathlib import Path

from done_run import build

HOST_OPERATOR = "host-operator"
WITNESS_OPERATOR = "witness-operator"


def external(records: dict, *roles: str) -> dict:
    """Make each named record claim EXTERNAL scope in its own ``witness_scope`` field."""
    for role in roles:
        records[role]["witness_scope"] = "EXTERNAL"
    return records


def add_artifact(root: Path, case: dict, name: str, raw: bytes) -> str:
    (root / name).write_bytes(raw)
    case["artifacts"][name] = {"path": name, "length": len(raw),
                               "sha256": hashlib.sha256(raw).hexdigest()}
    return name


def pin(root: Path, case: dict, policy: dict, role: str, bundle: bytes, host_key: str,
        witness_key: str, *, host_operator: str = HOST_OPERATOR,
        witness_operator: str = WITNESS_OPERATOR, scope: str = "EXTERNAL",
        **extra: bytes) -> dict:
    """Store a bundle (and any retained checkpoint or proof) and pin it for one role.

    The role's consumer pin is set to ``scope`` (``EXTERNAL`` by default), the
    only pin scope that may name a witness.
    """
    config = {"bundle": add_artifact(root, case, f"{role}.witness.json", bundle),
              "host": {"public_key": host_key, "operator": host_operator},
              "witness": {"public_key": witness_key, "operator": witness_operator}}
    for key, raw in extra.items():
        config[key] = add_artifact(root, case, f"{role}.{key}.json", raw)
    policy["witnesses"][role]["witness_scope"] = scope
    policy["witnesses"][role]["witnessed"] = config
    return config


def written(root: Path, records: dict, claim_type: str) -> tuple[dict, dict, dict]:
    """Build a case, write its record files, and return files, case and policy."""
    files, case, policy = build(records, claim_type)
    for name, raw in files.items():
        (root / name).write_bytes(raw)
    return files, case, policy

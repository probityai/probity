"""Check a done contract's oracle-free probes as graded outside the agent.

A contract command that carries ``probe`` (``determinism``, ``type_strict`` or
``import_side_effects``) is a probe, not a behavioural test: it asks whether passing
code passes for the right reason. The contract, final tree and grade are bound as for
``acceptance_observed/v1``, and the whole grade is compared with the whole contract.

Every probe also exits nonzero on a plain wrong answer, so a probe counts only on a
split whose behavioural commands all passed: a visible probe when every visible
behavioural command exited zero, a held-out probe (``heldout`` id prefix) when every
held-out one did. An inactive probe's result is the outcome axis's business.

No probe in the contract gives ``not_established`` / ``no_probes``. Otherwise the
first active probe that failed with an answer, in contract order, gives
``contradicted`` / ``probe_<mode>_failed``; else an active probe stopped at its limit
(``timed_out``) gives ``not_established`` / ``probe_timed_out``; else ``supported`` /
``probes_passed``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from . import acceptance_observed

CLAIM_TYPE = "probe_observed/v1"
LIMIT = ("Producer, vantage and witness scope are consumer pins, not authenticated "
         "identities. A probe reports one property of the code; passing it does not show "
         "the code is correct.")


def _split(command_id: str) -> str:
    return "heldout" if command_id.startswith(acceptance_observed.HELDOUT_PREFIX) else "visible"


def adjudicate(case: Any, policy: Any, artifact_root: Path) -> dict:
    result, decide, bound = acceptance_observed.bind(
        case, policy, artifact_root, CLAIM_TYPE, set(), LIMIT)
    if "done" in bound:
        return bound["done"]
    contract = bound["contract"]
    modes = {command["id"]: command["probe"] for command in contract["acceptance"]
             if "probe" in command}
    if not modes:
        return decide("not_established", "no_probes")
    outcomes = bound["outcomes"]
    passing = {"visible": True, "heldout": True}
    for item in outcomes:
        if item["id"] not in modes and item["exit"] != 0:
            passing[_split(item["id"])] = False
    active = [item for item in outcomes if item["id"] in modes and passing[_split(item["id"])]]
    inactive = [item["id"] for item in outcomes
                if item["id"] in modes and not passing[_split(item["id"])]]
    failed = [item for item in active if item["exit"] != 0]
    answered = [item for item in failed if not item.get("timed_out")]
    result["checks"].append({"id": "probes", "status": "failed" if answered else (
        "unavailable" if failed else "met"), "active": active, "inactive": inactive})
    pairs = (bound["tree"], bound["grade"])
    if answered:
        return decide("contradicted", f"probe_{modes[answered[0]['id']]}_failed", *pairs)
    if failed:
        return decide("not_established", "probe_timed_out")
    return decide("supported", "probes_passed", *pairs)

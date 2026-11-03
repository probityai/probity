"""Public replay of a retained protected-action packet: journals, ledgers and dispatch bundles."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
from typing import Any

from probity_observer.crypto import canonical, strict_loads
from probity_observer.dispatch_records import verify_dispatch_bundle
from probity_observer.grant_records import ActionRequest, GrantPolicy
from probity_observer.history import verify_checkpoint
from probity_observer.ledger import verify_ledger_head
from probity_witness_operator.protocol import require

from .protocol import BUNDLE_FILES, checkpoint_prefix, journal_entries

RUN_FORMAT = "probity-protected-operator-run-v0"
BUNDLES = ("bundle", "after-restart-bundle")


def load(path: Path) -> Any:
    """Read exact canonical JSON bytes from a retained record."""
    return strict_loads(path.read_bytes())


def _dispatch(directory: Path, config: dict[str, Any], retained: dict[str, Any]) -> None:
    """Verify the grant-to-native relation over a copy that holds only the bundle files."""
    with tempfile.TemporaryDirectory() as temporary:
        snapshot = Path(temporary)
        for name in BUNDLE_FILES:
            shutil.copyfile(directory / name, snapshot / name)
        verify_dispatch_bundle(snapshot, ActionRequest(**config["request"]), GrantPolicy(**config["policy"]),
                               config["observerKey"], config["witnessKey"], retained,
                               execution_digest=config["executionDigest"], decision_digest=config.get("decisionDigest"))


def _bundle(directory: Path, selection: dict[str, Any], candidate: dict[str, Any], last: bool) -> dict[str, Any]:
    """Check one captured bundle against the heads the consumer held outside it."""
    config = selection["dispatchConfiguration"]
    key = config["witnessKey"]
    entries = journal_entries((directory / "authorization.jsonl").read_bytes(), config, selection["beforeRoot"])
    checkpoint_prefix(entries, selection["initialAuthorizationCheckpoint"], key)
    ledger = directory / "witness-ledger.jsonl"
    verify_ledger_head(ledger, selection["initialNativeHead"], key)
    receipts = verify_ledger_head(ledger, candidate["native"], key)["count"]
    if last:
        verify_checkpoint(entries, candidate["authorization"], key)
        require(receipts == candidate["native"]["count"], "candidate native head is not current")
    complete = len(entries) == 3
    if complete:
        _dispatch(directory, config, candidate["authorization"])
    return {"bundle": directory.name, "journalPhases": len(entries), "nativeReceipts": receipts, "dispatchBundleVerified": complete}


def _case(directory: Path) -> dict[str, Any]:
    """Replay every captured bundle of one case under its separately recorded selection."""
    selection = load(directory / "host-selection.json")
    candidate = load(directory / "candidate-heads.json")
    names = [name for name in BUNDLES if (directory / name).is_dir()]
    require(bool(names), "case has no captured bundle")
    return {"bundles": [_bundle(directory / name, selection, candidate, name == names[-1]) for name in names]}


def read(packet: Path) -> dict[str, Any]:
    """Replay the retained protected-action packet with public code only.

    Parameters
    ----------
    packet : Path
        Retained ``native`` directory holding ``report.json`` and ``cases/``.

    Returns
    -------
    dict
        Per-case journal, ledger and dispatch-bundle outcomes. The summary is
        unsigned; every checked record carries signatures verified here.
    """
    report = load(packet / "report.json")
    require(report["format"] == RUN_FORMAT and report["status"] == "passed", "retained run report differs")
    names = sorted(path.name for path in (packet / "cases").iterdir())
    require(names == sorted(report["cases"]), "case population differs from the run report")
    return {"profile": RUN_FORMAT, "witnessScope": report["witnessScope"], "evidenceVantage": report["evidenceVantage"],
            "cases": {name: _case(packet / "cases" / name) for name in names}}


def encode(result: dict[str, Any]) -> bytes:
    """Serialize a replay result as the retained report bytes."""
    return canonical(result) + b"\n"

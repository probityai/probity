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
from probity_witness_operator.protocol import history_entries, require

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


def _bundle(directory: Path, selection: dict[str, Any], admitted: bool, candidate: dict[str, Any]) -> dict[str, Any]:
    """Check one captured bundle against the heads the consumer held outside it.

    The full dispatch relation is replayed for the final bundle of a case the consumer admitted.
    """
    config = selection["dispatchConfiguration"]
    key = config["witnessKey"]
    entries = journal_entries((directory / "authorization.jsonl").read_bytes(), config, selection["beforeRoot"])
    checkpoint_prefix(entries, selection["initialAuthorizationCheckpoint"], key)
    receipts = verify_ledger_head(directory / "witness-ledger.jsonl", selection["initialNativeHead"], key)["count"]
    if admitted:
        _dispatch(directory, config, candidate["authorization"])
    return {"bundle": directory.name, "journalPhases": len(entries), "nativeReceipts": receipts, "dispatchBundleVerified": admitted}


def _latest(directory: Path, suffix: str) -> Path:
    """Select the last numbered witness export of one kind."""
    exports = sorted((directory / "witness-exports").glob("*-" + suffix))
    require(bool(exports), "witness export is missing")
    return exports[-1]


def _heads(directory: Path, key: str, candidate: dict[str, Any]) -> dict[str, Any]:
    """Authenticate the consumer's candidate heads against the witness's exported histories."""
    ledger = _latest(directory, "native-ledger.jsonl")
    native = verify_ledger_head(ledger, candidate["native"], key)
    require(native["count"] == candidate["native"]["count"], "candidate native head is not current")
    entries = history_entries(_latest(directory, "authorization.jsonl").read_bytes())
    verify_checkpoint(entries, candidate["authorization"], key)
    return {"nativeReceipts": native["count"], "authorizationEntries": len(entries)}


def _case(directory: Path) -> dict[str, Any]:
    """Replay every captured bundle and the candidate heads of one case under its recorded selection."""
    selection = load(directory / "host-selection.json")
    candidate = load(directory / "candidate-heads.json")
    names = [name for name in BUNDLES if (directory / name).is_dir()]
    require(bool(names), "case has no captured bundle")
    admitted = (directory / "consumer-after-admission-admission.json").is_file()
    bundles = [_bundle(directory / name, selection, admitted and name == names[-1], candidate) for name in names]
    return {"bundles": bundles, "heads": _heads(directory, selection["dispatchConfiguration"]["witnessKey"], candidate)}


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

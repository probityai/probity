"""Finite authorization-journal grammar a reader checks offline."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from probity_observer.crypto import digest, verify_signature
from probity_observer.dispatch_records import CONFIG_DOMAIN, PRIOR_DOMAIN
from probity_observer.history import GENESIS
from probity_observer.ledger import RECEIPT_DOMAIN
from probity_witness_operator.protocol import (
    HEX_DIGEST,
    exact_fields,
    history_entries,
    require,
)

MAX_JOURNAL = 65536
BUNDLE_FILES = ("dispatch-state.json", "authorization.jsonl", "history.jsonl", "witness-ledger.jsonl", "packet.json")
CHECKPOINT_FIELDS = {"count", "head", "keyid", "signature"}


def checkpoint_prefix(entries: list[dict[str, Any]], checkpoint: Any, key: str) -> None:
    """Authenticate an exact checkpoint and require its position in these bytes."""
    exact_fields(checkpoint, CHECKPOINT_FIELDS, "authorization checkpoint fields differ")
    require(checkpoint["keyid"] == key, "authorization checkpoint key differs")
    count = checkpoint["count"]
    require(type(count) is int and 0 <= count <= len(entries), "authorization checkpoint count differs")
    require(checkpoint["head"] == (entries[count - 1]["hash"] if count else GENESIS), "authorization history does not extend retained checkpoint")
    verify_signature(key, "probity-checkpoint-v0", {"count": count, "head": checkpoint["head"]}, checkpoint["signature"])


def journal_entries(raw: bytes, configuration: dict[str, Any], before_root: str) -> list[dict[str, Any]]:
    """Check three recorded phases without asserting target or clock truth."""
    require(0 < len(raw) <= MAX_JOURNAL, "authorization journal exceeds finite limit")
    entries = history_entries(raw)
    require(1 <= len(entries) <= 3, "authorization phase population differs")
    initial = {"kind": "dispatch-created", "configurationDigest": digest(CONFIG_DOMAIN, configuration), "beforeRoot": before_root}
    require(entries[0]["event"] == initial, "authorization initialization differs from host configuration")
    if len(entries) >= 2:
        _prior(entries[1]["event"], configuration)
    if len(entries) == 3:
        _completed(entries[2]["event"], configuration["request"], before_root)
    return entries


def _prior(event: Any, configuration: dict[str, Any]) -> None:
    """Authenticate the host observer's exact prior relation and public pins."""
    exact_fields(event, {"kind", "prior"}, "authorization prior event fields differ")
    require(event["kind"] == "grant-before-dispatch", "authorization prior phase differs")
    prior = event["prior"]
    exact_fields(prior, {"payload", "keyid", "signature"}, "authorization prior envelope differs")
    require(prior["keyid"] == configuration["observerKey"], "authorization observer key differs")
    payload = prior["payload"]
    exact_fields(payload, {"profile", "configurationDigest", "grantDigest", "request", "nativeCommitmentDigest", "nativeStartCheckpoint", "authorizedAt"}, "authorization prior fields differ")
    verify_signature(configuration["observerKey"], PRIOR_DOMAIN, payload, prior["signature"])
    require(payload["profile"] == PRIOR_DOMAIN, "authorization prior profile differs")
    require(payload["configurationDigest"] == digest(CONFIG_DOMAIN, configuration), "authorization prior configuration differs")
    require(payload["request"] == configuration["request"], "authorization prior action differs")
    for field in ("grantDigest", "nativeCommitmentDigest"):
        require(isinstance(payload[field], str) and HEX_DIGEST.fullmatch(payload[field]) is not None, "authorization prior digest differs")
    timestamp = datetime.fromisoformat(payload["authorizedAt"].replace("Z", "+00:00"))
    require(timestamp.tzinfo is not None, "authorization prior time lacks an offset")
    checkpoint = payload["nativeStartCheckpoint"]
    exact_fields(checkpoint, CHECKPOINT_FIELDS | {"ledgerReceipt"}, "authorization native checkpoint differs")
    require(checkpoint["keyid"] == configuration["witnessKey"] and type(checkpoint["count"]) is int and checkpoint["count"] == 1, "authorization native begin pin differs")
    require(isinstance(checkpoint["head"], str) and HEX_DIGEST.fullmatch(checkpoint["head"]) is not None, "authorization native head differs")
    verify_signature(configuration["witnessKey"], "probity-checkpoint-v0", {"count": 1, "head": checkpoint["head"]}, checkpoint["signature"])
    receipt = checkpoint["ledgerReceipt"]
    exact_fields(receipt, {"sequence", "previous", "intervalId", "authorityDigest", "observerKey", "phase", "checkpoint", "hash", "keyid", "signature"}, "authorization native receipt fields differ")
    require(type(receipt["sequence"]) is int and receipt["sequence"] >= 1, "authorization native receipt sequence differs")
    body = {field: receipt[field] for field in ("sequence", "previous", "intervalId", "authorityDigest", "observerKey", "phase", "checkpoint")}
    require(receipt["keyid"] == configuration["witnessKey"] and receipt["hash"] == digest(RECEIPT_DOMAIN, body), "authorization native receipt key or digest differs")
    verify_signature(configuration["witnessKey"], RECEIPT_DOMAIN, body, receipt["signature"])
    require(receipt["phase"] == "begin", "authorization native receipt phase differs")
    authority = {"intervalId": configuration["request"]["run_id"], "scope": "/work", "operation": "write-file"}
    require(receipt["authorityDigest"] == digest("probity-authority-v0", authority), "authorization native authority differs")
    require(receipt.get("observerKey") == configuration["observerKey"], "authorization native receipt observer differs")
    require(receipt.get("intervalId") == configuration["request"]["run_id"], "authorization native receipt interval differs")
    require(receipt.get("checkpoint") == {field: checkpoint[field] for field in CHECKPOINT_FIELDS}, "authorization native receipt checkpoint differs")


def _completed(event: Any, request: dict[str, Any], before_root: str) -> None:
    """Check the recorded result identity; the separate reader checks its packet."""
    exact_fields(event, {"kind", "packetDigest", "result"}, "authorization completion fields differ")
    require(event["kind"] == "dispatch-completed", "authorization completion phase differs")
    require(isinstance(event["packetDigest"], str) and HEX_DIGEST.fullmatch(event["packetDigest"]) is not None, "authorization packet digest differs")
    result = event["result"]
    exact_fields(result, {"request_id", "path", "before_root", "after_root", "replayed"}, "authorization result fields differ")
    require(result["request_id"] == request["request_id"] and result["path"] == request["target_path"], "authorization result action differs")
    require(result["before_root"] == before_root and result["replayed"] is False, "authorization result prior differs")
    require(isinstance(result["after_root"], str) and HEX_DIGEST.fullmatch(result["after_root"]) is not None, "authorization result root differs")

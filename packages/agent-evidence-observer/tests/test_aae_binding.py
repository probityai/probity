"""Keep kernel permission, issuer authentication and local execution separate, over a committed record."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from pathlib import Path

import pytest
from fixture_records import load, materialize, pinned_keys
from probity_observer.aae_binding import local_transaction, verify_effect_link
from probity_observer.aae_enforce import enforce_check, native_digest
from probity_observer.crypto import SigningKey, VerificationError
from probity_observer.grant_records import ActionRequest

CONTENT = b"one local reference effect\n"


@pytest.fixture
def arguments(tmp_path: Path) -> dict:
    record = materialize("aae-effect-link", tmp_path)
    request = ActionRequest("run-1", "attempt-1", "request-1", "tenant-1", "principal-1", "local.write-file",
                            "/work/result.txt", hashlib.sha256(CONTENT).hexdigest())
    transaction = local_transaction(request)
    mandate = json.loads((record / "mandate.json").read_bytes())
    observer, witness = pinned_keys(record)
    return {
        "mandate": mandate, "transaction": transaction, "record": enforce_check(mandate, transaction),
        "request": request, "pinned_mandate_digest": native_digest("mandate", mandate),
        "history": record / "history.jsonl", "workspace": record / "workspace",
        "pinned_observer_key": observer, "pinned_witness_key": witness,
        "packet": load(record / "packet.json"), "link": load(record / "link.json"),
    }


def _refuse(operation, expected, caplog):
    with pytest.raises(VerificationError, match=f"^{re.escape(expected)}$") as caught:
        operation()
    assert str(caught.value) == expected
    assert caplog.records == []


class TestAaeEffectBinding:
    class TestPassingCases:
        def test_replayed_permit_precedes_one_verified_local_write(self, arguments):
            result = verify_effect_link(**arguments)
            assert result["kernelVerdict"] == "PERMIT"
            assert result["execution"] == "recorded-local-write"
            assert result["linkage"] == "verified"
            assert result["issuerAuthentication"] == "not-established"
            assert result["witnessScope"] == "PEER"
            assert (arguments["workspace"] / "result.txt").read_bytes() == CONTENT

        def test_missing_link_leaves_execution_unknown(self, arguments):
            result = verify_effect_link(**{**arguments, "link": None})
            assert result["execution"] == "unknown"
            assert result["linkage"] == "missing"
            assert result["issuerAuthentication"] == "not-established"

        def test_unsigned_issuer_text_does_not_upgrade_authentication(self, arguments):
            mandate = copy.deepcopy(arguments["mandate"])
            mandate["issuer"] = "did:example:forged-unsigned-issuer"
            result = verify_effect_link(**{
                **arguments, "mandate": mandate, "record": enforce_check(mandate, arguments["transaction"]),
                "pinned_mandate_digest": native_digest("mandate", mandate), "link": None,
            })
            assert result["kernelVerdict"] == "PERMIT"
            assert result["issuerAuthentication"] == "not-established"
            assert result["execution"] == "unknown"

    class TestFailingCases:
        def test_effect_link_requires_consumer_selected_observer_pin(self, arguments, caplog):
            _refuse(
                lambda: verify_effect_link(**{**arguments, "pinned_observer_key": SigningKey.generate().public_hex}),
                "AAE effect link signer differs from the observer pin",
                caplog,
            )

        def test_unsigned_replacement_payload_is_not_accepted(self, arguments, caplog):
            arguments["link"]["payload"]["coreDigest"] = "sha256:" + "0" * 64
            _refuse(lambda: verify_effect_link(**arguments), "signature does not verify under the pinned key", caplog)

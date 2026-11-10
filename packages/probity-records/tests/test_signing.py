"""Key custody backends: Vault transit, AWS KMS, Cloud KMS, and delegated session keys.

Each backend is driven through a fake of its service that holds a real Ed25519 key, so every signature
in these tests is a real one checked by the same verifiers a customer runs.
"""

from __future__ import annotations

import base64
import io
import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from probity_records import (AwsKmsKey, GcpKmsKey, Journal, Signer, SigningError, SigningKey, Trust,
                             VaultTransitKey, delegate, sign_permit, verify_delegation, verify_journal,
                             verify_permit)
from probity_records.journal import KEYS_FILE


def _raw(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


class FakeVault:
    """The two transit endpoints the backend calls, over a real key per version."""

    def __init__(self, kind: str = "ed25519") -> None:
        self.kind, self.keys, self.calls = kind, {1: Ed25519PrivateKey.generate()}, []
        self.answer_version: int | None = None

    def rotate(self) -> None:
        self.keys[max(self.keys) + 1] = Ed25519PrivateKey.generate()

    def __call__(self, req, timeout=None):  # noqa: ANN001 - urlopen signature
        self.calls.append((req.get_method(), req.full_url, req.headers))
        if req.get_method() == "GET":
            body = {"data": {"type": self.kind, "latest_version": max(self.keys),
                             "keys": {str(v): {"public_key": base64.b64encode(_raw(k)).decode()}
                                      for v, k in self.keys.items()}}}
        else:
            msg = json.loads(req.data)
            version = self.answer_version or msg["key_version"]
            sig = self.keys[version].sign(base64.b64decode(msg["input"]))
            body = {"data": {"signature": f"vault:v{version}:{base64.b64encode(sig).decode()}"}}
        return io.BytesIO(json.dumps(body).encode())


def test_vault_transit_signs_under_the_pinned_version_and_names_it() -> None:
    vault = FakeVault()
    key = VaultTransitKey("http://vault:8200", "authority", token="t", opener=vault)
    assert isinstance(key, SigningKey)
    sig = key.sign(b"hello")
    key.public.verify(sig, b"hello")
    assert key.provenance == {"backend": "vault-transit", "key": "transit/authority", "version": 1}
    assert vault.calls[-1][1] == "http://vault:8200/v1/transit/sign/authority"
    vault.rotate()  # a rotation after start never changes the key a running authority signs with
    key.public.verify(key.sign(b"again"), b"again")


def test_vault_answer_from_another_version_or_key_is_refused() -> None:
    vault = FakeVault()
    key = VaultTransitKey("http://vault:8200", "authority", token="t", opener=vault)
    vault.rotate()
    vault.answer_version = 2
    with pytest.raises(SigningError, match="another key version"):
        key.sign(b"x")
    vault.answer_version = None
    vault.keys[1] = Ed25519PrivateKey.generate()  # the service now answers with a key we never pinned
    with pytest.raises(SigningError, match="does not accept"):
        key.sign(b"x")


def test_vault_refuses_a_non_ed25519_key_and_a_missing_token(monkeypatch) -> None:
    with pytest.raises(SigningError, match="not ed25519"):
        VaultTransitKey("http://v", "k", token="t", opener=FakeVault("ecdsa-p256"))
    monkeypatch.delenv("VAULT_TOKEN", raising=False)
    with pytest.raises(SigningError, match="no Vault token"):
        VaultTransitKey("http://v", "k", opener=FakeVault())


class FakeAwsKms:
    def __init__(self, spec: str = "ECC_NIST_EDWARDS25519") -> None:
        self.key, self.spec, self.calls = Ed25519PrivateKey.generate(), spec, []

    def get_public_key(self, KeyId):  # noqa: N803 - boto3 names
        der = self.key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        return {"KeyId": f"arn:aws:kms:us-east-1:111122223333:key/{KeyId}", "KeySpec": self.spec, "PublicKey": der}

    def sign(self, **kw):
        self.calls.append(kw)
        return {"Signature": self.key.sign(kw["Message"])}


def test_aws_kms_signs_raw_ed25519_and_refuses_oversized_messages() -> None:
    kms = FakeAwsKms()
    key = AwsKmsKey("k1", client=kms)
    key.public.verify(key.sign(b"m"), b"m")
    assert kms.calls[-1] == {"KeyId": "k1", "Message": b"m", "MessageType": "RAW",
                             "SigningAlgorithm": "ED25519_SHA_512"}
    assert key.provenance["backend"] == "aws-kms" and key.provenance["key"].endswith("key/k1")
    with pytest.raises(SigningError, match="4096"):
        key.sign(b"x" * 4097)
    with pytest.raises(SigningError, match="not ECC_NIST_EDWARDS25519"):
        AwsKmsKey("k2", client=FakeAwsKms("ECC_NIST_P256"))


class FakeGcpKms:
    def __init__(self) -> None:
        self.key = Ed25519PrivateKey.generate()

    def get_public_key(self, request):
        pem = self.key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
        return SimpleNamespace(pem=pem, algorithm=SimpleNamespace(name="EC_SIGN_ED25519"))

    def asymmetric_sign(self, request):
        return SimpleNamespace(signature=self.key.sign(request["data"]))


def test_gcp_kms_signs_and_names_the_key_version() -> None:
    name = "projects/p/locations/global/keyRings/r/cryptoKeys/authority/cryptoKeyVersions/1"
    key = GcpKmsKey(name, client=FakeGcpKms())
    key.public.verify(key.sign(b"m" * 10000), b"m" * 10000)
    assert key.provenance == {"backend": "gcp-kms", "key": name}


def test_a_journal_signed_through_a_kms_backend_verifies_and_names_its_custody(tmp_path) -> None:
    key = GcpKmsKey("projects/p/k/1", client=FakeGcpKms())
    journal = Journal(tmp_path, key)
    journal.append("https://example.test/t", "s", "0" * 64, {"phase": "note"})
    cp = journal.checkpoint()
    trust = Trust(key_custody={key.key_id: "gcp-kms"})
    assert verify_journal(tmp_path, [key.public_pem()], cp, trust=trust)["verdict"] == "PASS"
    wrong = Trust(key_custody={key.key_id: "aws-kms"})
    out = verify_journal(tmp_path, [key.public_pem()], cp, trust=wrong)
    assert out["verdict"] == "FAIL" and any("key_custody" in f for f in out["failures"])


def test_delegated_session_key_signs_large_records_under_a_kms_root(tmp_path) -> None:
    root = AwsKmsKey("k1", client=FakeAwsKms())
    session = delegate(root, timedelta(hours=1))
    assert session.key_id != root.key_id and session.provenance["root"]["backend"] == "aws-kms"
    journal = Journal(tmp_path, session)
    big = {"phase": "note", "blob": "x" * 20000}  # far past the 4096-byte raw KMS cap
    journal.append("https://example.test/t", "s", "0" * 64, big)
    out = verify_journal(tmp_path, [root.public_pem()], journal.checkpoint(),
                         trust=Trust(key_custody={root.key_id: "aws-kms"}))
    assert out["verdict"] == "PASS", out["failures"]
    # the session key alone is not trusted: without the root pinned nothing verifies
    other = Signer.generate()
    assert verify_journal(tmp_path, [other.public_pem()], journal.checkpoint())["verdict"] == "FAIL"


def test_a_session_key_outside_its_window_or_from_an_unpinned_root_is_refused(tmp_path) -> None:
    root = Signer.generate()
    past = delegate(root, timedelta(minutes=5), now=datetime.now(UTC) - timedelta(hours=2))
    journal = Journal(tmp_path, past)
    journal.append("https://example.test/t", "s", "0" * 64, {"phase": "note"})
    out = verify_journal(tmp_path, [root.public_pem()], journal.checkpoint())
    assert any("outside_its_certified_window" in f for f in out["failures"])
    rogue = delegate(Signer.generate())
    with pytest.raises(ValueError, match="delegation_unverified"):
        verify_delegation(rogue.certificate, [root.public])
    forged = json.loads(json.dumps(past.certificate))
    forged["body"]["notAfter"] = "2999-01-01T00:00:00.000000Z"
    with pytest.raises(ValueError, match="delegation_unverified"):
        verify_delegation(forged, [root.public])


def test_rotation_records_each_certificate_once(tmp_path) -> None:
    root = Signer.generate()
    journal = Journal(tmp_path, delegate(root))
    journal.append("https://example.test/t", "s", "0" * 64, {"phase": "note"})
    journal.rotate(delegate(root))
    journal.append("https://example.test/t", "s", "0" * 64, {"phase": "note"})
    Journal(tmp_path, journal.signer)  # reopening with the same key adds nothing
    assert len((tmp_path / KEYS_FILE).read_text().splitlines()) == 2
    assert verify_journal(tmp_path, [root.public_pem()], journal.checkpoint())["verdict"] == "PASS"


def test_permits_carry_custody_and_a_delegated_permit_verifies_under_the_root_only() -> None:
    root = Signer.generate()
    session = delegate(root)
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")  # issued inside the window
    permit = sign_permit(session, {"issuedAt": now, "permitId": "p"})
    claims = verify_permit(permit, root.public_pem())
    assert claims is not None and claims["keyProvenance"]["backend"] == "delegated"
    late = sign_permit(session, {"issuedAt": "2999-01-01T00:00:00.000000Z", "permitId": "p"})
    assert verify_permit(late, root.public_pem()) is None
    assert verify_permit(permit, Signer.generate().public_pem()) is None
    plain = sign_permit(root, {"issuedAt": now, "permitId": "p"})
    assert verify_permit(plain, root.public_pem())["keyProvenance"] == {"backend": "local"}

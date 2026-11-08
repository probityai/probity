"""Where the authority's signing key comes from: a file, an environment variable, HashiCorp Vault,
AWS Secrets Manager or Google Secret Manager. Each resolver returns the Ed25519 private key PEM; the
authority loads it once, at construction, never inside the workflow sandbox or on a replay.

The cloud clients are optional imports (``probity-temporal[aws]``, ``probity-temporal[gcp]``); each
resolver also accepts a ready client, which is how tests and custom credential chains use it.
"""

from __future__ import annotations

import json
import os
import urllib.request
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from probity_records import Signer


class KeyResolver(Protocol):
    def resolve(self) -> bytes:
        """The private key PEM."""


def load_signer(resolver: KeyResolver) -> Signer:
    return Signer.from_pem(resolver.resolve())


@dataclass(frozen=True)
class FileKey:
    path: Path

    def resolve(self) -> bytes:
        mode = Path(self.path).stat().st_mode & 0o077
        if mode:
            raise PermissionError(f"{self.path} is readable by group or others (mode {oct(mode)})")
        return Path(self.path).read_bytes()


@dataclass(frozen=True)
class EnvKey:
    name: str = "PROBITY_AUTHORITY_KEY_PEM"

    def resolve(self) -> bytes:
        value = os.environ.get(self.name)
        if not value:
            raise KeyError(f"environment variable {self.name} is not set")
        return value.encode()


@dataclass(frozen=True)
class VaultKey:
    """KV v2 secret ``mount/data/path``, field ``field``; token from ``token`` or ``VAULT_TOKEN``."""

    address: str
    path: str
    field: str = "pem"
    mount: str = "secret"
    token: str | None = None
    namespace: str | None = None
    opener: Callable[..., Any] = urllib.request.urlopen

    def resolve(self) -> bytes:
        token = self.token or os.environ.get("VAULT_TOKEN")
        if not token:
            raise KeyError("no Vault token (pass token= or set VAULT_TOKEN)")
        req = urllib.request.Request(f"{self.address.rstrip('/')}/v1/{self.mount}/data/{self.path.lstrip('/')}",
                                     headers={"X-Vault-Token": token,
                                              **({"X-Vault-Namespace": self.namespace} if self.namespace else {})})
        with self.opener(req, timeout=10) as resp:
            data = json.loads(resp.read())
        return str(data["data"]["data"][self.field]).encode()


@dataclass(frozen=True)
class AwsSecretsManagerKey:
    secret_id: str
    field: str | None = None
    client: Any = None
    region: str | None = None

    def resolve(self) -> bytes:
        client = self.client
        if client is None:
            import boto3  # noqa: PLC0415 - optional extra

            client = boto3.client("secretsmanager", region_name=self.region)
        out = client.get_secret_value(SecretId=self.secret_id)
        text = out.get("SecretString") or out["SecretBinary"].decode()
        return (json.loads(text)[self.field] if self.field else text).encode()


@dataclass(frozen=True)
class GcpSecretManagerKey:
    """``name`` is ``projects/P/secrets/S/versions/V``."""

    name: str
    client: Any = None

    def resolve(self) -> bytes:
        client = self.client
        if client is None:
            from google.cloud import secretmanager  # noqa: PLC0415 - optional extra

            client = secretmanager.SecretManagerServiceClient()
        return bytes(client.access_secret_version(request={"name": self.name}).payload.data)


@dataclass(frozen=True)
class FirstOf:
    """Try resolvers in order; the first that returns a key wins. Every failure is kept for the error."""

    resolvers: Sequence[KeyResolver]

    def resolve(self) -> bytes:
        failures = []
        for r in self.resolvers:
            try:
                return r.resolve()
            except Exception as exc:  # noqa: BLE001 - reported together below
                failures.append(f"{type(r).__name__}: {exc}")
        raise LookupError("no key resolver returned a key: " + "; ".join(failures))

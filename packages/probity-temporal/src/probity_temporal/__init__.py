"""Temporal plugin: single-use permits bound to each activity's exact arguments, and signed records
of what ran that anyone can verify offline."""

from . import errors
from .admission import NotAdmissible, admit
from .authority import (EVENT, PHASE, Decision, EffectOwner, LocalAuthority, Request,
                        ResultOwner)
from .keys import AwsSecretsManagerKey, EnvKey, FileKey, FirstOf, GcpSecretManagerKey, VaultKey
from .plugin import (NoEffect, ProbityPlugin, call_sha256, check_approval, complete_gated_async,
                     current_idempotency_key, current_permit, execute_gated_activity,
                     execute_gated_local_activity, gated, pause_token, pending_approval, probity_principal)

__all__ = ["EVENT", "PHASE", "AwsSecretsManagerKey", "Decision", "EffectOwner", "EnvKey",
           "FileKey", "FirstOf", "GcpSecretManagerKey", "LocalAuthority", "NoEffect", "NotAdmissible",
           "ProbityPlugin", "Request", "ResultOwner", "VaultKey", "admit", "call_sha256",
           "check_approval", "complete_gated_async", "current_idempotency_key", "current_permit", "errors",
           "execute_gated_activity", "execute_gated_local_activity", "gated", "pause_token", "pending_approval",
           "probity_principal"]

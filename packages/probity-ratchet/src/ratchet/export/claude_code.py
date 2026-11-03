"""Compile an admitted Ratchet guard into a Claude Code PreToolUse hook.

The hook is one self-contained Python file. It carries a header naming the guard id, the harness version and
digest, the SHA-256 of the signed decision receipt that admitted the harness and the hook kind, so provenance
survives the file being copied anywhere; then the hook body.

The hook body is chosen with `--hook`. The default, `emit`, pastes `ratchet.export.hook_emit` verbatim: it
records each call, its view and a reference to its history, and allows the call; it never blocks, because
this package ships no isolation boundary to run an untrusted guard in at every tool call. An enforcing body
comes from the `ratchet.hooks` entry-point group: `--hook NAME` loads the factory registered under NAME,
which returns a `HookBody`. A `--require` list of isolation layers is refused for the emit body, which
applies none, rather than written into a hook that would ignore it.

Only an admitted guard is exported: the receipt must verify under a trusted key, say `admitted`, and name
this exact harness by version and digest, and the harness must contain the guard.

    python -m ratchet.export.claude_code --harness harness.json --guard-id G --receipt receipt.json \
        --trusted-key <ed25519 public key hex> --out .claude/hooks/ratchet_G.py
"""

from __future__ import annotations

import argparse
import ast
import json
import sys
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from importlib.metadata import entry_points
from pathlib import Path
from typing import Any, Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from ratchet_cases.types import sha256_hex

from ratchet.agent.guard_api import GuardLimits
from ratchet.export import hook_emit
from ratchet.improve.receipt import ReceiptError, verify
from ratchet.types import Guard, Harness, Procedure
from ratchet.verify.dsse import keyid_of

HOOK_GROUP = "ratchet.hooks"
EMIT = "emit"
EMIT_RUNTIME_PATH = Path(hook_emit.__file__)
PROVENANCE_KEYS = (
    "guard_id",
    "guard_sha256",
    "harness_version",
    "harness_digest",
    "decision_receipt_sha256",
    "decision_signers",
    "decided_at",
    "hook_kind",
)
EMIT_HEADER_KEYS = (*PROVENANCE_KEYS, "hook_runtime_sha256")


class ExportError(ValueError):
    """The guard is not admitted, or a hook file does not match its own provenance."""


def text_sha256(text: str) -> str:
    return sha256_hex(text.encode("utf-8"))


@dataclass(frozen=True)
class Provenance:
    guard_id: str
    guard_sha256: str
    harness_version: str
    harness_digest: str
    decision_receipt_sha256: str
    decision_signers: str
    decided_at: str

    def header(self, hook_kind: str, extra: Mapping[str, str]) -> dict[str, str]:
        return {**asdict(self), "hook_kind": hook_kind, **extra}


def _signers(envelope: bytes, trusted: Mapping[str, Ed25519PublicKey]) -> list[str]:
    signed = []
    for keyid, key in sorted(trusted.items()):
        try:
            verify(envelope, {keyid: key})
        except ReceiptError:
            continue
        signed.append(keyid)
    return signed


def verify_admission(
    harness: Harness, envelope: bytes, trusted: Mapping[str, Ed25519PublicKey]
) -> dict[str, Any]:
    """The decision payload, or ExportError unless it verifies under a trusted key and admits exactly
    this harness."""
    try:
        decision = verify(envelope, trusted)
    except ReceiptError as exc:
        raise ExportError(f"decision receipt does not verify: {exc}") from exc
    if not harness.verify_digest():
        raise ExportError("harness content does not match its digest")
    if decision.get("admitted") is not True:
        raise ExportError("the decision did not admit the harness")
    if decision.get("candidate") != harness.version or decision.get("candidate_digest") != harness.digest:
        raise ExportError(
            f"the decision admits {decision.get('candidate')!r}, not harness {harness.version!r}"
        )
    return decision


def admitted_guard(
    harness: Harness, guard_id: str, envelope: bytes, trusted: Mapping[str, Ed25519PublicKey]
) -> tuple[Guard, Provenance]:
    """The guard and its provenance, or ExportError when the receipt does not admit this harness."""
    decision = verify_admission(harness, envelope, trusted)
    guard = next((g for g in harness.guards if g.id == guard_id), None)
    if guard is None:
        raise ExportError(f"harness {harness.version} has no guard {guard_id!r}")
    provenance = Provenance(
        guard_id=guard.id,
        guard_sha256=text_sha256(guard.source),
        harness_version=harness.version,
        harness_digest=harness.digest,
        decision_receipt_sha256=sha256_hex(envelope),
        decision_signers=",".join(_signers(envelope, trusted)),
        decided_at=str(decision.get("decided_at", "")),
    )
    return guard, provenance


def py_literal(text: str) -> str:
    """A Python literal for `text` that `ruff format` leaves as it is: a raw triple-quoted string when
    that is exact (double quotes first), else a double-quoted escaped string."""
    if "\n" in text:
        for quote in ('"""', "'''"):
            if quote not in text and not text.endswith(("\\", quote[0])):
                literal = "r" + quote + text + quote
                if ast.literal_eval(literal) == text:
                    return literal
    return json.dumps(text)


class HookBody(Protocol):
    """A hook body: renders the hook file for an admitted guard and verifies a file it rendered. A factory
    registered under the `ratchet.hooks` entry-point group takes no arguments and returns one."""

    kind: str

    def render(self, guard: Guard, provenance: Provenance, limits: GuardLimits) -> str: ...

    def verify(self, text: str) -> dict[str, str]: ...


def read_header(text: str, keys: Sequence[str] = PROVENANCE_KEYS) -> dict[str, str]:
    """The `# key: value` lines of a hook file's header, up to its first non-comment line."""
    header: dict[str, str] = {}
    for line in text.splitlines():
        if not line.startswith("#"):
            break
        key, sep, value = line.removeprefix("# ").partition(": ")
        if line.startswith("# ") and sep and key in keys:
            header[key] = value
    return header


def _constants(tree: ast.Module) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            try:
                out[node.targets[0].id] = ast.literal_eval(node.value)
            except ValueError:
                continue
    return out


class EmitHookBody:
    """The default body: `ratchet.export.hook_emit`, pasted verbatim. Records and allows every call."""

    kind = EMIT

    def render(self, guard: Guard, provenance: Provenance, limits: GuardLimits) -> str:
        if limits.require:
            raise ExportError(
                "the emit hook applies no isolation layer and enforces nothing; it cannot meet the required "
                f"layers {', '.join(limits.require)}. Choose an enforcing hook body with --hook, or "
                "require none"
            )
        runtime = EMIT_RUNTIME_PATH.read_text(encoding="utf-8")
        header = provenance.header(self.kind, {"hook_runtime_sha256": text_sha256(runtime)})
        lines = [
            "#!/usr/bin/env python3",
            "# Ratchet emit-only guard hook for Claude Code (PreToolUse), from ratchet.export.claude_code.",
            *(f"# {key}: {header[key]}" for key in EMIT_HEADER_KEYS),
            "# It records every call for replay against the guard and allows it; it never blocks.",
            "# `python -m ratchet.export.claude_code --verify <this file>` checks every digest above.",
            hook_emit.RUNTIME_BEGIN,
            runtime.rstrip("\n"),
            "",
            "",
            hook_emit.RUNTIME_END,
            "",
            f"GUARD_ID = {py_literal(guard.id)}",
            f"GUARD_SHA256 = {py_literal(provenance.guard_sha256)}",
            f"RUNTIME_SHA256 = {py_literal(header['hook_runtime_sha256'])}",
            f"GUARD_SOURCE = {py_literal(guard.source)}",
            "CONFIG = EmitConfig(",
            "    guard_id=GUARD_ID,",
            "    guard_sha256=GUARD_SHA256,",
            "    runtime_sha256=RUNTIME_SHA256,",
            "    hook_file=__file__,",
            ")",
            "",
            'if __name__ == "__main__":',
            "    sys.exit(main(CONFIG, sys.argv[1:]))",
            "",
        ]
        return "\n".join(lines)

    def verify(self, text: str) -> dict[str, str]:
        header = read_header(text, EMIT_HEADER_KEYS)
        missing = [k for k in EMIT_HEADER_KEYS if k not in header]
        if missing:
            raise ExportError(f"hook header is missing {missing}")
        runtime = hook_emit.embedded_runtime(text)
        if runtime is None:
            raise ExportError("hook runtime markers are missing")
        constants = _constants(ast.parse(text))
        actual = {
            "guard_id": constants.get("GUARD_ID"),
            "guard_sha256": text_sha256(str(constants.get("GUARD_SOURCE"))),
            "hook_runtime_sha256": text_sha256(runtime),
        }
        pinned = {"GUARD_SHA256": "guard_sha256", "RUNTIME_SHA256": "hook_runtime_sha256"}
        wrong = sorted(k for k, v in actual.items() if header[k] != v)
        wrong += sorted(name for name, key in pinned.items() if constants.get(name) != header[key])
        if wrong:
            raise ExportError(f"hook does not match its header: {wrong}")
        return header


def hook_body(name: str = EMIT) -> HookBody:
    """The emit body, or the body registered as `name` under the `ratchet.hooks` entry-point group."""
    if name == EMIT:
        return EmitHookBody()
    found = [ep for ep in entry_points(group=HOOK_GROUP) if ep.name == name]
    if not found:
        known = sorted({EMIT, *(ep.name for ep in entry_points(group=HOOK_GROUP))})
        raise ExportError(f"no hook body {name!r} is installed; installed: {', '.join(known)}")
    body: HookBody = found[0].load()()
    return body


def render_hook(
    guard: Guard, provenance: Provenance, limits: GuardLimits | None = None, hook: str = EMIT
) -> str:
    """The hook file's text."""
    return hook_body(hook).render(guard, provenance, limits or GuardLimits())


def verify_hook(text: str) -> dict[str, str]:
    """Check that a hook file matches its own header, with the body named by its `hook_kind`. Returns the
    header. This proves the file is the one the receipt names; verifying the receipt itself needs the
    envelope and the signer's public key."""
    kind = read_header(text).get("hook_kind")
    if kind is None:
        raise ExportError("hook header names no hook_kind")
    return hook_body(kind).verify(text)


def settings_entry(command: str, hook_path: str, matcher: str = "*") -> dict[str, Any]:
    """The `.claude/settings.json` fragment that installs a hook. `onFailure: block` makes a hook that
    cannot even start deny the call."""
    handler = {"type": "command", "command": command, "args": [hook_path], "onFailure": "block"}
    return {"hooks": {"PreToolUse": [{"matcher": matcher, "hooks": [handler]}]}}


def export_hook(
    harness: Harness,
    guard_id: str,
    envelope: bytes,
    trusted: Mapping[str, Ed25519PublicKey],
    out: Path,
    limits: GuardLimits | None = None,
    hook: str = EMIT,
) -> Provenance:
    guard, provenance = admitted_guard(harness, guard_id, envelope, trusted)
    text = render_hook(guard, provenance, limits, hook)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text, encoding="utf-8")
    out.chmod(0o755)
    return provenance


# --- loading and the command line ---------------------------------------------------------------------------


def harness_from_json(doc: Mapping[str, Any]) -> Harness:
    return Harness(
        version=doc["version"],
        parent=doc["parent"],
        system_prompt=doc["system_prompt"],
        procedures=[Procedure(**p) for p in doc["procedures"]],
        guards=[Guard(**g) for g in doc["guards"]],
        tool_allowlist=list(doc["tool_allowlist"]),
        created_by=doc["created_by"],
        digest=doc["digest"],
    )


def public_key(hex_key: str) -> Ed25519PublicKey:
    try:
        return Ed25519PublicKey.from_public_bytes(bytes.fromhex(hex_key.strip()))
    except ValueError as exc:
        raise ExportError("a trusted key must be a 32-byte Ed25519 public key in hex") from exc


def trusted_keys(hex_keys: Sequence[str]) -> dict[str, Ed25519PublicKey]:
    keys = [public_key(k) for k in hex_keys]
    return {keyid_of(k): k for k in keys}


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m ratchet.export.claude_code", description=__doc__.split("\n")[0]
    )
    p.add_argument("--verify", type=Path, help="check a generated hook against its header and exit")
    p.add_argument("--harness", type=Path, help="harness JSON (a Harness as written by Ratchet)")
    p.add_argument("--guard-id")
    p.add_argument("--receipt", type=Path, help="the DSSE decision envelope that admitted the harness")
    p.add_argument("--trusted-key", action="append", default=[], help="Ed25519 public key, hex; repeatable")
    p.add_argument("--out", type=Path)
    p.add_argument(
        "--require",
        default=",".join(GuardLimits().require),
        help="isolation layers the hook must apply, comma separated; refused for the emit body",
    )
    p.add_argument(
        "--hook", default=EMIT, help="hook body: emit (default) or a ratchet.hooks entry point name"
    )
    return p


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.verify is not None:
            header = verify_hook(args.verify.read_text(encoding="utf-8"))
            print(json.dumps(header, indent=2))
            return 0
        if not (args.harness and args.guard_id and args.receipt and args.out and args.trusted_key):
            raise ExportError("--harness, --guard-id, --receipt, --trusted-key and --out are required")
        harness = harness_from_json(json.loads(args.harness.read_text(encoding="utf-8")))
        require = tuple(x for x in args.require.split(",") if x)
        provenance = export_hook(
            harness,
            args.guard_id,
            args.receipt.read_bytes(),
            trusted_keys(args.trusted_key),
            args.out,
            GuardLimits(require=require),
            args.hook,
        )
    except ExportError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(asdict(provenance), indent=2))
    hook_path = str(args.out) if args.out.is_absolute() else "${CLAUDE_PROJECT_DIR}/" + args.out.as_posix()
    print(json.dumps(settings_entry("python3", hook_path), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())

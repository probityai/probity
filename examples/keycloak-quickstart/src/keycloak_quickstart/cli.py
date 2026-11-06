"""Command line for the quickstart: principal, record and swap-thumbprint."""

from __future__ import annotations

import argparse
import datetime
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import principal as principal_mod
from . import record


def read_json(path: Path) -> dict:
    return json.loads(path.read_text())


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def cmd_principal(args: argparse.Namespace) -> int:
    token = args.token.read_text().strip()
    built = principal_mod.build_principal(token, read_json(args.jwks), args.auth_method)
    write_json(args.out, built)
    print(f"principal: iss={built['issuer']}")
    print(f"           sub={built['subject']} client_id={built['clientId']}")
    print(f"           kid={built['kid']}")
    print(f"           thumbprint={built['keyThumbprint']}")
    return 0


def cmd_record(args: argparse.Namespace) -> int:
    built = read_json(args.principal)
    args.out.mkdir(parents=True, exist_ok=True)
    observer_key = Ed25519PrivateKey.generate()
    agent_key = Ed25519PrivateKey.generate()
    arguments = f"settlement {args.amount} by {built['clientId']}".encode()
    before, after = record.append_ledger(args.out / "ledger" / "settlements.jsonl", arguments.decode())
    now = datetime.datetime.now(datetime.UTC).replace(microsecond=0)
    pred = record.build_predicate(
        built,
        agent_key=agent_key,
        observer_key=observer_key,
        before_root=before,
        after_root=after,
        arguments=arguments,
        now=now,
    )
    envelope = record.seal(record.statement(pred), observer_key)
    write_json(args.out / "record.dsse.json", envelope)
    record.save_key(args.out / "observer.key", observer_key)
    (args.out / "observer.pub").write_text(record.raw_public(observer_key).hex() + "\n")
    print(f"recorded: write by {built['clientId']} ({built['subject']})")
    print(f"          request {pred['decision']['requestDigest']}")
    print(f"          record  {args.out / 'record.dsse.json'}")
    return 0


def cmd_swap(args: argparse.Namespace) -> int:
    envelope = read_json(args.record)
    stmt = record.decode_envelope(envelope)
    member = stmt["predicate"]["principal"]
    others = [
        principal_mod.jwk_thumbprint(k)
        for k in read_json(args.jwks)["keys"]
        if principal_mod.jwk_thumbprint(k) != member["keyThumbprint"]
    ]
    member["keyThumbprint"] = others[0]
    resealed = record.seal(stmt, record.load_key(args.observer_key))
    write_json(args.out, resealed)
    print(f"swapped keyThumbprint to {others[0]} and re-sealed {args.out}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="keycloak-quickstart")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("principal", help="read a Keycloak token into a principal member")
    p.add_argument("--token", type=Path, required=True)
    p.add_argument("--jwks", type=Path, required=True)
    p.add_argument("--auth-method", default="client_secret_basic")
    p.add_argument("--out", type=Path, required=True)
    p.set_defaults(func=cmd_principal)

    r = sub.add_parser("record", help="record one action and seal a record carrying the principal")
    r.add_argument("--principal", type=Path, required=True)
    r.add_argument("--out", type=Path, required=True)
    r.add_argument("--amount", default="120.00")
    r.set_defaults(func=cmd_record)

    s = sub.add_parser("swap-thumbprint", help="swap the key thumbprint and re-seal the record")
    s.add_argument("--record", type=Path, required=True)
    s.add_argument("--jwks", type=Path, required=True)
    s.add_argument("--observer-key", type=Path, required=True)
    s.add_argument("--out", type=Path, required=True)
    s.set_defaults(func=cmd_swap)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except principal_mod.TokenError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

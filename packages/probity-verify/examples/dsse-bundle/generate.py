"""Reproduce the DSSE bundle vectors for ``probityai verify`` and their expected outputs.

Each envelope wraps the done receipt of a run in ``../done-receipt``. The signing
keys come from fixed seeds and Ed25519 signatures are deterministic, so every
byte here is reproducible. The seeds are test keys and sign nothing else.
Run with --check to compare the committed bytes.
"""

import argparse
import base64
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

HERE = Path(__file__).resolve().parent
DONE = HERE.parent / "done-receipt"
SIGNER = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
OTHER = Ed25519PrivateKey.from_private_bytes(bytes(range(33, 65)))
IN_TOTO = "application/vnd.in-toto+json"


def pae(kind, payload):
    kind = kind.encode()
    return b"DSSEv1 %d %s %d %s" % (len(kind), kind, len(payload), payload)


def b64(data):
    return base64.b64encode(data).decode("ascii")


def envelope(payload, kind=IN_TOTO, key=SIGNER, payload_text=None):
    signature = key.sign(pae(kind, payload))
    return {"payload": payload_text or b64(payload), "payloadType": kind,
            "signatures": [{"keyid": "", "sig": b64(signature)}]}


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")


def pem(key):
    return key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)


def receipt(run):
    return (DONE / run / "receipt.json").read_bytes()


def tampered(data):
    value = json.loads(data)
    value["predicate"]["integrity"]["reason"] = "tampered_after_signing"
    return encoded(value)


def vectors():
    """``name -> (envelope or raw bytes, run, key file, expected exit)``."""
    honest = receipt("honest")
    signed = envelope(honest)
    forged = dict(signed, payload=b64(tampered(honest)))
    gamed = envelope(receipt("tampered-grader"))
    # The unpadded vector needs a payload whose canonical base64 ends in "=".
    padded = b64(receipt("tampered-grader"))
    if not padded.endswith("="):
        raise SystemExit("the tampered-grader receipt no longer needs base64 padding")
    return {
        "valid": (signed, "honest", "signer.pub", 0),
        "tampered-receipt": (gamed, "tampered-grader", "signer.pub", 0),
        "tampered-payload": (forged, "honest", "signer.pub", 0),
        "wrong-key": (signed, "honest", "other.pub", 0),
        "wrong-payload-type": (envelope(honest, kind="application/json"), "honest",
                               "signer.pub", 0),
        "malformed-no-signatures": (dict(signed, signatures=[]), "honest", "signer.pub", 2),
        "malformed-unpadded-base64": (dict(gamed, payload=padded.rstrip("=")),
                                      "tampered-grader", "signer.pub", 2),
    }


def expected(name, run, key, status):
    """The ``probityai verify --json`` stdout, or the stderr line for a refusal."""
    sys.path.insert(0, str(HERE.parents[1] / "src"))
    import contextlib
    import io

    from probity_verify.cli import main

    err = io.StringIO()
    argv = [str(HERE / f"{name}.dsse.json"), "--case", str(DONE / run / "receipt.case.json"),
            "--policy", str(DONE / run / "receipt.policy.json"), "--key", str(HERE / key),
            "--json"]
    stdout = io.BytesIO()
    wrapper = io.TextIOWrapper(stdout, encoding="utf-8")
    with contextlib.redirect_stderr(err), contextlib.redirect_stdout(wrapper):
        code = main(argv)
        wrapper.flush()
    if code != status:
        raise SystemExit(f"{name}: exit {code}, expected {status}: {err.getvalue()}")
    text = stdout.getvalue() if status == 0 else err.getvalue().encode("utf-8")
    return text.replace(str(HERE).encode(), b"<vectors>")


def files():
    built = {"signer.pub": pem(SIGNER), "other.pub": pem(OTHER)}
    table = {}
    for name, (value, run, key, status) in vectors().items():
        built[f"{name}.dsse.json"] = encoded(value)
        table[name] = {"case": f"../done-receipt/{run}/receipt.case.json",
                       "policy": f"../done-receipt/{run}/receipt.policy.json",
                       "key": key, "exit": status,
                       "expected": f"expected/{name}.{'json' if status == 0 else 'err'}"}
    built["vectors.json"] = encoded(table)
    return built, table


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    built, table = files()
    if not args.check:
        for name, data in built.items():
            (HERE / name).write_bytes(data)
    for name, row in table.items():
        run = Path(row["case"]).parent.name
        built[row["expected"]] = expected(name, run, row["key"], row["exit"])
    stale = [name for name, data in built.items()
             if not (HERE / name).is_file() or (HERE / name).read_bytes() != data]
    if args.check:
        if stale:
            raise SystemExit("stale: " + ", ".join(sorted(stale)))
        return
    (HERE / "expected").mkdir(exist_ok=True)
    for name in stale:
        (HERE / name).write_bytes(built[name])


if __name__ == "__main__":
    main()

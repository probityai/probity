"""Produce real local file captures through a separately installed Observer.

Only this producer imports Observer. The Verify consumer runs in a separate
environment. Local author-operated keys do not establish independent custody.
"""

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import sys
from pathlib import Path

from probity_observer.broker import Broker
from probity_observer.crypto import SigningKey, canonical
from probity_observer.ledger import LedgerWitness


def save(path, value):
    with path.open("xb") as stream:
        stream.write(canonical(value))
        stream.flush()
        os.fsync(stream.fileno())
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--mode", choices=("completed", "after-seal", "before-terminal"), required=True)
    args = parser.parse_args()
    root = args.output.absolute()
    root.mkdir(parents=True, exist_ok=False)
    workspace = root / "work"
    workspace.mkdir()
    observer, witness_key = SigningKey.generate(), SigningKey.generate()
    content = b"native retained result\n"
    authority = {"intervalId": "native-" + args.mode, "scope": "/work", "operation": "write-file"}
    distribution = importlib.metadata.distribution("agent-evidence-observer")
    installed = []
    for name in distribution.files or ():
        if str(name).startswith("probity_observer/") and str(name).endswith(".py"):
            path = distribution.locate_file(name)
            raw = path.read_bytes()
            installed.append({"path": str(name), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
    save(root / "producer-environment.json", {
        "python": sys.version, "executable": sys.executable, "platform": platform.platform(),
        "observer_distribution": distribution.version,
        "cryptography": importlib.metadata.version("cryptography"), "installed_modules": installed,
        "source_binding": "Installed module files read before broker invocation; not authenticated executing-byte provenance.",
    })
    save(root / "public-selection.json", {
        "observer_key": observer.public_hex, "witness_key": witness_key.public_hex,
        "authority": authority, "request_id": "write-1", "path": "/work/result.txt",
        "content_sha256": hashlib.sha256(content).hexdigest(), "witness_scope": "PEER",
        "operator": "author-operated local producer and witness",
    })
    witness = LedgerWitness(root / "ledger.jsonl", witness_key, observer.public_hex)
    broker = Broker(workspace, root / "history.jsonl", authority, observer, witness)
    broker.begin()
    broker.write("write-1", "/work/result.txt", content)
    if args.mode != "before-terminal":
        save(root / "packet.json", broker.seal())
    save(root / "head.json", witness.signed_head())
    print(json.dumps({"mode": args.mode, "next_exit": 0 if args.mode == "completed" else 74}), flush=True)
    if args.mode != "completed":
        os._exit(74)


if __name__ == "__main__":
    main()

"""Drive go-witness (third-party libraries only) through the probity-records checkpoint feed.

Run: python interop.py PATH_TO_go-witness. Exit 0 only when the external witness cosigned two
checkpoints (the second over a consistency proof), refused a split view, and the offline verifier
accepted the journal under a tlog-policy naming the external witness's key, and refused it without.
"""

import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from probity_records import Journal, Signer, Trust, verify_journal
from probity_records import witness as w

ORIGIN = "authority.example/interop"


def main(binary: str) -> int:
    signer = Signer.generate()
    journal = Journal(Path(tempfile.mkdtemp()) / "authority", signer)
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    proc = subprocess.Popen([binary, "-log-vkey", w.log_vkey(ORIGIN, signer), "-seed", os.urandom(32).hex(),
                             "-listen", f"127.0.0.1:{port}"], stdout=subprocess.PIPE, text=True)
    try:
        witness_vkey = proc.stdout.readline().strip()
        url = f"http://127.0.0.1:{port}"
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", port), 0.2).close()
                break
            except OSError:
                time.sleep(0.1)
        policy = f"log {w.log_vkey(ORIGIN, signer)}\nwitness ext {witness_vkey}\nquorum ext\n"
        feed = w.Feed(journal, ORIGIN, [(url, witness_vkey)], policy=w.parse_policy(policy))
        for i in range(3):
            journal.append("https://example.test/t", f"s{i}", "0" * 64, {"phase": "note"})
        feed.publish()
        for i in range(5):
            journal.append("https://example.test/t", f"t{i}", "0" * 64, {"phase": "note"})
        note = feed.publish()
        trust = Trust(witness_policy=policy)
        out = verify_journal(journal.directory, [signer.public_pem()], journal.checkpoint(), trust=trust,
                             witnessed_checkpoint=note)
        print("verify:", out["verdict"], out["witnessed"], out["failures"])
        bare = w.sign_checkpoint(w.Checkpoint(ORIGIN, 8, w.root(w.journal_leaves(journal.path))), signer)
        refused = verify_journal(journal.directory, [signer.public_pem()], journal.checkpoint(), trust=trust,
                                 witnessed_checkpoint=bare)
        print("uncosigned:", refused["verdict"], refused["failures"])
        fork = w.sign_checkpoint(w.Checkpoint(ORIGIN, 8, w.leaf_hash(b"other")), signer)
        try:
            w.add_checkpoint(url, w.encode_add_checkpoint(8, [], fork))
            print("split view: ACCEPTED (defect)")
            return 1
        except w.WitnessRefused as exc:
            status = exc.status
            print("split view refused:", status)
        ok = (out["verdict"] == "PASS" and out["witnessed"]["cosigners"] == ["ext"]
              and refused["verdict"] == "FAIL" and status == 422)
        print("INTEROP", "PASS" if ok else "FAIL")
        return 0 if ok else 1
    finally:
        proc.kill()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))

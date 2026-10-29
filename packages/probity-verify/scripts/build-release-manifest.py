"""Build or check docs/release-manifest.json, the record of what a release checks against.

The manifest binds, for the version in pyproject.toml: the verifier identifier every
decision carries as ``reference.verifier.id``, the digest of each conformance corpus, one
digest over the expected decisions of all their vectors, and the GitHub Actions and
workflow files that build and publish the release.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[1]
OUTPUT = ROOT / "docs/release-manifest.json"
CORPORA = ("vectors-done-checks", "vectors-operand-lineage", "vectors-source-coverage")
WORKFLOWS = ("release.yml", "python-build.yml")
USES = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)", re.MULTILINE)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def build() -> dict:
    """The manifest for the source at ROOT."""
    sys.path.insert(0, str(ROOT / "src"))
    from probity_verify.core import REFERENCE_VERIFIER_ID

    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    corpora, expectations = [], []
    for name in CORPORA:
        manifest = json.loads((ROOT / name / "MANIFEST.json").read_text(encoding="utf-8"))
        corpora.append({"directory": name, "suite": manifest["suite"],
                        "corpus_digest": manifest["corpusDigest"], "vectors": len(manifest["vectors"])})
        expectations.extend({"suite": manifest["suite"], "id": vector["id"], "expected": vector["expected"]}
                            for vector in manifest["vectors"])
    expectations.sort(key=lambda row: (row["suite"], row["id"]))
    workflows, actions = [], set()
    for name in WORKFLOWS:
        raw = (REPO / ".github/workflows" / name).read_bytes()
        workflows.append({"path": f".github/workflows/{name}", "sha256": _sha256(raw)})
        actions.update(ref for ref in USES.findall(raw.decode("utf-8")) if not ref.startswith("./"))
    return {
        "package": project["name"],
        "version": project["version"],
        "reference": {"verifier": {"id": REFERENCE_VERIFIER_ID}},
        "corpora": corpora,
        "expectations_digest": _sha256(_canonical(expectations)),
        "workflows": workflows,
        "actions": sorted(actions),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail when the file is not current")
    args = parser.parse_args()
    text = json.dumps(build(), indent=2, sort_keys=True) + "\n"
    if args.check:
        if not OUTPUT.is_file() or OUTPUT.read_text(encoding="utf-8") != text:
            print("docs/release-manifest.json is stale; run scripts/build-release-manifest.py", file=sys.stderr)
            return 1
        return 0
    OUTPUT.write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

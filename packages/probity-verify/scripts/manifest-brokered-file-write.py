"""Bind only public native results and exact package source, excluding venvs."""

import argparse
import hashlib
import json
import stat
from pathlib import Path


def build(root):
    selected = ["native", "wheels", "producer-source/pyproject.toml", "producer-source/README.md",
                "producer-source/LICENSE", "producer-source/src", "producer-revision.txt", "producer-tree.txt",
                "producer-dependencies.txt", "consumer-dependencies.txt"]
    paths = []
    for name in selected:
        path = root / name
        try:
            mode = path.lstat().st_mode
        except FileNotFoundError:
            continue
        if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
            raise ValueError("public capture selection is not a regular file or directory")
        paths.extend(path.rglob("*") if stat.S_ISDIR(mode) else [path])
    files = []
    for path in sorted(set(paths)):
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            continue
        if not stat.S_ISREG(mode):
            raise ValueError("public capture contains a nonregular file")
        raw = path.read_bytes()
        files.append({"path": path.relative_to(root).as_posix(), "bytes": len(raw),
                      "sha256": hashlib.sha256(raw).hexdigest()})
    return {"schema": "probity-brokered-file-write-capture-manifest/v1", "base_directory": ".",
            "scope": "Selected public capture files relative to this manifest's parent; not authenticated executing-byte provenance.",
            "files": files}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    args = parser.parse_args()
    args.root.mkdir(parents=True, exist_ok=True)
    result = build(args.root)
    (args.root / "manifest.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"files": len(result["files"]), "manifest": str(args.root / "manifest.json")}))


if __name__ == "__main__":
    main()

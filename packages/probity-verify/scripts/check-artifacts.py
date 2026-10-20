"""Check wheel payloads, source inputs and RECORD hashes before publication."""

import argparse
import base64
import csv
import hashlib
import io
import stat
import subprocess
import tomllib
from pathlib import Path, PurePosixPath
from zipfile import ZipFile

from distribution_checks import check_source_archive, check_wheel_metadata


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def check(wheel: Path, sdist: Path, source_root: Path | None = None) -> None:
    root = source_root.resolve() if source_root is not None else Path(__file__).resolve().parents[1]
    project = tomllib.loads((root / "pyproject.toml").read_text())["project"]
    source = {p.relative_to(root / "src").as_posix(): p
              for p in (root / "src/probity_verify").rglob("*.py")}
    samples = root / "examples/source-coverage"
    source.update({"probity_verify/samples/" + p.name: p for p in samples.iterdir()
                   if p.name == "__init__.py" or p.suffix in {".json", ".html", ".txt"}})
    with ZipFile(wheel) as archive:
        names = archive.namelist()
        require(len(names) == len(set(names)), "duplicate wheel member")
        for member in archive.infolist():
            path = PurePosixPath(member.filename)
            require(not path.is_absolute() and ".." not in path.parts and "\\" not in member.filename
                    and path.as_posix() == member.filename, "wheel member path")
            require(not member.is_dir() and stat.S_IFMT(member.external_attr >> 16) in {0, stat.S_IFREG},
                    "wheel regular-file payload")
        infos = [n for n in names if n.endswith(".dist-info/METADATA")]
        require(len(infos) == 1, "wheel metadata population")
        info = infos[0].rsplit("/", 1)[0]
        metadata = check_wheel_metadata(archive, info, root, project, "probity_verify", ["LICENSE"])
        payload = {n for n in names if not n.startswith(info + "/")}
        require(payload == set(source), "wheel source and sample population")
        for name, path in source.items():
            require(archive.read(name) == path.read_bytes(), "wheel source bytes: " + name)
        record = info + "/RECORD"
        rows = list(csv.reader(io.StringIO(archive.read(record).decode())))
        require(all(len(row) == 3 for row in rows), "RECORD columns")
        require(len(rows) == len(names) and {r[0] for r in rows} == set(names), "RECORD population")
        for name, digest, size in rows:
            if name == record:
                require(digest == size == "", "RECORD self-reference")
            else:
                raw = archive.read(name)
                value = base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).rstrip(b"=").decode()
                require(digest == "sha256=" + value and size == str(len(raw)), "RECORD bytes: " + name)
    tracked = subprocess.check_output(["git", "ls-files", "-z", "--", "src", "examples", "tests", "scripts",
        "docs", "vectors-source-coverage", "vectors-operand-lineage", "vectors-done-checks", "pyproject.toml", "README.md", "LICENSE",
        "MANIFEST.in"], cwd=root)
    expected = {name for name in tracked.decode().split("\0") if name}
    check_source_archive(sdist, root, project, metadata, expected,
                         "src/probity_verify.egg-info", "probity_verify")
    print(f"checked {len(source)} wheel payloads, every RECORD hash and the source archive inputs")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheel", type=Path)
    parser.add_argument("sdist", type=Path)
    parser.add_argument("--source-root", type=Path, help="compare a retained artifact with its matching source snapshot")
    args = parser.parse_args()
    check(args.wheel, args.sdist, args.source_root)

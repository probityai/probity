"""Which verifier bytes produced a decision: the release and a digest of the package files.

Every decision names its verifier as ``reference.verifier``: the stable ``id``, the ``version`` of
the release whose files are running, and ``package_sha256``, a digest of the files of the
``agent_evidence_verify`` package that is running. A relying party that holds the wheel recomputes
the same digest from the wheel's members (``python -m agent_evidence_verify.identity <wheel>``).

The fields are what the producing process says about itself. A matching digest identifies which
release a producer claims to have run and lets an honest pipeline's decisions be traced to a
wheel; it does not authenticate the decision, because any program can print any digest, and it
does not cover code outside the package (dependencies, ``sitecustomize``, a ``.pth`` hook) or
bytecode in ``__pycache__``. A decision is evidence of which bytes ran only when it comes from a
runner the relying party already trusts to report its own runtime, such as its own CI.

``version`` is named only when the running package is the distribution's own: the installed
files its ``RECORD`` lists, or the source tree of an editable install. A source tree imported
ahead of an installed wheel (``PYTHONPATH``, a checkout on ``sys.path``) would otherwise carry the
wheel's version beside a digest of other files.

The digest is SHA-256 over ``sha256sum``-style lines, one per file, sorted by path::

    <sha256 hex of the file>  agent_evidence_verify/<path inside the package>\\n

Bytecode (``__pycache__`` and ``*.pyc``) is left out, because an interpreter writes it after
install. Paths use ``/``. The wheel's members under ``agent_evidence_verify/`` and an install of
that wheel give the same lines, so they give the same digest.
"""

from __future__ import annotations

import hashlib
import re
import sys
import zipfile
from collections.abc import Iterable
from functools import lru_cache
from importlib.metadata import Distribution, distributions
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlparse

from .ijson import parse_ijson

DISTRIBUTION = "agent-evidence-verify"
PACKAGE = "agent_evidence_verify"

#: The release detail of ``reference.verifier`` in compact sorted JSON output.
_RELEASE_DETAIL = re.compile(rb',"package_sha256":"([0-9a-f]{64})"(,"version":"[^"]*")?')


def _counted(path: PurePosixPath) -> bool:
    return "__pycache__" not in path.parts and path.suffix != ".pyc"


def package_digest(files: Iterable[tuple[str, bytes]]) -> str:
    """The digest of ``(path, bytes)`` pairs, each path relative to the package's parent."""
    lines = sorted(f"{hashlib.sha256(body).hexdigest()}  {path}\n" for path, body in files
                   if _counted(PurePosixPath(path)))
    if not lines:
        raise ValueError(f"no files of the {PACKAGE} package were found")
    return hashlib.sha256("".join(lines).encode("utf-8")).hexdigest()


def _installed_files() -> Iterable[tuple[str, bytes]]:
    root = Path(__file__).resolve().parent
    for path in sorted(root.rglob("*")):
        if path.is_file():
            yield f"{PACKAGE}/{path.relative_to(root).as_posix()}", path.read_bytes()


#: A wheel member that installs into the package: at the root, or under ``<dist>.data/purelib``
#: or ``platlib`` (PEP 427), which an installer moves into the same directory.
_WHEEL_MEMBER = re.compile(rf"(?:[^/]+\.data/(?:purelib|platlib)/)?({PACKAGE}/.+)")


def wheel_digest(wheel: Path) -> str:
    """The package digest a decision written by an install of ``wheel`` carries."""
    with zipfile.ZipFile(wheel) as archive:
        members = []
        for name in archive.namelist():
            match = _WHEEL_MEMBER.fullmatch(name)
            if match and not name.endswith("/"):
                members.append((match.group(1), archive.read(name)))
    return package_digest(members)


def release_of(dist: Distribution, running: Path) -> str | None:
    """``dist``'s version when ``running`` (this module's file) is one of ``dist``'s own files."""
    running = running.resolve()
    for entry in dist.files or ():
        if (PurePosixPath(str(entry)) == PurePosixPath(PACKAGE, running.name)
                and Path(str(dist.locate_file(entry))).resolve() == running):
            return dist.version
    try:
        direct = parse_ijson(dist.read_text("direct_url.json") or "null")
    except ValueError:  # IJSONError included
        return None
    if isinstance(direct, dict) and (direct.get("dir_info") or {}).get("editable"):
        url = urlparse(str(direct.get("url", "")))
        if url.scheme == "file" and running.is_relative_to(Path(unquote(url.path)).resolve()):
            return dist.version
    return None


def placeholder_release_detail(output: bytes) -> bytes:
    """Compact JSON decisions with the package digest and version as fixed placeholders.

    A committed expected output stays byte-exact across releases: only the verdict and its
    evidence are compared, and the verifier id stays in the bytes.
    """
    return _RELEASE_DETAIL.sub(
        lambda m: b',"package_sha256":"<package_sha256>"'
        + (b',"version":"<version>"' if m.group(2) else b""), output)


def without_release_detail(output: bytes) -> bytes:
    """Compact JSON decisions as a release that named its verifier by id only wrote them."""
    return _RELEASE_DETAIL.sub(b"", output)


def running_release() -> str | None:
    """The release of the running package, or None when it is not the distribution's own files.

    Every distribution of the name on ``sys.path`` is asked, not only the first: a build of the
    source tree leaves ``src/agent_evidence_verify.egg-info`` beside the package, and with ``src``
    on ``sys.path`` that metadata is found ahead of the installed distribution while owning none of
    the running files.
    """
    running = Path(__file__)
    for dist in distributions(name=DISTRIBUTION):
        release = release_of(dist, running)
        if release is not None:
            return release
    return None  # a source tree that was never installed has no release to name


@lru_cache(maxsize=1)
def verifier_reference(verifier_id: str) -> dict:
    """``reference.verifier`` for this process: id, installed version and package digest."""
    reference = {"id": verifier_id, "package_sha256": package_digest(_installed_files())}
    release = running_release()
    if release is not None:
        reference["version"] = release
    return reference


def main(argv: list[str] | None = None) -> int:
    """Print the package digest of each wheel named on the command line."""
    args = sys.argv[1:] if argv is None else argv
    if not args:
        print("usage: python -m agent_evidence_verify.identity WHEEL...", file=sys.stderr)
        return 2
    for name in args:
        print(f"{wheel_digest(Path(name))}  {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

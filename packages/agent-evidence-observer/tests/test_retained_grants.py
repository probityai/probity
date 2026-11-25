"""The retired grant module is kept once, as the exact bytes every retained run pinned."""

import hashlib
import importlib
import subprocess
import sys

import pytest
from probity_observer import retained_grants

PINNED = "a51c74997d81af6a046cb8336aa683b047c1967cd760a2bf08806cb80c20c990"


def test_the_pinned_file_is_the_bytes_every_retained_run_names() -> None:
    assert retained_grants.PINNED_SHA256 == PINNED
    assert hashlib.sha256(retained_grants.PINNED_FILE.read_bytes()).hexdigest() == PINNED


def test_the_loaded_module_is_the_pinned_one() -> None:
    module = retained_grants.load()
    assert module.GRANT_DOMAIN == "probity-protected-action-grant-v0"
    assert retained_grants.verify_grant is module.verify_grant
    assert retained_grants.ActionRequest is module.ActionRequest


def test_other_bytes_are_refused_not_loaded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(retained_grants, "PINNED_SHA256", "0" * 64)
    monkeypatch.delitem(sys.modules, retained_grants.MODULE_NAME)
    with pytest.raises(retained_grants.PinnedBytesDiffer):
        retained_grants.load()
    assert retained_grants.MODULE_NAME not in sys.modules


def test_a_changed_file_is_refused_by_a_fresh_interpreter(tmp_path) -> None:
    root = tmp_path / "probity_observer"
    root.parent.mkdir(exist_ok=True)
    source = retained_grants.PINNED_FILE.parent
    probe = (
        "import sys, shutil, pathlib\n"
        f"shutil.copytree({str(source)!r}, {str(root)!r}, ignore=shutil.ignore_patterns('__pycache__'))\n"
        f"p = pathlib.Path({str(root)!r}) / '_pinned_grant_records_d1e92ccb7.py'\n"
        "p.write_bytes(p.read_bytes() + b'\\n# edited\\n')\n"
        f"sys.path.insert(0, {str(tmp_path)!r})\n"
        "try:\n    import probity_observer.retained_grants\n"
        "except ImportError as exc:\n    print(type(exc).__name__)\n    raise SystemExit(0)\n"
        "raise SystemExit(3)\n"
    )
    done = subprocess.run([sys.executable, "-I", "-c", probe], capture_output=True, text=True, check=False)
    assert done.returncode == 0, done.stderr
    assert done.stdout.strip() == "PinnedBytesDiffer"
    importlib.invalidate_caches()

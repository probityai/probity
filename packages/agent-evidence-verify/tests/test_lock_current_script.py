"""The lock check recompiles onto the committed lock, so upstream releases cannot turn it red."""

import os
import stat
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check-lock-current.sh"


def run_check(tmp_path, compiled_text):
    """Run the script with a stand-in uv that records the output file's prior content."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    uv = bin_dir / "uv"
    uv.write_text(
        "#!/bin/sh\n"
        'while [ "$#" -gt 0 ]; do [ "$1" = -o ] && out=$2; shift; done\n'
        'cat "$out" > "$SEEN"\n'
        'printf "%s" "$COMPILED" > "$out"\n'
    )
    uv.chmod(uv.stat().st_mode | stat.S_IEXEC)
    lock = tmp_path / "x.txt"
    lock.write_text("pycparser==3.11\n")
    (tmp_path / "x.in").write_text("cffi\n")
    env = dict(os.environ, PATH=f"{bin_dir}:{os.environ['PATH']}",
               SEEN=str(tmp_path / "seen"), COMPILED=compiled_text)
    done = subprocess.run(
        [str(SCRIPT), str(tmp_path / "x.in"), str(lock), "3.12", str(tmp_path / "scratch")],
        env=env, capture_output=True, text=True, check=False)
    return done, (tmp_path / "seen").read_text()


def test_compile_starts_from_the_committed_lock(tmp_path):
    done, seen = run_check(tmp_path, "pycparser==3.11\n")
    assert seen == "pycparser==3.11\n"
    assert done.returncode == 0, done.stderr


def test_a_lock_that_disagrees_with_its_input_fails(tmp_path):
    done, _ = run_check(tmp_path, "pycparser==3.11\ncffi==2.1.1\n")
    assert done.returncode == 1
    assert "+cffi==2.1.1" in done.stdout

"""Every file under ``vectors/shared`` is this package's output, byte for byte, on every run.

``scripts/gen_shared_vectors.py`` writes the shared vectors that the TypeScript twin and every other reader
run. A generator that reads the host's clock writes different journal lines on each run, so regenerating one
family rewrites the others, and a maintainer who keeps only the family they changed leaves the committed files
behind the generator. These tests hold it to one output: no clock reader named in the scripts, the same bytes from
two runs, and the bytes that are committed.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
from probity_records.clock_lint import scan_paths

ROOT = Path(__file__).resolve().parents[1]
SHARED = ROOT / "vectors" / "shared"


def _generator():
    spec = importlib.util.spec_from_file_location(
        "gen_shared_vectors", ROOT / "scripts" / "gen_shared_vectors.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _files(directory: Path) -> dict[str, bytes]:
    return {p.name: p.read_bytes() for p in sorted(directory.glob("*.json"))}


@pytest.fixture(scope="module")
def two_runs(
    tmp_path_factory: pytest.TempPathFactory,
) -> tuple[dict[str, bytes], dict[str, bytes]]:
    gen = _generator()
    first, second = tmp_path_factory.mktemp("first"), tmp_path_factory.mktemp("second")
    gen.main(first)
    gen.main(second)
    return _files(first), _files(second)


def test_the_vector_scripts_name_no_clock_reader() -> None:
    result = scan_paths([ROOT / "scripts"])
    assert (
        len(result.files) >= 2
    )  # the read path works: an empty listing reports absence like a clean tree
    assert result.findings == (), "\n".join(map(str, result.findings))


def test_two_runs_write_the_same_bytes(
    two_runs: tuple[dict[str, bytes], dict[str, bytes]],
) -> None:
    first, second = two_runs
    assert sorted(first) == sorted(second)
    assert [name for name in first if first[name] != second[name]] == []


def test_every_committed_file_is_the_generators_output(
    two_runs: tuple[dict[str, bytes], dict[str, bytes]],
) -> None:
    written, committed = two_runs[0], _files(SHARED)
    assert (
        len(written) >= 19
    )  # every family the generator writes; other tools write the rest of the directory
    assert [name for name in written if committed.get(name) != written[name]] == []

"""The import probe against a module that forges its after-import report (oracle round 1,
Kimi A10). The observer catches a forged report that leaves the genuine one behind it; a
forgery that silences the genuine one passes here, and probity-verify reads that pass as open
(``probe_import_unobserved``)."""

import sys

import pytest

from probity_observer.done import replay

SNAPSHOT = ("import builtins, json, os\n"
            "_s = sorted([n, type(v).__name__, id(v)] for n, v in vars(builtins).items())\n"
            "_r = (json.dumps({'builtins': _s}) + '\\n').encode()\n")
FORGE = ("for _fd in range(3, 64):\n"
         "    try:\n"
         "        os.write(_fd, _r)\n"
         "        break\n"
         "    except OSError:\n"
         "        pass\n")
MUTATE = "import builtins\nbuiltins.oracle_import_mutation = 1\n"
ENTRY = "def f():\n    return 1\n"

MODULES = {
    "honest": ENTRY,
    "mutating": MUTATE + ENTRY,
    "forged": SNAPSHOT + MUTATE + FORGE + ENTRY,
    "forged_then_redirected": (SNAPSHOT + MUTATE + FORGE
                               + "os.dup2(os.open(os.devnull, os.O_WRONLY), _fd)\n" + ENTRY),
    "forged_then_closed": SNAPSHOT + MUTATE + FORGE + "os.close(_fd)\n" + ENTRY,
}


def probe(tmp_path, name):
    (tmp_path / "cand.py").write_text(MODULES[name])
    request = {"child_argv": [sys.executable, "-I", "-c",
                              replay.child_source("cand", "f", probe_import=True)],
               "child_cwd": str(tmp_path), "call_timeout": 10.0}
    result = replay.import_side_effects(request)
    replay.close_all()
    return result


def test_an_honest_import_passes_on_its_own_report(tmp_path):
    assert probe(tmp_path, "honest")["passed"] is True


def test_a_real_change_fails_on_the_comparison(tmp_path):
    result = probe(tmp_path, "mutating")
    assert (result["passed"], result["builtins"]["added"]) == (False, ["oracle_import_mutation"])
    assert replay.failure_kind(result) == "assertion"


def test_a_forged_report_ahead_of_the_genuine_one_fails(tmp_path):
    # Before the extra-report check this forgery passed the probe (passed: True).
    result = probe(tmp_path, "forged")
    assert (result["passed"], result["failure"]) == (False, replay.PROTOCOL_FORGED)
    assert result["builtins"] == {"extra_reports": 1}
    assert replay.failure_kind(result) == "assertion"


@pytest.mark.parametrize("name", ["forged_then_redirected", "forged_then_closed"])
def test_a_forgery_that_silences_the_genuine_report_is_only_an_in_process_pass(tmp_path, name):
    # The observer cannot tell this from an honest pass: both rest on the candidate's own
    # report. That is why probity-verify never reads an import probe pass as supported.
    result = probe(tmp_path, name)
    assert result["passed"] is True
    assert result["evidence_from_worker"] == ["builtins_after_import"]

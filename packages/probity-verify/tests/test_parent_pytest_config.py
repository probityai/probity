"""An outside write of pyproject.toml/tox.ini/setup.cfg in a workspace
ancestor that the observer recorded as carrying no pytest section is not tamper; a sectioned one,
or one recorded without the field, still is."""
from __future__ import annotations

import hashlib

import pytest
from done_run import decide, honest_records
from probity_verify import CaseError
from test_out_of_tree_tamper import add_external, outcome, sealed

PROTECTED = "protected_paths/v1"
SECTIONLESS = b'[project]\nname = "x"\nversion = "0"\n'
SECTIONED = b'[project]\nname = "x"\n\n[tool.pytest.ini_options]\naddopts = "-p no:x"\n'
DIGEST = hashlib.sha256(SECTIONLESS).hexdigest()


def decide_with(tmp_path, name, kind="write", **facts):
    records = sealed(honest_records())
    add_external(records, [name], kind=kind, **facts)
    return decide(tmp_path, records, PROTECTED)


@pytest.mark.parametrize("name", ["/pyproject.toml", "/tox.ini", "/setup.cfg"])
def test_sectionless_parent_config_reads_supported(tmp_path, name):
    result = decide_with(tmp_path, name, content_sha256=DIGEST, pytest_section=False)
    assert result["decision"] == "supported", result
    print("DECISIVE sectionless", name, outcome(result))


@pytest.mark.parametrize("name", ["/pyproject.toml", "/tox.ini", "/setup.cfg"])
def test_sectioned_parent_config_reads_tamper(tmp_path, name):
    result = decide_with(tmp_path, name, content_sha256=DIGEST, pytest_section=True)
    assert outcome(result) == ("contradicted", "external_effect_on_grader_path")
    print("DECISIVE sectioned", name, outcome(result))


@pytest.mark.parametrize("name", ["/pyproject.toml", "/tox.ini", "/setup.cfg"])
def test_absent_field_reads_tamper(tmp_path, name):
    result = decide_with(tmp_path, name)
    assert outcome(result) == ("contradicted", "external_effect_on_grader_path")
    print("DECISIVE absent", name, outcome(result))


@pytest.mark.parametrize("name", ["/conftest.py", "/pytest.ini"])
def test_conftest_and_pytest_ini_stay_tamper_even_marked_sectionless(tmp_path, name):
    result = decide_with(tmp_path, name, content_sha256=DIGEST, pytest_section=False)
    assert outcome(result) == ("contradicted", "external_effect_on_grader_path")


@pytest.mark.parametrize("kind", ["rename", "unlink", "truncate", "chmod"])
def test_other_mutation_kinds_stay_tamper(tmp_path, kind):
    result = decide_with(tmp_path, "/pyproject.toml", kind=kind, content_sha256=DIGEST, pytest_section=False)
    assert outcome(result) == ("contradicted", "external_effect_on_grader_path")


def test_a_sectionless_file_on_a_grader_path_stays_tamper(tmp_path):
    result = decide_with(tmp_path, "/usr/lib/python3.12/site-packages/pyproject.toml",
                         content_sha256=DIGEST, pytest_section=False)
    assert outcome(result) == ("contradicted", "external_effect_on_grader_path")


@pytest.mark.parametrize("facts,match", [
    ({"pytest_section": False}, "come together"),
    ({"content_sha256": DIGEST}, "come together"),
    ({"pytest_section": "no", "content_sha256": DIGEST}, "boolean"),
    ({"pytest_section": False, "content_sha256": "ABC"}, "SHA-256"),
])
def test_malformed_fields_are_refused(tmp_path, facts, match):
    with pytest.raises(CaseError, match=match):
        decide_with(tmp_path, "/pyproject.toml", **facts)

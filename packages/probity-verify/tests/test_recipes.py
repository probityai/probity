"""Discovery must refuse a recipe that misstates the executable contract."""

import copy
import json
import re
import runpy
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
GENERATOR = runpy.run_path(str(ROOT / "scripts/build-recipes.py"))
BUILD = GENERATOR["build"]


@pytest.fixture
def recipes():
    return json.loads((ROOT / "docs/recipe-source.json").read_text())


def test_package_availability_and_fixture_scope_have_distinct_contracts(recipes):
    result = BUILD(ROOT, recipes)
    assert result["schema_version"] == "probity-recipes/v1"
    assert result["distribution"] == {
        "name": "probity-verify", "status": "published",
        "installation": "docs/install.md", "python": ">=3.11",
    }
    assert result["fixture_scope"] == "source-checkout"
    assert result["operator"] == "author-run synthetic fixtures"
    assert result["error_behavior"] == {"exit_code": 2, "verdict": False}
    assert all(recipe["exit_code"] == 0 for recipe in result["recipes"])


def test_changed_expected_decision_refuses(recipes):
    recipes["recipes"][0]["expected_decision"] = "supported"
    with pytest.raises(ValueError, match="recipe decision changed"):
        BUILD(ROOT, recipes)


def test_missing_registered_adapter_refuses(recipes):
    recipes["recipes"] = [r for r in recipes["recipes"]
                          if r["claim_type"] != "authority_anchor/v1"]
    with pytest.raises(ValueError, match="coverage does not match"):
        BUILD(ROOT, recipes)


def test_case_outside_checkout_refuses(recipes):
    recipes["recipes"][0]["case"] = "../outside.json"
    with pytest.raises(ValueError, match="escapes the repository"):
        BUILD(ROOT, recipes)


def test_policy_for_wrong_claim_refuses(recipes):
    recipes["recipes"][0]["claim_type"] = "authority_anchor/v1"
    with pytest.raises(ValueError, match="claim differs from consumer policy"):
        BUILD(ROOT, recipes)


def test_duplicate_case_policy_refuses(recipes):
    recipes["recipes"].append(copy.deepcopy(recipes["recipes"][0]))
    with pytest.raises(ValueError, match="duplicate case and policy"):
        BUILD(ROOT, recipes)


@pytest.fixture
def repository(tmp_path):
    for name in ["examples", "docs", "src"]:
        shutil.copytree(ROOT / name, tmp_path / name)
    shutil.copyfile(ROOT / "pyproject.toml", tmp_path / "pyproject.toml")
    return tmp_path


def test_published_name_does_not_assert_source_candidate_was_uploaded(repository, recipes):
    before = BUILD(repository, recipes)
    metadata = repository / "pyproject.toml"
    changed, count = re.subn(rb'(?m)^version = "[^"]+"$', b'version = "999.0.0"',
                             metadata.read_bytes())
    assert count == 1
    metadata.write_bytes(changed)
    after = BUILD(repository, recipes)
    assert before["package_metadata"] != after["package_metadata"]
    assert before["distribution"] == after["distribution"]
    assert before["recipes"] == after["recipes"]
    assert before["error_behavior"] == after["error_behavior"]


def test_missing_case_refuses(recipes):
    recipes["recipes"][0]["case"] = "examples/no-case.json"
    with pytest.raises(ValueError, match="recipe file is missing"):
        BUILD(ROOT, recipes)


def test_altered_pinned_artifact_refuses(repository, recipes):
    path = repository / "examples/source-coverage/source.html"
    path.write_bytes(path.read_bytes() + b"changed")
    with pytest.raises(ValueError):
        BUILD(repository, recipes)


def test_ambiguous_case_json_refuses(repository, recipes):
    path = repository / recipes["recipes"][0]["case"]
    path.write_text('{"case_id":"shadowed",' + path.read_text().lstrip()[1:])
    with pytest.raises(ValueError, match="duplicate JSON key"):
        BUILD(repository, recipes)


@pytest.mark.parametrize("output", ["recipes.json", "recipes.md"])
def test_stale_output_refuses_without_writing(repository, monkeypatch, output):
    main = GENERATOR["main"]
    monkeypatch.setitem(main.__globals__, "ROOT", repository)
    monkeypatch.setattr(sys, "argv", ["build-recipes.py"])
    assert main() == 0
    monkeypatch.setattr(sys, "argv", ["build-recipes.py", "--check"])
    assert main() == 0
    path = repository / "docs" / output
    path.write_bytes(b"stale output sentinel")
    with pytest.raises(SystemExit) as error:
        main()
    assert error.value.code == 1
    assert path.read_bytes() == b"stale output sentinel"


def test_invalid_recipe_cli_exits_two(repository, monkeypatch, recipes):
    recipes["recipes"][0]["case"] = "examples/no-case.json"
    (repository / "docs/recipe-source.json").write_text(json.dumps(recipes))
    main = GENERATOR["main"]
    monkeypatch.setitem(main.__globals__, "ROOT", repository)
    monkeypatch.setattr(sys, "argv", ["build-recipes.py", "--check"])
    with pytest.raises(SystemExit) as error:
        main()
    assert error.value.code == 2

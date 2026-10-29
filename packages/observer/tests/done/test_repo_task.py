"""A repository task from a proposal file: parsed, checked, sealed, compiled."""

import argparse
import json
import shutil

import pytest

from probity_observer.done import cli, contract, pytest_plugins, repo_task
from probity_observer.done.formats import DoneError, sha256
from probity_observer.done.runner import SubprocessRunner


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repo"
    (root / "tests").mkdir(parents=True)
    (root / "app.py").write_text("def double(x):\n    return x\n")
    (root / "tests" / "test_app.py").write_text(
        "import os, sys\nsys.path.insert(0, os.getcwd())\nfrom app import double\n\n\n"
        "def test_double():\n    assert double(2) == 4\n    assert double(0) == 0\n")
    return root


PROPOSAL = json.dumps({"acceptance": [{"id": "unit", "argv": ["python", "-m", "pytest", "-q",
                                                               "-p", "no:cacheprovider",
                                                               "tests/test_app.py"],
                                       "expect_on_start": "fail"}],
                       "protected_paths": [{"path": "tests", "kind": "directory"}],
                       "rationale": "the test file checks doubling"})


def test_a_proposal_file_seals_after_stability(tmp_path, repo, harness, python_bin):
    path = tmp_path / "proposal.json"
    path.write_text("Here it is:\n" + PROPOSAL)
    task = repo_task.from_file(repo, "repo-double", "make double double", path, None,
                               tmp_path / "w")
    assert task.notes["proposal"]["source"] == "file"
    assert task.notes["proposal"]["proposal_sha256"] == sha256(path.read_bytes())
    sealed = contract.compile_task(task, tmp_path / "out", harness, SubprocessRunner(python_bin),
                                   timeout=60)
    compiled = json.loads((sealed.out / "sealed" / "compile.json").read_bytes())
    assert compiled["notes"]["proposal"]["rationale"] == "the test file checks doubling"
    assert compiled["strength"] == "reference_free"
    assert sealed.record["protected_paths"][0]["exclude"] == list(contract.EXCLUDE)


def test_a_recorded_call_is_read_for_its_answer(tmp_path):
    call = tmp_path / "call.json"
    call.write_text(json.dumps({"request": {"model": "m"}, "response": json.dumps(
        {"choices": [{"message": {"content": PROPOSAL}}]})}))
    text, digest = repo_task.read_proposal(call)
    assert text == PROPOSAL and digest == sha256(call.read_bytes())
    bare = tmp_path / "bare.txt"
    bare.write_text(PROPOSAL)
    assert repo_task.read_proposal(bare)[0] == PROPOSAL


@pytest.mark.parametrize("response", [{"choices": []}, {"choices": [{"message": {"content": None}}]}])
def test_a_recorded_call_without_an_answer_is_refused(tmp_path, response):
    call = tmp_path / "call.json"
    call.write_text(json.dumps({"response": response}))
    with pytest.raises(DoneError, match="recorded call"):
        repo_task.read_proposal(call)


@pytest.mark.parametrize("text", [
    json.dumps({"acceptance": [{"id": "a", "argv": ["sh", "-c", "test -f DONE"],
                                "expect_on_start": "fail"}],
                "protected_paths": [], "rationale": ""}),
    "no json here",
    "{not json}",
    json.dumps({"acceptance": []}),
    json.dumps({"acceptance": [], "protected_paths": [], "rationale": ""}),
    json.dumps({"acceptance": [{"id": "a", "argv": [], "expect_on_start": "fail"}],
                "protected_paths": [], "rationale": ""}),
    json.dumps({"acceptance": [{"id": "a", "argv": ["x"]}], "protected_paths": [], "rationale": ""}),
    json.dumps({"acceptance": [{"id": "a", "argv": ["x"], "expect_on_start": "fail"}],
                "protected_paths": [{"path": "missing.py", "kind": "file"}], "rationale": ""}),
    json.dumps({"acceptance": [{"id": "a", "argv": ["x"], "expect_on_start": "fail"}],
                "protected_paths": [{"path": "../etc", "kind": "directory"}], "rationale": ""}),
    json.dumps({"acceptance": [{"id": "a", "argv": ["x"], "expect_on_start": "fail"}],
                "protected_paths": "tests", "rationale": ""}),
    json.dumps({"acceptance": [{"id": "a", "argv": ["x"], "expect_on_start": "fail"}],
                "protected_paths": [{"path": "tests"}], "rationale": ""}),
    json.dumps({"acceptance": [{"id": "a", "argv": ["python", "-m", "unittest", "nowhere.Case"],
                                "expect_on_start": "fail"}], "protected_paths": [], "rationale": ""}),
])
def test_malformed_proposals_are_refused(tmp_path, repo, text):
    with pytest.raises(DoneError, match="acceptance|protected|JSON|test runner|malformed|sealed"):
        repo_task.task_from_proposal(repo, "t", "task", text, None, tmp_path / "w")


def test_proposed_commands_are_sealed_with_repeats_isolation_and_ids(tmp_path, repo):
    reference = tmp_path / "reference"
    shutil.copytree(repo, reference)
    (reference / "app.py").write_text("def double(x):\n    return x * 2\n")
    text = json.dumps({"acceptance": [
        {"id": "unit", "argv": ["pytest", "-q", "tests/test_app.py::test_double"],
         "expect_on_start": "fail"},
        {"id": "named", "argv": ["python", "-m", "unittest", "tests.test_app.test_double"],
         "expect_on_start": "fail"},
        {"id": "keyword", "argv": ["python", "-m", "pytest", "-k", "double"], "expect_on_start": "fail"},
        {"id": "lost", "argv": ["python", "-m", "unittest", "nowhere.Case"], "expect_on_start": "fail"}],
        "protected_paths": [], "rationale": "r"})
    task, record = repo_task.task_from_proposal(repo, "t", "make double double", text, reference,
                                                tmp_path / "w")
    commands = {command.id: command for command in task.commands}
    assert set(commands) == {"unit", "named", "keyword"}
    assert record["dropped"] == [{"id": "lost", "argv": ["python", "-m", "unittest", "nowhere.Case"],
                                  "reason": "unittest_unresolved"}]
    assert {name: change.ranges for name, change in task.mutation_targets.items()} == {
        "app.py": ((2, 2),)}
    for command in commands.values():
        argv = command.argv
        assert pytest_plugins.is_sealed_pytest(argv)
        assert argv[argv.index("--probity-repeats") + 1] == "2"
        assert argv[argv.index("--probity-isolate") + 1] == "app.py::double"
    assert commands["unit"].record()["ids"] == ["tests/test_app.py::test_double"]
    assert commands["named"].record()["ids"] == ["tests/test_app.py::test_double"]
    assert "ids" not in commands["keyword"].record() and commands["keyword"].argv[-2:] == ("-k", "double")
    assert (tmp_path / "w/heldout/config/probity-plugins/probity_repeat.py").is_file()
    assert repo_task.unittest_node(repo, "tests.test_app") == "tests/test_app.py"


def _args(tmp_path, repo, **extra):
    values = {name: None for name in cli.PROVIDER_OPTIONS}
    values.update(dataset="repo", repo=str(repo), work=str(tmp_path / "w"), reference=None,
                  task_id="t", task="make double double", proposal=None, runner="subprocess",
                  python=None)
    values.update(extra)
    return argparse.Namespace(**values)


def test_the_command_line_takes_a_proposal_file(tmp_path, repo):
    path = tmp_path / "proposal.json"
    path.write_text(PROPOSAL)
    task, strengthener = cli._task(_args(tmp_path, repo, proposal=str(path)))
    assert strengthener is None and [command.id for command in task.commands] == ["unit"]


def test_without_a_proposal_or_a_provider_a_repo_task_is_refused(tmp_path, repo, monkeypatch):
    monkeypatch.setattr(cli.providers, "contract_provider", lambda: None)
    with pytest.raises(DoneError, match="--proposal"):
        cli._task(_args(tmp_path, repo))
    with pytest.raises(DoneError, match="--work"):
        cli._task(_args(tmp_path, repo, work=None))


def test_an_installed_provider_gets_the_model_options(tmp_path, repo, monkeypatch):
    seen = {}

    class Provider:
        def provide(self, repo, task_id, description, *, reference, work, runner, options):
            seen.update(options=options, reference=reference)
            return "task", "strengthener"

    monkeypatch.setattr(cli.providers, "contract_provider", Provider)
    assert cli._task(_args(tmp_path, repo, model="m", model_url="http://h")) == ("task", "strengthener")
    assert seen["options"]["model"] == "m" and seen["reference"] is None

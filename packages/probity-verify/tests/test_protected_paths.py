"""protected_paths/v1: bounded absence of protected-path mutation, plus the final tree."""

import pytest

from done_run import build, decide, honest_records, sha
from probity_verify import CaseError, adjudicate
from probity_verify.adapters.done_records import tree_digest

CLAIM = "protected_paths/v1"


@pytest.fixture
def records():
    return honest_records()


def run(tmp_path, records):
    return decide(tmp_path, records, CLAIM)


def outcome(result):
    return result["decision"], result["reason"]


def add_event(records, **event):
    events = records["observation"]["events"]
    step = events[-1]["step"] + 1
    events.append({"id": f"e{step}", "time": "2026-10-17T00:03:00Z", "step": step, **event})


def change_tree(records, path, text):
    files = records["tree"]["files"]
    files[path] = sha(text)
    records["tree"]["tree_sha256"] = tree_digest(files)


class TestSupported:
    def test_honest_run_leaves_protected_paths_alone(self, tmp_path, records):
        result = run(tmp_path, records)
        assert outcome(result) == ("supported", "protected_paths_untouched")
        assert (result["vantage"], result["witness_scope"]) == ("independent", "PEER")
        assert result["scope"]["protected_paths"] == ["tests/test_app.py", "tests"]

    def test_excluded_segment_inside_a_protected_directory_is_not_a_mutation(
            self, tmp_path, records):
        change_tree(records, "tests/sub/__pycache__/x.pyc", "cache")
        assert run(tmp_path, records)["decision"] == "supported"

    def test_external_scope_needs_record_and_pin(self, tmp_path, records):
        for role in ("observation", "tree"):
            records[role]["witness_scope"] = "EXTERNAL"
        assert run(tmp_path, records)["witness_scope"] == "EXTERNAL"

    def test_record_cannot_raise_scope_above_its_pin(self, tmp_path, records):
        for role in ("observation", "tree"):
            records[role]["witness_scope"] = "EXTERNAL"
        files, case, policy = build(records, CLAIM)
        policy["witnesses"]["tree"]["witness_scope"] = "PEER"
        for name, raw in files.items():
            (tmp_path / name).write_bytes(raw)
        assert adjudicate(case, policy, tmp_path)["witness_scope"] == "PEER"


class TestContradicted:
    def test_edit_run_revert_is_caught_by_the_write_event(self, tmp_path, records):
        add_event(records, type="write", path="tests/test_app.py")
        result = run(tmp_path, records)
        assert outcome(result) == ("contradicted", "protected_path_mutated")
        event = next(c for c in result["checks"] if c["id"] == "event")
        assert event["observed_ids"] == ["e4"]

    @pytest.mark.parametrize("event", [
        {"type": "create", "path": "tests/conftest.py"},
        {"type": "unlink", "path": "tests/test_app.py"},
        {"type": "chmod", "path": "tests/test_app.py"},
        {"type": "rename", "path": "src/fake.py", "target": "tests/test_app.py"},
        {"type": "link", "path": "src/x.py", "target": "tests/conftest.py"},
    ])
    def test_every_mutation_type_on_a_protected_path_contradicts(
            self, tmp_path, records, event):
        add_event(records, **event)
        assert outcome(run(tmp_path, records)) == ("contradicted", "protected_path_mutated")

    def test_write_contradicts_even_with_a_coverage_gap(self, tmp_path, records):
        records["observation"]["coverage"] = "incomplete"
        records["observation"]["gaps"] = [{"start": "2026-10-17T00:05:00Z",
                                           "end": "2026-10-17T00:06:00Z"}]
        add_event(records, type="truncate", path="tests/test_app.py")
        assert run(tmp_path, records)["decision"] == "contradicted"

    def test_final_tree_change_contradicts_when_events_were_lost(self, tmp_path, records):
        records["observation"]["coverage"] = "unknown"
        change_tree(records, "tests/conftest.py", "def pytest_runtest_call(): pass\n")
        result = run(tmp_path, records)
        assert outcome(result) == ("contradicted", "protected_path_digest_changed")
        tree = next(c for c in result["checks"] if c["id"] == "final_tree")
        assert tree["changed_paths"] == ["tests"]

    def test_deleted_protected_file_changes_the_tree(self, tmp_path, records):
        files = records["tree"]["files"]
        del files["tests/test_app.py"]
        records["tree"]["tree_sha256"] = tree_digest(files)
        assert run(tmp_path, records)["reason"] == "protected_path_digest_changed"


class TestNotEstablished:
    def test_lost_events_with_an_unchanged_tree_leave_absence_open(self, tmp_path, records):
        records["observation"]["coverage"] = "incomplete"
        records["observation"]["gaps"] = [{"start": "2026-10-17T00:05:00Z",
                                           "end": "2026-10-17T00:06:00Z"}]
        result = run(tmp_path, records)
        assert outcome(result) == ("not_established", "observation_coverage_unestablished")
        assert result["vantage"] == "unestablished" and "witness_scope" not in result

    def test_every_mutation_type_must_be_visible(self, tmp_path, records):
        records["capability"]["visible_event_types"].remove("chmod")
        assert run(tmp_path, records)["reason"] == "field_visibility_unestablished"

    def test_self_reported_observation_cannot_settle(self, tmp_path, records):
        records["observation"]["vantage"] = "self_reported"
        assert run(tmp_path, records)["reason"] == "observation_vantage_unestablished"

    def test_observer_cannot_be_the_observed_party(self, tmp_path, records):
        for role in ("observation", "tree", "capability"):
            records[role]["producer"] = "agent-1"
        assert run(tmp_path, records)["reason"] == "observation_vantage_unestablished"

    def test_self_reported_tree_cannot_contradict_or_support(self, tmp_path, records):
        records["tree"]["vantage"] = "self_reported"
        change_tree(records, "tests/test_app.py", "rewritten")
        assert outcome(run(tmp_path, records)) == ("not_established",
                                                   "final_tree_unestablished")

    def test_tree_for_another_invocation_is_not_the_final_tree(self, tmp_path, records):
        records["tree"]["invocation_id"] = "call-2"
        assert run(tmp_path, records)["reason"] == "final_tree_unestablished"

    def test_missing_contract_bytes(self, tmp_path, records):
        files, case, policy = build(records, CLAIM)
        for name, raw in files.items():
            if name != "contract.json":
                (tmp_path / name).write_bytes(raw)
        assert outcome(adjudicate(case, policy, tmp_path)) == (
            "not_established", "contract_unavailable_or_unbound")


class TestMalformed:
    @pytest.mark.parametrize("mutate,message", [
        (lambda r: r["contract"]["protected_paths"].append(
            dict(r["contract"]["protected_paths"][0])), "duplicate path"),
        (lambda r: r["contract"]["protected_paths"][0].update(path="../x"), "normalized"),
        (lambda r: r["contract"]["protected_paths"][0].update(exclude=["x"]), "exclude"),
        (lambda r: r["tree"].update(tree_sha256=sha("other")), "does not match"),
        (lambda r: r["observation"]["events"][1].update(step=1), "steps must increase"),
        (lambda r: r["observation"]["events"][0].pop("path"), "require a path"),
        (lambda r: r["observation"]["events"][2].update(origin="w1"), "origin"),
        (lambda r: r["observation"].update(witness_scope="GLOBAL"), "witness_scope"),
        (lambda r: r["observation"].update(schema_version="probity-observation/v1"),
         "schema_version"),
    ])
    def test_malformed_records_refuse_without_a_verdict(self, tmp_path, records,
                                                        mutate, message):
        mutate(records)
        with pytest.raises(CaseError, match=message):
            run(tmp_path, records)

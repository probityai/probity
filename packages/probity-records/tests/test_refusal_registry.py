"""The refusal-code registry and the lint that holds every check to it."""

from __future__ import annotations

import copy
import json
from importlib import resources

import pytest
from probity_records import refusal_codes, refusal_lint
from probity_records.refusal_lint import Config, lint_source

REGISTRY = json.loads(resources.files("probity_records").joinpath("refusal_codes.json").read_text(encoding="utf-8"))
CFG = Config(carriers=frozenset({"Hop"}), refusal_calls=frozenset({"_refuse"}), raisers=frozenset({"Refused"}),
             exempt_functions=frozenset({"grade"}), located_lists=frozenset({"problems"}),
             assigned=frozenset({"result"}))
KNOWN = frozenset({"grant_revoked", "permit_missing", "edge_absent"})


def findings(source: str, config: Config = CFG) -> list[str]:
    return [f.problem for f in lint_source("m.py", source, KNOWN, config)]


def test_every_check_of_this_package_reports_only_registered_codes() -> None:
    assert refusal_lint.lint_package() == []


def test_the_registry_is_sorted_unique_snake_and_every_identifier_is_derived() -> None:
    codes = refusal_codes.CODES
    assert len(codes) == len(REGISTRY["codes"]) > 300
    for entry in REGISTRY["codes"]:
        assert entry["uri"] == refusal_codes.REGISTRY + "/" + entry["code"] == codes[entry["code"]].uri


@pytest.mark.parametrize(("edit", "why"), [
    (lambda d: d["codes"].reverse(), "out of order"),
    (lambda d: d["codes"].insert(1, copy.deepcopy(d["codes"][0])), "out of order or repeated"),
    (lambda d: d["codes"][0].update(code="grant-revoked"), "snake-case"),
    (lambda d: d["codes"][0].update(uri="https://example.com/x"), "identifier"),
    (lambda d: d["codes"][0].update(extra="x"), "exactly the string members"),
    (lambda d: d["codes"][0].update(meaning=""), "meaning"),
    (lambda d: d["codes"][0].update(meaning="café"), "meaning"),
    (lambda d: d["codes"][0].update(check="Grants"), "dotted"),
    (lambda d: d.update(registry="https://example.com/r"), "this registry"),
    (lambda d: d.update(version=2), "this registry"),
    (lambda d: d.update(codes=[]), "non-empty"),
])
def test_a_registry_that_is_not_exactly_the_format_is_refused(edit, why: str) -> None:  # type: ignore[no-untyped-def]
    data = copy.deepcopy(REGISTRY)
    edit(data)
    with pytest.raises(refusal_codes.RegistryError, match=why):
        refusal_codes.parse(data)


def test_a_refusal_string_names_its_code_before_the_detail() -> None:
    assert refusal_codes.code_of("grant_revoked:2") == "grant_revoked"
    assert refusal_codes.is_registered("delegation_holder_unregistered:3")
    assert not refusal_codes.is_registered("delegation-holder-unregistered")
    with pytest.raises(KeyError, match="unregistered refusal code 'no_such_code'"):
        refusal_codes.lookup("no_such_code:x")


# ---- the lint: one passing and one refused case per position, so dropping any rule turns a test red ----------------

@pytest.mark.parametrize(("source", "refused"), [
    ('def f():\n    return "grant_revoked"\n', []),
    ('def f():\n    return "grant-revoked"\n', ["refusal code not in snake form"]),
    ('def f():\n    return None, "no_such_code"\n', ["refusal code not registered"]),
    ('def f():\n    return Hop(False, "permit_missing")\n', []),
    ('def f():\n    return Hop(False, "replayed")\n', ["refusal code not in snake form"]),
    ('def f():\n    raise Refused("grant_revoked", "any prose detail")\n', []),
    ('def f():\n    raise Refused("stale-epoch: prose")\n', ["refusal code not in snake form"]),
    ('def f(x):\n    _refuse(x, "no_such_code")\n', ["refusal code not registered"]),
    ('def f(j):\n    j.append("refusal", reason="no-edge")\n', ["refusal code not in snake form"]),
    ('def f(reason):\n    return reason == "permit-missing"\n', ["refusal code not in snake form"]),
    ('def f(reason):\n    return reason in {"edge_absent", "no_such_code"}\n', ["refusal code not registered"]),
    ('NO_EDGE = "no-edge"\ndef f():\n    return NO_EDGE\n', ["refusal code not in snake form"]),
    ('FORGED = frozenset({"bad-signature"})\ndef f(reason):\n    return reason in FORGED\n',
     ["refusal code not in snake form"]),
    ('UNUSED = "not-a-refusal"\n', []),
    ('def f(r):\n    return f"delegation-{r}"\n', ["refusal code composed at run time"]),
    ('def f(r):\n    return "delegation-" + r\n', ["refusal code composed at run time"]),
    ('def f(d):\n    return None, f"grant_revoked:{d}"\n', []),
    ('def f(d):\n    return None, f"no_such_code:{d}"\n', ["refusal code not registered"]),
    ('def f(problems, w):\n    problems.append(f"{w}:grant_revoked:{1}")\n', []),
    ('def f(problems, w, n):\n    problems.append(f"{w}:binding_{n}:permit_missing")\n', []),
    ('def f(problems, w, p):\n    problems.append(f"{w}:{p}")\n', []),
    ('def f(problems, o):\n    problems.append(f"exception_{o}")\n', ["refusal code composed at run time"]),
    ('def f(problems, w, r):\n    problems.append(f"{w}:{r}_allow_without_evidence")\n',
     ["refusal code composed at run time"]),
    ('def f(problems):\n    problems.append("no-such")\n', ["refusal code not in snake form"]),
    ('def grade(b):\n    return "act-chain"\n', []),
    ('def f():\n    result = "grant-invalid"\n', ["refusal code not in snake form"]),
    ('def f():\n    return "ok"\n', []),
    ('def f():\n    return {"decision": "deny", "reason": "grant-revoked"}\n', ["refusal code not in snake form"]),
    ('def f():\n    return "sha256:" + "0" * 64\n', []),
    ('def f(x):\n    return x.decode("utf-8")\n', []),
])
def test_the_lint_reads_every_refusal_position(source: str, refused: list[str]) -> None:
    assert findings(source) == refused


def test_a_name_configured_for_one_file_applies_to_that_file_only() -> None:
    config = Config(raisers=frozenset({"m.py::ValueError"}))
    assert [f.problem for f in lint_source("m.py", 'raise ValueError("grant-x")\n', KNOWN, config)] == [
        "refusal code not in snake form"]
    assert lint_source("other.py", 'raise ValueError("grant-x")\n', KNOWN, config) == []


def test_unknown_lint_settings_are_refused() -> None:
    with pytest.raises(ValueError, match="unknown lint settings"):
        Config.load({"carrier": ["Hop"]})


def test_registry_files_are_read_for_their_codes_alone(tmp_path) -> None:  # type: ignore[no-untyped-def]
    extra = tmp_path / "extra.json"
    extra.write_text(json.dumps({"codes": [{"code": "private_code"}]}), encoding="utf-8")
    assert refusal_lint.registered(extra) == {"private_code"}
    extra.write_text(json.dumps({"codes": [{"code": "private-code"}]}), encoding="utf-8")
    with pytest.raises(ValueError, match="not a snake-case code"):
        refusal_lint.registered(extra)


def test_the_cli_exits_one_on_a_finding(tmp_path) -> None:  # type: ignore[no-untyped-def]
    source = tmp_path / "m.py"
    source.write_text('def f():\n    return "no-edge"\n', encoding="utf-8")
    config = tmp_path / "lint.json"
    config.write_text("{}", encoding="utf-8")
    assert refusal_lint.main(["--config", str(config), str(source)]) == 1
    source.write_text('def f():\n    return "edge_absent"\n', encoding="utf-8")
    assert refusal_lint.main(["--config", str(config), str(source)]) == 0

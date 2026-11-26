"""The refusal-code registry and the lint that holds every check to it."""

from __future__ import annotations

import copy
import json
from importlib import resources
from pathlib import Path

import pytest
from probity_records import refusal_codes, refusal_lint
from probity_records.refusal_lint import Config, lint_source

REGISTRY = json.loads(
    resources.files("probity_records")
    .joinpath("refusal_codes.json")
    .read_text(encoding="utf-8")
)
CFG = Config(
    carriers=frozenset({"Hop"}),
    refusal_calls=frozenset({"_refuse"}),
    raisers=frozenset({"Refused"}),
    exempt_functions=frozenset({"grade"}),
    located_lists=frozenset({"problems"}),
    assigned=frozenset({"result"}),
)
KNOWN = frozenset({"grant_revoked", "permit_missing", "edge_absent"})


def findings(source: str, config: Config = CFG) -> list[str]:
    return [f.problem for f in lint_source("m.py", source, KNOWN, config)]


def test_every_check_of_this_package_reports_only_registered_codes() -> None:
    assert refusal_lint.lint_package() == []


def _failures(node: object) -> list[str]:
    if isinstance(node, dict):
        return [
            s
            for k, v in node.items()
            for s in (
                [x for x in v if isinstance(x, str)]
                if k == "failures" and isinstance(v, list)
                else _failures(v)
            )
        ]
    return [s for x in node for s in _failures(x)] if isinstance(node, list) else []


def test_every_verdict_in_the_shared_vectors_names_a_registered_code() -> None:
    """Both verifiers report these strings byte for byte, so this holds the TypeScript twin to the registry too."""
    vectors = Path(__file__).resolve().parents[1] / "vectors" / "shared"
    unregistered = set()
    for path in sorted(vectors.glob("*.json")):
        for failure in _failures(json.loads(path.read_text(encoding="utf-8"))):
            if not refusal_codes.is_registered(failure):
                unregistered.add((path.name, failure))
    assert not unregistered


def test_every_module_is_linted_or_excluded_with_a_reason() -> None:
    """A new check under a new module name cannot escape the lint: every module is in one of the two lists."""
    modules = {p.stem for p in Path(refusal_lint.__file__).parent.glob("*.py")}
    linted, excluded = set(refusal_lint.PACKAGE_MODULES), set(refusal_lint.NOT_LINTED)
    assert not linted & excluded
    assert modules == linted | excluded
    assert all(reason.strip() for reason in refusal_lint.NOT_LINTED.values())


def test_the_registry_is_sorted_unique_snake_and_every_identifier_is_derived() -> None:
    codes = refusal_codes.CODES
    assert len(codes) == len(REGISTRY["codes"]) > 300
    for entry in REGISTRY["codes"]:
        assert (
            entry["uri"]
            == refusal_codes.REGISTRY + "/" + entry["code"]
            == codes[entry["code"]].uri
        )


@pytest.mark.parametrize(
    ("edit", "why"),
    [
        (lambda d: d["codes"].reverse(), "out of order"),
        (
            lambda d: d["codes"].insert(1, copy.deepcopy(d["codes"][0])),
            "out of order or repeated",
        ),
        (lambda d: d["codes"][0].update(code="grant-revoked"), "snake-case"),
        (lambda d: d["codes"][0].update(uri="https://example.com/x"), "identifier"),
        (lambda d: d["codes"][0].update(extra="x"), "exactly the string members"),
        (lambda d: d["codes"][0].update(meaning=""), "meaning"),
        (lambda d: d["codes"][0].update(meaning="café"), "meaning"),
        (lambda d: d["codes"][0].update(check="Grants"), "dotted"),
        (lambda d: d.update(registry="https://example.com/r"), "this registry"),
        (lambda d: d.update(version=2), "this registry"),
        (lambda d: d.update(codes=[]), "non-empty"),
        (
            lambda d: d["codes"][0].update(
                code="line_1", uri=refusal_codes.REGISTRY + "/line_1"
            ),
            "form of a location",
        ),
        (
            lambda d: d["codes"][0].update(
                code="principal_agent", uri=refusal_codes.REGISTRY + "/principal_agent"
            ),
            "form of a location",
        ),
    ],
)
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


def test_a_located_refusal_names_the_code_after_its_locations() -> None:
    """The verifiers' own output, ``line_3:principal_agent:principal_expired``, reads as its code."""
    assert (
        refusal_codes.code_of("line_3:principal_agent:principal_expired")
        == "principal_expired"
    )
    assert refusal_codes.code_of(
        "keys_line_2:session_key_delegation_invalid:delegation_unverified"
    ) == ("session_key_delegation_invalid")
    assert (
        refusal_codes.code_of("binding_0:approval_signature_unverified")
        == "approval_signature_unverified"
    )
    assert refusal_codes.lookup("line_7:grant_revoked:1").code == "grant_revoked"
    assert not refusal_codes.is_registered("line_7")
    assert (
        refusal_codes.code_of("principal_sponsor_not_registered")
        == "principal_sponsor_not_registered"
    )


# ---- the lint: one passing and one refused case per position, so dropping any rule turns a test red ----------------


@pytest.mark.parametrize(
    ("source", "refused"),
    [
        ('def f():\n    return "grant_revoked"\n', []),
        ('def f():\n    return "grant-revoked"\n', ["refusal code not in snake form"]),
        (
            'def f():\n    return None, "no_such_code"\n',
            ["refusal code not registered"],
        ),
        ('def f():\n    return Hop(False, "permit_missing")\n', []),
        (
            'def f():\n    return Hop(False, "replayed")\n',
            ["refusal code not in snake form"],
        ),
        ('def f():\n    raise Refused("grant_revoked", "any prose detail")\n', []),
        (
            'def f():\n    raise Refused("stale-epoch: prose")\n',
            ["refusal code not in snake form"],
        ),
        (
            'def f(x):\n    _refuse(x, "no_such_code")\n',
            ["refusal code not registered"],
        ),
        (
            'def f(j):\n    j.append("refusal", reason="no-edge")\n',
            ["refusal code not in snake form"],
        ),
        (
            'def f(reason):\n    return reason == "permit-missing"\n',
            ["refusal code not in snake form"],
        ),
        (
            'def f(reason):\n    return reason in {"edge_absent", "no_such_code"}\n',
            ["refusal code not registered"],
        ),
        (
            'NO_EDGE = "no-edge"\ndef f():\n    return NO_EDGE\n',
            ["refusal code not in snake form"],
        ),
        (
            'FORGED = frozenset({"bad-signature"})\ndef f(reason):\n    return reason in FORGED\n',
            ["refusal code not in snake form"],
        ),
        ('UNUSED = "not-a-refusal"\n', []),
        ('MARK = "aid1!"\ndef f(k):\n    return MARK + k\n', []),
        (
            'MARK = "id-v1"\ndef f(k):\n    return MARK + k\n',
            ["refusal code not in snake form"],
        ),
        (
            'def f(r):\n    return f"delegation-{r}"\n',
            ["refusal code composed at run time"],
        ),
        (
            'def f(r):\n    return "delegation-" + r\n',
            ["refusal code composed at run time"],
        ),
        ('def f(d):\n    return None, f"grant_revoked:{d}"\n', []),
        (
            'def f(d):\n    return None, f"no_such_code:{d}"\n',
            ["refusal code not registered"],
        ),
        ('def f(problems, w):\n    problems.append(f"{w}:grant_revoked:{1}")\n', []),
        (
            'def f(problems, w, n):\n    problems.append(f"{w}:binding_{n}:permit_missing")\n',
            [],
        ),
        ('def f(problems, w, p):\n    problems.append(f"{w}:{p}")\n', []),
        (
            'def f(problems, o):\n    problems.append(f"exception_{o}")\n',
            ["refusal code composed at run time"],
        ),
        (
            'def f(problems, w, r):\n    problems.append(f"{w}:{r}_allow_without_evidence")\n',
            ["refusal code composed at run time"],
        ),
        (
            'def f(problems):\n    problems.append("no-such")\n',
            ["refusal code not in snake form"],
        ),
        ('def grade(b):\n    return "act-chain"\n', []),
        (
            'def f():\n    result = "grant-invalid"\n',
            ["refusal code not in snake form"],
        ),
        ('def f():\n    return "ok"\n', []),
        (
            'def f():\n    return {"decision": "deny", "reason": "grant-revoked"}\n',
            ["refusal code not in snake form"],
        ),
        ('def f():\n    return "sha256:" + "0" * 64\n', []),
        ('def f(x):\n    return x.decode("utf-8")\n', []),
        ('def f(r, e):\n    raise Refused(f"{r}: {e} under change")\n', []),
        (
            'def f(r, e):\n    raise Refused(f"{r}_x: {e}")\n',
            ["refusal code composed at run time"],
        ),
        (
            'A = ("permit-missing",)\nB = ("edge_absent",)\ndef f(reason):\n    return reason in A + B\n',
            ["refusal code not in snake form"],
        ),
        (
            'def f(problems, i):\n    problems.append(f"entry {i}: grant-x")\n',
            ["refusal code not in snake form"],
        ),
        ('def f(problems, i, e):\n    problems.append(f"entry {i}: {e}")\n', []),
        # a local the function returns is judged where it is bound
        (
            'def f():\n    r = "grant-revoked"\n    return r\n',
            ["refusal code not in snake form"],
        ),
        (
            'def f():\n    r = "grant-revoked"\n    return None, r\n',
            ["refusal code not in snake form"],
        ),
        ('def f():\n    r = "not-returned"\n    return 1\n', []),
        (
            'def f(b):\n    problems = [f"need_{n}" for n in b]\n    return problems\n',
            ["refusal code composed at run time"],
        ),
        ("def f(b):\n    problems = [c for c in b]\n    return problems\n", []),
        (
            'def f(x):\n    return x or "grant-revoked"\n',
            ["refusal code not in snake form"],
        ),
        (
            'def f(x):\n    return [c for c in x] or ["grant-revoked"]\n',
            ["refusal code not in snake form"],
        ),
        (
            'def f(x):\n    return [f"need_{n}" for n in x]\n',
            ["refusal code composed at run time"],
        ),
        ('def f():\n    return (r := "grant-x")\n', ["refusal code not in snake form"]),
        (
            'def f():\n    return (False, *("grant-x",))\n',
            ["refusal code not in snake form"],
        ),
        (
            'def f(x):\n    return "grant-%s" % x\n',
            ["refusal code composed at run time"],
        ),
        ('def f(x):\n    return "%d items" % x\n', []),
        (
            'def f(x):\n    return "grant_{}".format(x)\n',
            ["refusal code composed at run time"],
        ),
        (
            'def f(x):\n    return "_".join(["grant", x])\n',
            ["refusal code composed at run time"],
        ),
        ('def f(x):\n    return "".join(x)\n', []),
        (
            'def f(x):\n    raise Refused("%s" % x)\n',
            ["refusal code composed at run time"],
        ),
        ('def f():\n    yield "grant-revoked"\n', ["refusal code not in snake form"]),
        ('f = lambda: "grant-revoked"\n', ["refusal code not in snake form"]),
        # every way a problem joins a located list
        (
            'def f(problems):\n    problems.extend(["grant-x"])\n',
            ["refusal code not in snake form"],
        ),
        ('def f(problems):\n    problems.extend(["grant_revoked"])\n', []),
        (
            'def f(problems, c):\n    problems.append("grant-x" if c else "grant_revoked")\n',
            ["refusal code not in snake form"],
        ),
        ('def f():\n    problems = ["grant-x"]\n', ["refusal code not in snake form"]),
        (
            'def f(problems):\n    problems += ["no_such_code"]\n',
            ["refusal code not registered"],
        ),
        # a literal location is not a code; the code after it is judged
        (
            'def f(problems, why):\n    problems.append(f"principal_sponsor:{why}")\n',
            [],
        ),
        ('def f(problems):\n    problems.append("line_3:grant_revoked")\n', []),
        (
            'def f(problems):\n    problems.append("line_3:no_such_code")\n',
            ["refusal code not registered"],
        ),
    ],
)
def test_the_lint_reads_every_refusal_position(source: str, refused: list[str]) -> None:
    assert findings(source) == refused


def test_a_name_configured_for_one_file_applies_to_that_file_only() -> None:
    config = Config(raisers=frozenset({"m.py::ValueError"}))
    assert [
        f.problem
        for f in lint_source("m.py", 'raise ValueError("grant-x")\n', KNOWN, config)
    ] == ["refusal code not in snake form"]
    assert lint_source("other.py", 'raise ValueError("grant-x")\n', KNOWN, config) == []


def test_a_call_names_the_positions_that_hold_codes_and_an_exempt_call_holds_none() -> (
    None
):
    config = Config(
        refusal_calls=frozenset({"_refuse@1"}), exempt_calls=frozenset({"set_policy"})
    )
    assert lint_source("m.py", '_refuse("mint", "edge_absent")\n', KNOWN, config) == []
    assert [
        f.problem
        for f in lint_source("m.py", '_refuse("mint", "no-edge")\n', KNOWN, config)
    ] == ["refusal code not in snake form"]
    assert (
        lint_source("m.py", 'set_policy([], reason="initial-policy")\n', KNOWN, config)
        == []
    )
    assert [
        f.problem
        for f in lint_source(
            "m.py", 'other([], reason="initial-policy")\n', KNOWN, config
        )
    ] == ["refusal code not in snake form"]


def test_unknown_lint_settings_are_refused() -> None:
    with pytest.raises(ValueError, match="unknown lint settings"):
        Config.load({"carrier": ["Hop"]})


def test_registry_files_are_read_for_their_codes_alone(tmp_path) -> None:  # type: ignore[no-untyped-def]
    extra = tmp_path / "extra.json"
    extra.write_text(
        json.dumps({"codes": [{"code": "private_code"}]}), encoding="utf-8"
    )
    assert refusal_lint.registered(extra) == {"private_code"}
    extra.write_text(
        json.dumps({"codes": [{"code": "private-code"}]}), encoding="utf-8"
    )
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


def test_the_verifier_packages_identity_and_authority_checks_report_only_registered_codes() -> (
    None
):
    """The key authority and actor marker checks of agent-evidence-verify, read from this repository's tree."""
    source = (
        Path(__file__).resolve().parents[2]
        / "agent-evidence-verify"
        / "src"
        / "agent_evidence_verify"
    )
    assert refusal_lint.lint_verifier(source) == []


def test_a_verifier_reason_outside_the_registry_is_refused() -> None:
    source = 'def f():\n    return "unauthorized", "key_somehow_odd"\n'
    found = lint_source(
        "key_authority.py", source, refusal_codes.CODES, refusal_lint.VERIFIER_CONFIG
    )
    assert [f.problem for f in found] == ["refusal code not registered"]
    assert not lint_source(
        "key_authority.py",
        'def f():\n    return "authorized", "key_pinned"\n',
        refusal_codes.CODES,
        refusal_lint.VERIFIER_CONFIG,
    )


def test_an_exempt_function_nested_in_a_checked_one_leaves_its_labels_alone() -> None:
    source = (
        "def check():\n"
        "    def grade():\n"
        "        label = 'not_a_registered_code'\n"
        "        return label\n"
        "    return grade\n"
    )
    assert findings(source) == []


def test_the_dnssec_refusal_codes_of_the_key_authority_check_are_registered() -> None:
    """The ``dnssec_<reason>`` codes are values of one table, which the lint does not read as refusal positions."""
    import ast

    path = (
        Path(__file__).resolve().parents[2]
        / "agent-evidence-verify"
        / "src"
        / "agent_evidence_verify"
        / "key_authority.py"
    )
    table = next(
        n.value
        for n in ast.parse(path.read_text(encoding="utf-8")).body
        if isinstance(n, ast.Assign)
        and any(getattr(t, "id", "") == "_DNSSEC_REFUSALS" for t in n.targets)
    )
    codes = {v.value for v in table.values}
    assert len(codes) == 19
    assert codes <= set(refusal_codes.CODES)


def test_the_receiver_policy_refusal_codes_are_registered_under_their_check() -> None:
    """A receiver built on these records refuses a request its route policy does not admit with one of two codes; a
    receiver in any language names the refusal by the same identifier."""
    for code in ("receiver_policy_denied", "receiver_agent_rule_missing"):
        entry = refusal_codes.lookup(code)
        assert entry.check == "receiver.policy"
        assert entry.uri == refusal_codes.REGISTRY + "/" + code

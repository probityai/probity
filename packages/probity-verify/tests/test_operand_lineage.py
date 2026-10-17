"""Adversarial checks for the exact, consumer-pinned operand-lineage claim."""

from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from probity_verify.common import CaseError
from probity_verify.core import adjudicate


class TestOperandLineage:
    """Exercise the public adjudication kernel, including artifact binding."""

    @staticmethod
    def packet(tmp_path: Path, source: dict, trace: dict, *, constants: dict | None = None,
               final_step: str = "total") -> tuple[dict, dict]:
        """Build separate source and execution artifacts and consumer pins."""
        artifacts = {}
        witnesses = {}
        for role, content in (("source", source), ("execution", trace)):
            data = (json.dumps(content, sort_keys=True) + "\n").encode("utf-8")
            (tmp_path / f"{role}.json").write_bytes(data)
            digest = hashlib.sha256(data).hexdigest()
            artifacts[role] = {"path": f"{role}.json", "sha256": digest, "length": len(data)}
            witnesses[role] = {"artifact": role, "sha256": digest,
                               "authority": f"consumer-pinned {role} observation"}
        case = {"schema_version": "probity-case/v1", "case_id": "figure-1",
                "artifacts": artifacts}
        policy = {"schema_version": "probity-policy/v1", "witnesses": witnesses,
                  "assessments": {"figure-1": {"claim_type": "operand_lineage/v1",
                    "source_witness": "source", "execution_witness": "execution",
                    "final_step": final_step, "constants": constants or {}}}}
        return case, policy

    @staticmethod
    def operand(kind: str, ref: str, value: str) -> dict:
        return {"kind": kind, "ref": ref, "value": value}

    @classmethod
    def chain(cls, left: str = "15.20", right: str = "12", constant: str = "2") -> dict:
        """Compute a difference, then multiply it by a declared constant."""
        return {"steps": [
            {"id": "difference", "operation": "subtract", "operands": [
                cls.operand("source", "checking", left),
                cls.operand("source", "savings", right)], "result": "3.20"},
            {"id": "total", "operation": "multiply", "operands": [
                cls.operand("step", "difference", "3.20"),
                cls.operand("constant", "multiplier", constant)], "result": "6.40"}],
            "figure": "6.40"}

    class TestPassingCases:
        def test_chained_lineage_and_declared_constant(self, tmp_path: Path) -> None:
            case, policy = TestOperandLineage.packet(
                tmp_path, {"values": {"checking": "15.20", "savings": "12"}},
                TestOperandLineage.chain(), constants={"multiplier": "2"})
            decision = adjudicate(case, policy, tmp_path)
            assert decision["decision"] == "supported"
            assert decision["reason"] == "lineage_recomputed"
            assert [check["status"] for check in decision["checks"]] == ["met", "met"]
            assert len(decision["policy_sha256"]) == 64

        @given(a=st.integers(min_value=-100000, max_value=100000),
               b=st.integers(min_value=-100000, max_value=100000))
        def test_exact_addition_for_signed_operands(self, a: int, b: int) -> None:
            trace = {"steps": [{"id": "total", "operation": "add", "operands": [
                TestOperandLineage.operand("source", "a", str(a)),
                TestOperandLineage.operand("source", "b", str(b))],
                "result": str(a + b)}], "figure": str(a + b)}
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                case, policy = TestOperandLineage.packet(
                    root, {"values": {"a": str(a), "b": str(b)}}, trace)
                assert adjudicate(case, policy, root)["decision"] == "supported"

        def test_exact_terminating_division(self, tmp_path: Path) -> None:
            trace = {"steps": [{"id": "total", "operation": "divide", "operands": [
                TestOperandLineage.operand("source", "a", "1"),
                TestOperandLineage.operand("source", "b", "4")],
                "result": "0.25"}], "figure": "0.25"}
            case, policy = TestOperandLineage.packet(
                tmp_path, {"values": {"a": "1", "b": "4"}}, trace)
            assert adjudicate(case, policy, tmp_path)["decision"] == "supported"

    class TestFailingCases:
        @pytest.mark.parametrize(("change", "reason"), [
            ({"left": "14.20", "right": "11"}, "operand_unresolved"),
            ({"constant": "3"}, "operand_unresolved"),
        ])
        def test_compensating_operands_and_false_constant(
            self, tmp_path: Path, change: dict, reason: str,
        ) -> None:
            trace = TestOperandLineage.chain(
                left=change.get("left", "15.20"), right=change.get("right", "12"),
                constant=change.get("constant", "2"))
            case, policy = TestOperandLineage.packet(
                tmp_path, {"values": {"checking": "15.20", "savings": "12"}},
                trace, constants={"multiplier": "2"})
            result = adjudicate(case, policy, tmp_path)
            assert result["decision"] == "contradicted"
            assert result["reason"] == reason

        def test_prior_step_cannot_launder_bad_operands(self, tmp_path: Path) -> None:
            trace = TestOperandLineage.chain(left="99")
            case, policy = TestOperandLineage.packet(
                tmp_path, {"values": {"checking": "15.20", "savings": "12"}},
                trace, constants={"multiplier": "2"})
            result = adjudicate(case, policy, tmp_path)
            assert result["reason"] == "operand_unresolved"
            assert len(result["checks"]) == 1

        def test_correct_figure_does_not_rescue_wrong_operation(self, tmp_path: Path) -> None:
            trace = TestOperandLineage.chain()
            trace["steps"][0]["operation"] = "add"
            case, policy = TestOperandLineage.packet(
                tmp_path, {"values": {"checking": "15.20", "savings": "12"}},
                trace, constants={"multiplier": "2"})
            assert adjudicate(case, policy, tmp_path)["reason"] == "result_mismatch"

        def test_declared_constant_must_contribute_to_final_figure(self, tmp_path: Path) -> None:
            trace = TestOperandLineage.chain()
            case, policy = TestOperandLineage.packet(
                tmp_path, {"values": {"checking": "15.20", "savings": "12"}},
                trace, constants={"multiplier": "2", "unused": "7"})
            result = adjudicate(case, policy, tmp_path)
            assert result["decision"] == "contradicted"
            assert result["reason"] == "declared_constant_unused"

        def test_dead_step_cannot_pad_lineage(self, tmp_path: Path) -> None:
            trace = TestOperandLineage.chain()
            trace["steps"].append({"id": "decoy", "operation": "add", "operands": [
                TestOperandLineage.operand("source", "checking", "15.20"),
                TestOperandLineage.operand("source", "savings", "12")], "result": "27.20"})
            case, policy = TestOperandLineage.packet(
                tmp_path, {"values": {"checking": "15.20", "savings": "12"}},
                trace, constants={"multiplier": "2"})
            assert adjudicate(case, policy, tmp_path)["reason"] == "step_not_in_final_lineage"

        def test_missing_trace_is_not_established(self, tmp_path: Path) -> None:
            case, policy = TestOperandLineage.packet(
                tmp_path, {"values": {"checking": "15.20", "savings": "12"}},
                TestOperandLineage.chain(), constants={"multiplier": "2"})
            (tmp_path / "execution.json").unlink()
            result = adjudicate(case, policy, tmp_path)
            assert result["decision"] == "not_established"
            assert result["reason"] == "witness_unavailable_or_unbound"

        def test_missing_source_reference_is_not_established(self, tmp_path: Path) -> None:
            trace = TestOperandLineage.chain()
            case, policy = TestOperandLineage.packet(
                tmp_path, {"values": {"checking": "15.20"}}, trace,
                constants={"multiplier": "2"})
            result = adjudicate(case, policy, tmp_path)
            assert result["decision"] == "not_established"
            assert result["reason"] == "reference_missing"

        def test_nonterminating_division_needs_rounding_policy(self, tmp_path: Path) -> None:
            trace = {"steps": [{"id": "total", "operation": "divide", "operands": [
                TestOperandLineage.operand("source", "a", "1"),
                TestOperandLineage.operand("source", "b", "3")],
                "result": "0.333"}], "figure": "0.333"}
            case, policy = TestOperandLineage.packet(
                tmp_path, {"values": {"a": "1", "b": "3"}}, trace)
            result = adjudicate(case, policy, tmp_path)
            assert result["decision"] == "not_established"
            assert result["reason"] == "rounding_rule_missing"

        def test_malformed_decimal_is_an_error_not_a_verdict(self, tmp_path: Path) -> None:
            trace = TestOperandLineage.chain(left="NaN")
            case, policy = TestOperandLineage.packet(
                tmp_path, {"values": {"checking": "15.20", "savings": "12"}},
                trace, constants={"multiplier": "2"})
            with pytest.raises(CaseError, match=r"steps\[0\].operands\[0\].value: expected finite decimal string"):
                adjudicate(case, policy, tmp_path)

        def test_malformed_later_step_cannot_hide_behind_failed_first_step(
            self, tmp_path: Path,
        ) -> None:
            trace = TestOperandLineage.chain(left="99")
            trace["steps"][1]["result"] = "NaN"
            case, policy = TestOperandLineage.packet(
                tmp_path, {"values": {"checking": "15.20", "savings": "12"}},
                trace, constants={"multiplier": "2"})
            with pytest.raises(CaseError, match=r"steps\[1\].result: expected finite decimal string"):
                adjudicate(case, policy, tmp_path)

        def test_unknown_witness_is_a_policy_error(self, tmp_path: Path) -> None:
            case, policy = TestOperandLineage.packet(
                tmp_path, {"values": {"a": "1"}}, TestOperandLineage.chain())
            policy["assessments"]["figure-1"]["source_witness"] = "absent"
            with pytest.raises(CaseError, match="source_witness: unknown witness"):
                adjudicate(case, policy, tmp_path)

        def test_source_and_execution_must_be_separate_artifacts(self, tmp_path: Path) -> None:
            case, policy = TestOperandLineage.packet(
                tmp_path, {"values": {"a": "1"}}, TestOperandLineage.chain())
            policy["witnesses"]["execution"]["artifact"] = "source"
            with pytest.raises(CaseError, match="source and execution require separate artifacts"):
                adjudicate(case, policy, tmp_path)

"""This package's copy of the identifier host rule is the agent-evidence-verify module, byte for byte.

The package does not depend on agent-evidence-verify at a release that carries the module, so it
ships its own copy; this test keeps the two from drifting apart.
"""

from pathlib import Path

import probity_effects.identifiers as copy

SOURCE = (Path(__file__).resolve().parents[2]
          / "agent-evidence-verify" / "src" / "agent_evidence_verify" / "identifiers.py")


def test_the_copy_is_the_source_file():
    assert Path(copy.__file__).read_bytes() == SOURCE.read_bytes()


def test_the_copy_recognises_both_hosts():
    old = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/uncertain-effect"
    new = "https://probityai.org/agent-evidence-vectors/predicate/v1/uncertain-effect"
    assert copy.canonical_identifier(new) == old
    assert copy.same_identifier(old, new)
    assert not copy.same_identifier("http://probityai.org/agent-evidence-vectors/predicate/v1/uncertain-effect", old)

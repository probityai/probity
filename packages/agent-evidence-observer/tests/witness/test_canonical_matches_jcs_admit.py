"""The observer's canonical bytes equal the jcs-admit crate's RFC 8785 output."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jcs_admit
import pytest

from probity_observer.crypto import canonical

VECTORS = json.loads(
    (Path(__file__).parent.parent / "fixtures" / "canonical-profile-v1" / "vectors.json").read_text(encoding="ascii")
)


@pytest.mark.parametrize("case", VECTORS["accept"], ids=[case["name"] for case in VECTORS["accept"]])
def test_canonical_matches_jcs_admit(case: dict[str, Any]) -> None:
    """Two independent RFC 8785 implementations agree byte for byte."""
    raw = json.dumps(case["value"], ensure_ascii=False).encode("utf-8")
    assert canonical(case["value"]) == jcs_admit.admit(raw) == bytes.fromhex(case["canonical_hex"])

"""Primary-source SDK hash selection for the ADK A2A failed-task profile."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .contract import A2A_SOURCE, A2A_VERSION, REVISIONS, SDK_VERSION, exact, load, require


def sdk_selection() -> dict[str, Any]:
    """Read the package's primary-source selection, independent of smolagents.

    Returns
    -------
    dict
        Complete ADK Python hashes from both pinned Git trees and exact
        A2A release wheel Python hashes. This reader needs neither framework.
    """
    selected = load(Path(__file__).with_name("sdk-source-selection.json"))
    exact(selected["revisions"], REVISIONS, "SDK source selection differs")
    exact(selected["versions"], {"google-adk": SDK_VERSION, "a2a-sdk": A2A_VERSION},
          "SDK version selection differs")
    exact(selected["a2aSource"], {"repository": "a2aproject/a2a-python",
          "commit": A2A_SOURCE, "tag": "v1.2.1"}, "A2A source selection differs")
    return selected


def sdk_hashes(variant: str) -> dict[str, str]:
    """Return the primary-source SDK hashes selected for one pin."""
    require(variant in REVISIONS, "unknown SDK variant")
    selected = sdk_selection()
    return {**selected["adk"][variant], **selected["a2a"]}

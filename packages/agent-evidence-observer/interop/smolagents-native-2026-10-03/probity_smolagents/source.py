"""Primary-source SDK hash selection for the smolagents profile."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .contract import SDK_SOURCE, SDK_VERSION, exact, load


def sdk_selection() -> dict[str, Any]:
    """Read the package's primary-source selection, independent of smolagents.

    Returns
    -------
    dict
        Complete Python and YAML source hashes derived from the official SDK
        Git tree. This reader does not import or require the framework.
    """
    selected = load(Path(__file__).with_name("sdk-source-selection.json"))
    exact(selected["commit"], SDK_SOURCE, "SDK source selection differs")
    exact(selected["version"], SDK_VERSION, "SDK version selection differs")
    return selected


def sdk_hashes() -> dict[str, str]:
    """Return the primary-source SHA-256 of every selected SDK file."""
    return {name: metadata["sha256"] for name, metadata in sdk_selection()["files"].items()}

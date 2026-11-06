"""Installed CLI for the retained Pydantic AI packet, read with its recorded framework version."""

from __future__ import annotations

from probity_pydantic import reader

# The retained packet records the framework it ran against. The shared reader is bound to the
# version of the newest retained run, so this command selects the older recorded one explicitly.
RETAINED_FRAMEWORK_VERSION = "1.68.0"


def main() -> None:
    """Run the Pydantic AI reader with the framework version recorded by the retained run.

    Takes the same arguments as :func:`probity_pydantic.reader.main`, including the
    required ``--pins-file`` and the optional ``--withheld-sources``.

    Returns
    -------
    None
        Write the reconstructed report to standard output on success.
    """
    reader.VERSION = RETAINED_FRAMEWORK_VERSION
    reader.main()

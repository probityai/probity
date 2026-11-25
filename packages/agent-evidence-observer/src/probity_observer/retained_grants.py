"""The one pinned copy of the retired grant module, for readers of retained runs.

Retained interop runs signed their grants and observer bindings under the old per-profile grant module
(``probity-protected-action-reference-v0``). The ruling in probity-records ``docs/one-name-ruling.md`` section 3
keeps those runs verifiable against exactly the bytes they pinned and re-signs nothing: this module loads those
bytes, refuses to load any others, and exposes the names the retained readers use. New records never use it;
they use :mod:`probity_observer.exact_grant`.
"""

from __future__ import annotations

import hashlib
import importlib.abc
import importlib.machinery
import importlib.util
import sys
from pathlib import Path
from types import CodeType, ModuleType

PINNED_COMMIT = "d1e92ccb7"

PINNED_SHA256 = "a51c74997d81af6a046cb8336aa683b047c1967cd760a2bf08806cb80c20c990"

PINNED_FILE = Path(__file__).with_name("_pinned_grant_records_d1e92ccb7.py")

MODULE_NAME = "probity_observer._pinned_grant_records"


class PinnedBytesDiffer(ImportError):
    """The pinned grant module's bytes are not the ones every retained run names."""


class _CheckedLoader(importlib.machinery.SourceFileLoader):
    """Compile the pinned file from the bytes just checked, never from a bytecode cache or a second read."""

    def get_code(self, fullname: str) -> CodeType:
        raw = self.get_data(self.path)
        if hashlib.sha256(raw).hexdigest() != PINNED_SHA256:
            raise PinnedBytesDiffer("the pinned grant module differs from its recorded digest")
        return self.source_to_code(raw, self.path)


def load() -> ModuleType:
    """The pinned module, loaded once after its digest check; its relative imports resolve inside this package."""
    loaded = sys.modules.get(MODULE_NAME)
    if loaded is not None:
        return loaded
    loader = _CheckedLoader(MODULE_NAME, str(PINNED_FILE))
    spec = importlib.util.spec_from_loader(MODULE_NAME, loader, origin=str(PINNED_FILE))
    if spec is None:
        raise PinnedBytesDiffer("the pinned grant module cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[MODULE_NAME] = module
    try:
        loader.exec_module(module)
    except BaseException:
        del sys.modules[MODULE_NAME]
        raise
    return module


_pinned = load()

ActionRequest = _pinned.ActionRequest
GrantPolicy = _pinned.GrantPolicy
AuthorizedAction = _pinned.AuthorizedAction
verify_grant = _pinned.verify_grant
verify_authorized_packet = _pinned.verify_authorized_packet
validate_utc_time = _pinned.validate_utc_time
utc_clock = _pinned.utc_clock

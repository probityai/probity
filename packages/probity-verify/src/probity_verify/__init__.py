"""probity-verify moved to agent-evidence-verify.

Importing probity_verify, or any probity_verify.<module>, returns the matching
agent_evidence_verify module and emits a DeprecationWarning.
"""

from __future__ import annotations

import importlib
import importlib.abc
import importlib.util
import sys
import warnings

import agent_evidence_verify as _new
from agent_evidence_verify import *  # noqa: F403

OLD = "probity_verify"
NEW = "agent_evidence_verify"

warnings.warn(
    "probity-verify moved to agent-evidence-verify; install agent-evidence-verify and "
    "import agent_evidence_verify instead",
    DeprecationWarning,
    stacklevel=2,
)


class _Alias(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    """Serve probity_verify.<x> as agent_evidence_verify.<x>."""

    def find_spec(self, fullname, path=None, target=None):
        if not fullname.startswith(OLD + "."):
            return None
        if importlib.util.find_spec(NEW + fullname[len(OLD):]) is None:
            return None
        return importlib.util.spec_from_loader(fullname, self)

    def create_module(self, spec):
        module = importlib.import_module(NEW + spec.name[len(OLD):])
        sys.modules[spec.name] = module
        return module

    def exec_module(self, module):
        return None


if not any(isinstance(f, _Alias) for f in sys.meta_path):
    sys.meta_path.insert(0, _Alias())

__version__ = getattr(_new, "__version__", None)

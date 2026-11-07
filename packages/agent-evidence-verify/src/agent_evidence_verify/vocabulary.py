"""Terms the verifier reads from the released agent-evidence-vocabulary registry.

The verifier does not keep its own copy of a registry term. It loads the term
list from the pinned ``agent_evidence_vocabulary`` package, so a value that the
registry does not define is refused, and a registry change that removes a term
the verifier accepts fails at import.
"""

from __future__ import annotations

from functools import lru_cache
from importlib.resources import files

import yaml


@lru_cache(maxsize=1)
def _registry() -> dict:
    text = files("agent_evidence_vocabulary").joinpath("vocabulary.yaml").read_text("utf-8")
    loader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
    return yaml.load(text, Loader=loader)


def version() -> str:
    """The registry version the verifier checks against."""
    return str(_registry()["meta"]["version"])


def terms(section: str, dimension: str) -> tuple[str, ...]:
    """Every value the registry defines for one dimension."""
    entry = _registry().get(section, {}).get(dimension)
    if not isinstance(entry, dict) or not isinstance(entry.get("values"), list):
        raise LookupError(f"vocabulary has no dimension {section}.{dimension}")  # noqa: TRY004 - a missing dimension is a lookup failure, not a type error
    return tuple(str(value) for value in entry["values"])


def term(section: str, dimension: str, value: str) -> str:
    """Return ``value`` when the registry defines it; raise LookupError when it does not."""
    if value not in terms(section, dimension):
        raise LookupError(f"{value!r} is not a {section}.{dimension} term in vocabulary {version()}")
    return value


#: Every witness_scope term the registry defines (SELF, PEER, EXTERNAL).
WITNESS_SCOPE_TERMS = terms("evidence_dimensions", "witness_scope")
#: The witness scopes the verifier accepts. SELF is a registry term that the
#: verifier refuses on purpose: a self-witnessed record cannot support a claim.
PEER = term("evidence_dimensions", "witness_scope", "PEER")
EXTERNAL = term("evidence_dimensions", "witness_scope", "EXTERNAL")
ACCEPTED_WITNESS_SCOPES = (PEER, EXTERNAL)


def witness_scope_error(value: object) -> str:
    """Why a witness_scope value is refused: not a registry term, or a refused term."""
    if isinstance(value, str) and value in WITNESS_SCOPE_TERMS:
        return f"witness_scope {value} is a vocabulary term the verifier refuses"
    return f"witness_scope is not a vocabulary {version()} term"

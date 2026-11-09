import importlib
import sys
import warnings


def test_old_names_resolve_to_new_modules():
    for name in [n for n in sys.modules if n == "probity_verify" or n.startswith("probity_verify.")]:
        del sys.modules[name]
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        old = importlib.import_module("probity_verify")
    assert any(issubclass(w.category, DeprecationWarning) for w in caught)
    import agent_evidence_verify.cli as new_cli

    assert importlib.import_module("probity_verify.cli") is new_cli
    from probity_verify.cli import main

    assert main is new_cli.main
    assert old.NEW == "agent_evidence_verify"

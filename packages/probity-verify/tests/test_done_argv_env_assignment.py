"""An acceptance argv cannot begin with an environment assignment."""
import pytest
from probity_verify.adapters.done_records import CaseError, _argv


def test_a_name_value_program_is_refused():
    with pytest.raises(CaseError, match="environment assignment"):
        _argv(["PYTHONPATH=/injected", "sh", "-c", "true"], "case.argv")


def test_an_ordinary_argv_is_kept():
    assert _argv(["pytest", "-q", "FOO=1"], "case.argv") == ["pytest", "-q", "FOO=1"]

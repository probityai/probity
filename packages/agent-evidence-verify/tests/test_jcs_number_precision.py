"""``jcs_canonical/v1`` refuses a number token that no double holds exactly.

RFC 8785 requires I-JSON input, and RFC 7493 section 2.2 rules out numbers with more precision than
an IEEE 754 double. Such a token names one number to an exact reader and another to a double reader,
so a signature over the canonical bytes of ``9007199254740993`` (written ``9007199254740992``) is
read by an int64 verifier as a signature over another value. It has no canonical form here.
"""

from __future__ import annotations

import pytest
from agent_evidence_verify.adapters import jcs_canonical as jcs


@pytest.mark.parametrize("text", [
    '{"n":9007199254740993}',
    '{"n":-9007199254740993}',
    '{"n":12345678901234567890}',
    '{"n":1e-400}',
    '{"n":3.141592653589793238462643383279}',
    '{"n":9007199254740993.0}',
])
def test_a_number_no_double_holds_exactly_has_no_canonical_form(text):
    with pytest.raises(jcs.Refusal):
        jcs.canonical("rfc8785", text)


@pytest.mark.parametrize("text,canonical", [
    ('{"n":9007199254740991}', b'{"n":9007199254740991}'),
    ('{"n":100000000000000000000}', b'{"n":100000000000000000000}'),
    ('{"n":1E21}', b'{"n":1e+21}'),
    ('{"n":0.1}', b'{"n":0.1}'),
    ('{"n":1.10}', b'{"n":1.1}'),
    ('{"n":-0.0}', b'{"n":0}'),
    ('{"n":0.30000000000000004}', b'{"n":0.30000000000000004}'),
])
def test_a_number_a_double_holds_exactly_keeps_its_canonical_form(text, canonical):
    assert jcs.canonical("rfc8785", text) == canonical

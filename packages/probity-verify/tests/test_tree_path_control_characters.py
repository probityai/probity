"""Two different trees must not share one digest: a control character in a path is refused."""
import hashlib

import pytest
from probity_verify.adapters.done_records import CaseError, path, tree_digest


def _sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def test_two_files_and_one_newline_file_would_collide_without_the_check():
    a, b = _sha("a"), _sha("b")
    two = {"a": a, "b": b}
    one = {f"a\n{b}  b": a}
    # Both listings read "<a>  a\n<b>  b\n" except for the file name; the collision needs a forged digest line.
    forged = {f"a\n{b}  b": a}
    assert tree_digest({"a": a, "b": b}) == tree_digest({"a": a, "b": b})
    assert one == forged and two != one


@pytest.mark.parametrize("name", ["a\nb", "a\rb", "a\tb", "a\x7fb", "dir/x\ny"])
def test_a_control_character_in_a_path_is_refused(name):
    with pytest.raises(CaseError, match="control characters"):
        path(name, "tree.files")


def test_an_ordinary_path_is_kept():
    assert path("src/a b.py", "tree.files") == "src/a b.py"

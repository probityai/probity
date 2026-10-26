"""The tree scanner refuses a path with a control character, so no two trees share a digest."""
import pytest
from probity_observer.sensors import treedigest


def test_a_newline_in_a_file_name_is_refused(tmp_path):
    (tmp_path / "a\nb").write_text("x")
    with pytest.raises(treedigest.TreeNameError):
        treedigest.scan(tmp_path)


def test_a_newline_in_a_symlink_name_is_refused(tmp_path):
    (tmp_path / "t").write_text("x")
    (tmp_path / "l\nk").symlink_to("t")
    with pytest.raises(treedigest.TreeNameError):
        treedigest.scan(tmp_path)


def test_two_files_and_the_forged_one_file_tree_differ_by_refusal(tmp_path):
    (tmp_path / "a").write_text("a")
    (tmp_path / "b").write_text("b")
    honest = treedigest.scan(tmp_path).sha256
    forged = tmp_path / "forged"
    forged.mkdir()
    (forged / f"a\n{treedigest.file_sha256(tmp_path / 'b')}  b").write_text("a")
    with pytest.raises(treedigest.TreeNameError):
        treedigest.scan(forged)
    assert honest

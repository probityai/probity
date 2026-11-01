from probity_observer.done.native import native, native_name


def test_a_native_name_is_a_compiled_suffix_or_a_versioned_shared_object():
    assert native_name("a.so") and native_name("a.so.1") and native_name("b.dll")
    assert not native_name("a.py")


def test_native_reads_the_elf_magic_when_the_name_does_not_say(tmp_path):
    elf = tmp_path / "tool"
    elf.write_bytes(b"\x7fELF\x02")
    text = tmp_path / "notes"
    text.write_bytes(b"plain")
    assert native(elf) and not native(text)
    assert native(tmp_path / "lib.so")

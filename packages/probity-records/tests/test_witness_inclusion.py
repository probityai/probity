"""RFC 9162 inclusion proofs: every leaf of every small tree proves, and a moved or altered proof does not."""

from __future__ import annotations

from probity_records.witness import inclusion_proof, leaf_hash, root, verify_inclusion


def _leaves(n: int) -> list[bytes]:
    return [leaf_hash(b"leaf %d" % i) for i in range(n)]


def test_every_leaf_of_every_tree_up_to_17_proves_under_its_root() -> None:
    for n in range(1, 18):
        leaves = _leaves(n)
        for i in range(n):
            assert verify_inclusion(i, n, leaves[i], inclusion_proof(i, leaves), root(leaves))


def test_a_proof_for_another_index_size_leaf_or_root_fails() -> None:
    leaves = _leaves(7)
    proof = inclusion_proof(3, leaves)
    assert not verify_inclusion(4, 7, leaves[3], proof, root(leaves))
    assert not verify_inclusion(3, 8, leaves[3], proof, root(leaves))
    assert not verify_inclusion(3, 7, leaves[2], proof, root(leaves))
    assert not verify_inclusion(3, 7, leaves[3], proof, root(leaves[:6]))
    assert not verify_inclusion(3, 7, leaves[3], [*proof, leaves[0]], root(leaves))
    assert not verify_inclusion(3, 7, leaves[3], proof[:-1], root(leaves))
    assert not verify_inclusion(7, 7, leaves[3], proof, root(leaves))
    assert not verify_inclusion(-1, 7, leaves[3], proof, root(leaves))

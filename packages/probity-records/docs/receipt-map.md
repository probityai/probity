# Receipt map (`probity-receipt-map/v1`)

A transparency log proves that a record is included. It cannot prove that no second record answers the same
question. The receipt map answers it for receipts: for one issuer key, one permit id and one stage, a log
commits a map root into its own tree, and a proof against that root shows the key holds exactly one receipt
(its leaf index and leaf hash) or none.

## Key

```
key = SHA-256("probity-receipt-map/v1 key" || issuer || u16(len(permit)) || permit || u16(len(stage)) || stage)
```

- `issuer`: the 32-byte SHA-256 of the record's raw Ed25519 public key (written as 64 lowercase hex digits).
  A record one party signs never takes the slot of a record another party signs.
- `permit`: UTF-8, 1 to 256 bytes, no control character.
- `stage`: one of `accept`, `execute`, `settle`, `final`.
- `u16`: big-endian length.

## Tree

A binary tree of depth 256 over the key bits, most significant first, in compact form:

```
entry      = SHA-256(0x00 || key || u64(leaf index) || leaf hash)
node(L, R) = SHA-256(0x01 || L || R)
empty      = 32 zero bytes
```

A subtree with no entry hashes to `empty`; a subtree with one entry hashes to that entry, at whatever depth;
a subtree with two or more is `node(left, right)`. Each set of entries has one root. An insert of a key that
is already present is refused: the first receipt for a key is the one the map holds.

## Proof

```json
{"key": "<64 hex>", "siblings": ["<base64 32 bytes>" | null, ...], "terminal": null | {"key": "<64 hex>", "index": 0, "leafHash": "<64 hex>"}}
```

`siblings` runs from the root down (`null` is the empty subtree); at most 256. Verify by starting from the
terminal's entry hash (or `empty` when the terminal is null), refusing a terminal whose key does not share
the first `len(siblings)` bits with `key`, and hashing up: at depth `d`, a key bit of 1 puts the sibling on
the left. The proof holds when the result equals the committed root. Then the key is present when the
terminal's key equals `key`, and absent otherwise (an empty path, or another key's entry on the path).

A proof that stops at another depth than the true tree, a terminal off the key's path, or a membership claim
for an absent key cannot reproduce the root. A proof with a sibling that is not 32 bytes, more than 256
siblings, or a non-integer index is malformed and refused before any hashing.

## Vectors

`vectors/shared/receipt-map.json`, written by `scripts/make_receipt_map_vectors.py`: the entries and root of a
24-entry map, member, absent and refused proofs against it, key derivations, and refused keys.
`tests/test_receipt_map.py` runs them and checks the file is what the script writes.

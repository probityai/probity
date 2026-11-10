# Check a stream of signed CBOR receipts

`cbor_receipt_chain/v1` answers one question about a class of authorization records: do these signed
receipts form one whole, ordered chain under keys the consumer chose? The class is a CBOR receipt per
decision, each linked to the one before it by the SHA-256 of its bytes, signed with Ed25519.

Every receipt in such a stream can verify while the stream is not the one that was written. The claim type
refuses what a per-receipt check passes: a receipt repeated, an authorization recorded twice, two receipts
swapped, a record re-signed under a key the consumer never pinned, and a first receipt that does not follow
the predecessor the consumer holds. It reports as `not_established`, never as a pass, what the bytes cannot
show: a restart that starts a new chain, a tail cut when no head was pinned, an effect the format does not
record, and a revocation commitment the receipts do not carry.

## The assessment

| Field | Meaning |
| --- | --- |
| `records` | the artifact holding one receipt per line, as hex or as a JSON object with one member |
| `profile` | the artifact naming the format (below) |
| `signer_keys` | the Ed25519 public keys, in hex, the consumer trusts |
| `first_prev` | the SHA-256 the first receipt must name, or absent when it starts a chain |
| `head`, `count` | the last receipt's SHA-256 and the receipt count the consumer kept outside the stream; both or neither |
| `require_effect`, `require_revocation` | ask for the effect or revocation commitment; an absent one is `not_established` |

## The format profile

A `cbor-receipt-profile/v1` file names the outer map's four member names, the signed-message context bytes,
whether keys and signatures are bare byte strings (`raw`) or `[alg, bytes]` pairs (`pair`), and the integer
member keys of the payload by role: `version` and `prev_hash` always, and `outcome`, `request_hash`, `proof`,
`revocation_hash` and `effect` when the format has them. The signed message is the context bytes, the version
byte and the payload bytes. The profile is a pinned input like the case: one format, one file. A profile
that is malformed is a case error and produces no verdict.

## Decisions

The first failing check is the reason: `receipt_shape`, `signature`, `signer_pinned`, `no_duplicate_receipt`,
`single_use`, `chain_order`, `head_anchor`, each `contradicted`. Otherwise `not_established` with the first of
`chain_reset`, `head_not_anchored`, `effect_not_recorded`, `revocation_not_consulted`, or `supported` with
`receipt_chain_holds`. A stream that stops before the pinned head cannot be told from one that was cut, so a
whole-chain `supported` needs the head.

The decoder is strict: indefinite lengths, tags, floats, repeated map keys, trailing bytes and nesting past
16 levels are refused. The example in `examples/cbor-receipt-chain/` is generated with a published test key.

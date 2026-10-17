# Running the verifier

## Run

Python 3.10 or newer and [uv](https://docs.astral.sh/uv/):

```sh
uv sync --extra test
uv run pytest
uv run probity-verify examples/source-coverage/case.json \
  --policy examples/source-coverage/policy-june.json
uv run probity-verify examples/operand-lineage/case.json \
  --policy examples/operand-lineage/policy.json
uv run probity-verify examples/authority-anchor/case.json \
  --policy examples/authority-anchor/policy.json
uv run probity-verify examples/event-absence/case.json \
  --policy examples/event-absence/policy.json
```

Add `--json` for the full decision or `--packet decision.txt` to save
the text packet. The synthetic June case returns
`contradicted`: a selected passage appears in the source capture but not in
the stored report. Run with `policy-april.json` to get `not_established`:
the June capture cannot establish an April intake. `case-complete.json`
with `policy-complete.json` returns `supported`.

Adapters that report what their verdict rests on add it to the decision
line, for example `Decision: supported (vantage: independent,
witness_scope: PEER)`. `--require-witness-scope EXTERNAL` holds a `supported`
verdict that does not rest on EXTERNAL witness scope as `not_established` with
reason `witness_scope_below_required`; a `contradicted` verdict stands; see
[Done-receipt checks](done-receipt.md#vantage-and-witness-scope).

## Inputs and decisions

The case supplies local artifacts with relative paths, byte lengths, and
SHA-256 digests. A separate consumer policy pins witnesses and sets the
claim requirements. The case cannot change them.

| Decision | Meaning |
| --- | --- |
| `supported` | The stated claim passes its adapter's checks against the pinned bytes. |
| `contradicted` | Bound evidence conflicts with a claim requirement. |
| `not_established` | Required evidence or a rule needed to decide is unavailable. |

The verifier checks supplied bytes; it does not fetch URLs or authenticate
the authority named in a policy. The consumer must inspect and pin the
capture independently. HTML extraction reads `<article>` text and omits
scripts, styles, and templates. It does not evaluate CSS or infer what a
browser displayed. Text matching does not establish that the selected
passages are material or that the report is otherwise complete.

## Signed bundles

`probity verify` reads its first argument as a probity case or as a DSSE
envelope. It decides the type from the JSON members. For an envelope, give the
case the payload belongs to and one or more trusted Ed25519 public keys (raw
32 bytes or PEM):

```sh
uv run probity verify examples/dsse-bundle/valid.dsse.json \
  --case examples/done-receipt/honest/receipt.case.json \
  --policy examples/done-receipt/honest/receipt.policy.json \
  --key examples/dsse-bundle/signer.pub
```

The verifier computes `PAE(payloadType, payload)` and tries every signature
under every key. It never reads `keyid`. It refuses non-canonical base64, an
empty `payloadType` and an envelope with no signatures (exit 2). If no supplied
key accepts a signature, the decision is `not_established` with reason
`dsse_signature_unverified`. If the payload type is not the expected one
(`--payload-type`, default `application/vnd.in-toto+json`), the reason is
`dsse_payload_type_unexpected`. Otherwise the verified payload replaces the
case artifact pinned to its SHA-256, and the claim adapter decides as for the
bare case. The first check, `dsse_envelope`, names the payload digest and the
SHA-256 of each accepting key. A payload that the claim does not read refuses
with exit 2. The vectors and their byte-exact outputs are in
`examples/dsse-bundle/` (`generate.py --check`).

## Artifact read boundary

Verify opens artifact paths relative to directory descriptors. Each directory
and the final regular file must open without symlink traversal. It reads bounded
chunks and checks the declared length and SHA-256. A missing artifact can produce
`not_established`. Unsafe paths, nonregular files, changed files and declared
binding mismatches refuse with exit 2 and no verdict.

This path needs POSIX descriptor-relative `open` and `stat`, non-following `stat`,
and `O_NOFOLLOW`, `O_DIRECTORY`, `O_NONBLOCK` and `O_CLOEXEC`. Verify refuses
artifact reads when Python lacks these capabilities. There is no path-based
fallback. Tests exercise Linux directory and file descriptors, actual symlinks,
FIFOs, sockets, and replacements at open and read boundaries. These checks bind
the consumed inode and bytes. They do not authenticate the host or prove that
a directory stayed unchanged after its descriptor opened.

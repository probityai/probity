# `aep_package/v1`: one action evidence package, every layer

`aep_package/v1` checks an action evidence package (`.aep`, a ZIP archive) layer by layer and reports every layer:
after the first failure each later check is `not_evaluated`, never skipped and never passed.

```json
{
  "claim_type": "aep_package/v1",
  "package": "package.aep",
  "authority": {"kind": "pin", "keys": [{"public_key_sha256": "<sha256 of the RSA key's DER SubjectPublicKeyInfo>"},
                                         {"public_key_sha256": "<sha256 of the raw ML-DSA-65 public key>"}]},
  "tsa_authority": {"kind": "pin", "keys": [{"public_key_sha256": "<sha256 of the TSA certificate key's DER SPKI>"}]}
}
```

| Check | Passes when |
|---|---|
| `package_shape` | the archive opens, its entries and central directory tile the file from byte 0 to the end with an empty comment (a second archive prepended, hidden in a gap or appended is read by one ZIP reader and not another), names no entry twice or twice under case folding, names no path, holds `response.txt`, `metadata.json`, `canonical.bin`, `hash.sha256`, `signature.sig`, `public_key.pem` and `timestamp.tsr`, and `metadata.json` is strict I-JSON |
| `hash` | SHA-256 of `canonical.bin` equals `hash.sha256` (one trailing LF accepted) |
| `canonical_form` | `canonical.bin` is `response.txt`, LF, RFC 8785 of `metadata.json`; the legacy response-only form leaves `metadata.json` outside every signature and is `not_established` / `metadata_unbound` |
| `rsa_signature` | the recovered RSA block is exactly the RFC 8017 SHA-256 encoding (DigestInfo with NULL parameters) or exactly the legacy encoding with absent parameters, which is named; a modulus under 2048 bits is refused |
| `signer_pinned` | the RSA key is admitted by `authority` |
| `receipt` | when present: `content_hash` is `sha256:` and the package hash, every field shared with `metadata.json` is equal (a value of another type disagrees), and a receipt signature verifies whenever `overt_receipt.sig` is present or `metadata.json` names it |
| `pqc_signature` | when present: ML-DSA-65 over `canonical.bin` (RFC 9881 SPKI or a raw 1952-byte key, empty context) under a key `authority` admits |
| `timestamp` | the RFC 3161 response is granted, it is CMS SignedData whose encapsulated content type and signed `contentType` attribute are both id-ct-TSTInfo (a TSA key that signed something else is not a time-stamp), its SHA-256 imprint is the package hash, `messageDigest` is SHA-256 of the TSTInfo, the CMS signature verifies under the embedded certificate, and that key is admitted by `tsa_authority` |

The whole RSA block is compared. Four blocks that end in the right digest are refused: arbitrary bytes between the
padding and the digest, bytes after the legacy DigestInfo prefix, a SHA-512 OID with a 32-byte digest, and a
padding string shorter than the modulus requires. A check that compares only the trailing 32 bytes accepts all four.

The key a package carries proves nothing alone: with no `authority` the verdict is `not_established` /
`signer_not_established`, and with no `tsa_authority` it is `not_established` / `tsa_not_established`. Supported:
`package_verifies`. The verdict does not show that the recorded action happened or that the response is true.

A legacy package is not supported because nothing signs its metadata: in the public suite's
`mcp-tools-call-denied-policy` package, rewriting `policy_decision` and the unsigned receipt's `policy.decision`
from `deny` to `allow` leaves every layer verifying. A reader that passes the legacy form passes that rewrite.

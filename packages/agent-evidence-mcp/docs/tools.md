# Tools

Every tool is read-only and offline, sets `readOnlyHint`, `destructiveHint: false` and `openWorldHint: false`, and has a title. Errors come back as `{"ok": false, "error": ...}`.

| tool | arguments | returns |
| --- | --- | --- |
| `verify_claim` | `case` and `policy` (JSON objects), `artifacts` (relative path to UTF-8 text) | `decision` (`supported`, `contradicted` or `not_established`), `reason`, `policy_sha256`, `checks`, `scope`, and the text `packet`. Input that is invalid returns an error and no decision. |
| `verify_sample` | `scenario`: `contradicted`, `not_established` or `supported` | the same fields, for a sample bundled with probity-verify |
| `list_vector_corpora` | none | each shipped corpus with its suite revision and vector count where it declares them |
| `run_vectors` | `corpus` (default `vectors`), `offset`, `limit` (at most 200) | the harness exit code, the corpus release and digest, `totals`, and one page of per-vector rows. A corpus whose harness prints a text verdict returns that text; one that needs an external verifier returns the harness error. |
| `explain_vector` | `vector_id`, `corpus` | the manifest entry (expected outcome and the conditions it tests), the spec path, and the vector's input bytes up to 16 KB |
| `lookup_term` | `term` (exact key) | section, status, allowed values, definition and source path; otherwise close terms |
| `check_artifact_digest` | `document` (TEA, CycloneDX or in-toto text) and one of `artifact_text`, `artifact_base64` | `admitted`, the matched digest and every digest the document names |
| `canonicalize_json` | `document` (JSON text), `profile`: `rfc8785` (default) or `ijson` | the RFC 8785 canonical text, its hex and SHA-256, from the `jcs-admit` crate; a refusal returns the crate's variant and fields (`DuplicateMember`, `StringNotScalar`, and `UnsafeInteger` under `ijson`) |
| `verify_dsse` | `envelope` (DSSE JSON), `trusted_keys` (a list of `public_key_hex` with an optional `key_id`, at most 16), `threshold` | `verified`, `payload_type`, the accepted key ids, and the payload (base64, first 16 KB) with its SHA-256, from the `dsse` crate; a refusal returns the crate's variant (`ThresholdNotMet`, `MalformedEnvelope`) |

`verify_claim` writes the supplied `artifacts` to a temporary directory, refuses absolute paths and `..`, and removes the directory afterwards. A case binds its artifacts by digest, so changing an artifact's bytes returns a binding error rather than a different verdict.

The server wraps `probity-verify`, `agent-evidence-vectors`, `agent-evidence-vocabulary`, `agent-evidence-admission` and `jcs-admit` (the wheel for the `jcs-admit` and `dsse` Rust crates), each pinned exactly in `pyproject.toml`.

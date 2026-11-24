# Web Bot Auth vectors: the agent browser profile

Twelve cases for `web_bot_auth/v1`, each a request signed the way a signing browser proxy signs what an agent's browser sends. The profile is described in [docs/web-bot-auth.md](https://github.com/probityai/probity/blob/main/packages/agent-evidence-verify/docs/web-bot-auth.md#the-agent-browser-profile). Each case directory holds the request capture, the body as it arrived, the pinned key directory, the case and the consumer policy; `MANIFEST.json` holds the expected decision and reason and the SHA-256 of every file.

| Case | Expected | What it shows |
| --- | --- | --- |
| supported | supported | a POST signed in the profile, with its body and its release record's stamp digest |
| supported-get-empty-body | supported | a GET covers the digest of no bytes, so the consumer binds the empty body |
| body-swapped | contradicted `content_digest_mismatch` | the body was replaced on the way |
| digest-dropped | contradicted `content_digest_mismatch` | `Content-Digest` was removed while the signature still lists it |
| digest-not-covered | contradicted `component_not_covered` | a signature that leaves `content-digest` out is not the profile |
| stale | contradicted `signature_expired` | read two minutes after it was signed for 60 seconds |
| ttl-over-profile | contradicted `validity_window_too_long` | valid for 300 seconds, over the profile's 60 |
| key-not-in-directory | not_established `key_not_in_directory` | signed by a key the pinned directory does not list |
| path-required | contradicted `component_not_covered` | a consumer that requires `@path`: the profile covers the path through `@target-uri` |
| stamp-digest-swapped | contradicted `pinned_field_mismatch` | the stamp digest was replaced, and the consumer pins its release record's |
| stamp-digest-swapped-unpinned | contradicted `signature_invalid` | the same swap, read with no pin: the signature covers the field |
| stamp-digest-of-another-release | contradicted `pinned_field_mismatch` | validly signed for another release record |

Run a verifier through the CLI contract (`<verifier> case.json --policy policy.json --json`):

```sh
uv run --extra test python vectors-web-bot-auth/check_vectors.py --verifier 'agent-evidence-verify'
uv run --extra test python vectors-web-bot-auth/check_vectors.py \
  --verifier 'node ../../node/probity-records-verify/src/cli.ts web-bot-auth'
```

The checker checks the committed bytes before it runs the verifier, runs it once per case and prints `executed N of 12 vectors`. Regenerate with `python3 vectors-web-bot-auth/gen_vectors.py`; `--check` compares a fresh build with the committed files. The generator writes each signature base by hand, so neither verifier is the oracle for a request it judges.

The corpus, the Python verifier and the TypeScript verifier have the same author. Two implementations agreeing on these cases shows they read the profile the same way; it is not an independent review of the profile.

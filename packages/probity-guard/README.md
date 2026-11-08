# probity-guard

Inline content guard for agent tool calls: it redacts or blocks secrets and personal data in the exact bytes a call sends or a stream returns, and signs a record of every redact and block that binds the input digest.

For teams putting an approval or permit gate in front of agent tools who also need data protection on that same path.

```sh
pip install probity-guard==0.1.0
```

```python
from probity_guard import Blocked, Guard, guarded_stream

guard = Guard()
print(guard.check("card 4111 1111 1111 1111").output)   # card [REDACTED:payment_card]
try:
    list(guarded_stream(guard, ["key AKIAABCD", "EFGHIJKLMNOP and more"]))
except Blocked as exc:
    print(exc.verdict.reason)                            # blocked_classifier
```

- A secret split across two chunks is seen whole: the stream holds back an overlap window.
- A classifier that errors blocks, and the error is recorded.
- After a block, every later chunk raises: nothing past the block reaches the consumer.
- With `Guard(journal=Journal(dir, signer))` each redact and block is a signed, hash-chained record that `probity_records.verify_journal` checks offline.
- `guard.content_guard()` plugs into `probity_temporal.LocalAuthority(content_guard=...)`, so a call carrying a secret is refused before its permit is issued.

Status: 0.1.0. Source: `packages/probity-guard` in this repository.

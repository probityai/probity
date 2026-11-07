# Built today and reused

The repository's first commit is from 2026-10-11, and everything under `src/ratchet`, `probity-ratchet-cases`, `tests`, `examples` and `docs` was written at the event. The rest is a pinned dependency or a service.

| Reused | Pin |
|---|---|
| Runtime | `jcs-admit~=0.1.0`, `httpx>=0.27`, `cryptography>=44`, `rich>=15`; extras: `pymongo>=4.10`, `raindrop-ai==0.0.75` |
| Earlier work of the same authors | `agent-evidence-verify~=0.2.1`, `agent-evidence-vectors~=0.26.0` |
| Instruction search extra | `gepa==0.1.4` |
| Services | MongoDB Atlas (`mongodb-atlas-local:8.3.9-20260928T091948Z` for development), Voyage embeddings, Raindrop |

The integration that writes and checks Ratchet's own admission records is new. The verifier it calls is not.

License: Apache-2.0.

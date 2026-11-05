# Checking a retained run

Python 3.12 or later and [`uv`](https://docs.astral.sh/uv/) are needed for these commands:

```sh
uv venv .venv --python python3.12
uv pip install --python .venv/bin/python -e '.[test]'
.venv/bin/pytest -q
.venv/bin/agent-evidence-observer verify scripts/fixtures/broker-packet
```

The command prints `status: verified`, `witnessScope: PEER`, and `noDetectedGap: true`. The last field means the broker's sequential file-tree snapshots found no divergence; it does not mean every agent effect was observed. `broker-packet/` contains the signed packet, history, public keys, witness state, and file tree. The operator's runtime wrote it, and verification works offline. Outside this fixture, consumers need independently obtained key pins; a bundle's own `trusted-keys.json` is not a source of trust.

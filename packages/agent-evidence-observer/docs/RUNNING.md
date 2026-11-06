# Checking a retained run

Python 3.12 or later and [`uv`](https://docs.astral.sh/uv/) are needed for these commands:

```sh
uv venv .venv --python python3.12
uv pip install --python .venv/bin/python -e '.[test]'
.venv/bin/pytest -q
.venv/bin/agent-evidence-observer verify scripts/fixtures/broker-packet \
  --observer-key a592976c199b8a4f3a80ca4412df916de591aa4a10f95e0b8030e1321bd2d9de \
  --witness-key 143f322c613549cf4da40ae09b0634f82b68d2d5a1017639bdde2e1eb15353f6
```

The command prints `status: verified`, `witnessScope: PEER`, and `noDetectedGap: true`. The last field means the broker's sequential file-tree snapshots found no divergence; it does not mean every agent effect was observed. `broker-packet/` contains the signed packet, history, witness state, and file tree. The operator's runtime wrote it, and verification works offline. The packet carries no keys: `verify` takes the observer and witness keys as `--observer-key` and `--witness-key`, obtained independently of the packet, and refuses to run without both. A packet re-signed under other keys fails against these pins.

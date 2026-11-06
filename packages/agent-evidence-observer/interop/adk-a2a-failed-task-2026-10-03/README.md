# Native ADK/A2A task failure and effects

A plain A2A server runs through ADK's public RemoteA2aAgent and Runner, with a signed target write before FAILED. The producing operation is run by the operator's runtime. This directory holds the installed offline reader, the retained CI packets from the last producing run, and the reader's fault controls. The reader preserves both the write and the failure, and publishes only the matched COMPLETED controls.

```bash
# from packages/agent-evidence-observer
python -m venv reader
reader/bin/python -m pip install --require-hashes -r interop/adk-a2a-failed-task-2026-10-03/requirements-reader.lock
reader/bin/python -m pip install --no-deps . interop/adk-a2a-failed-task-2026-10-03
reader/bin/python -I -B interop/adk-a2a-failed-task-2026-10-03/verify_retained.py
```

Requires Python 3.12. [PROFILE.md](PROFILE.md) gives the source pins, controls and exact scope. [.github/workflows/adk-a2a-failed-task.yml](../../../../.github/workflows/package-observer-adk-a2a-failed-task.yml) runs the same reader check and the fault controls over the retained packets. The retained record holds native transport bodies, session events, signed effects, wheel digests and reader reports; embedded source bytes are held as digests in `retained/WITHHELD-SOURCES.json`.

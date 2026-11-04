# Native Haystack publication and dispatch consumer

This profile gates native Haystack 3.3.0 tool writes and publishes verified evidence.
It is for hosts that use `Pipeline`, `Agent`, and `Tool`.
The producing operation is run by the operator's runtime. This directory holds the
installed framework-free reader, the retained CI packet from the last producing run,
and the reader's fault controls.

From packages/agent-evidence-observer, run the retained verification:

```sh
python -m venv reader
reader/bin/python -m pip install --require-hashes -r interop/haystack-native-2026-10-03/requirements-reader.lock
reader/bin/python -m pip install --no-deps . interop/haystack-native-2026-10-03
reader/bin/python -I -B interop/haystack-native-2026-10-03/verify_retained.py
```

The reader has no Haystack dependency. Embedded source bytes of the producing run are held
as digests in `retained/WITHHELD-SOURCES.json`, which the reader accepts through `--withheld`.
This source profile is version 0.0.1; no package-index release or outside adoption is claimed.

| Document | Job |
|---|---|
| [Contract](PROFILE.md) | Native population, source selection, effect and publication boundaries |
| [Reader](probity_haystack/reader.py) | Framework-free retained evidence verification |

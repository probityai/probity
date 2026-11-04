# Native smolagents publication consumer

A source-pinned ToolCallingAgent runs with scripted model attempts and a custom tool. The producing operation is run by the operator's runtime. This directory holds the installed offline reader, the retained CI packet from the last producing run, and the reader's fault controls.

The reader publishes the authorized permit case after checking the signed effect, selected SDK source, native callbacks and terminal state. Eight cases exercise wrong content, errors before and after a write, exhausted steps, a model error, incomplete closure and a final answer without a write.

From packages/agent-evidence-observer:

~~~bash
python -m venv reader
reader/bin/python -m pip install --require-hashes -r interop/smolagents-native-2026-10-03/requirements-reader.lock
reader/bin/python -m pip install --no-deps . interop/smolagents-native-2026-10-03
reader/bin/python -I -B interop/smolagents-native-2026-10-03/verify_retained.py
~~~

The retained record holds the native bytes, signed effects, wheel digests and reports; embedded source bytes are held as digests in `retained/WITHHELD-SOURCES.json`. Use the installed reader on a saved capture with its host policy and a withheld-source record:

~~~bash
policy_sha=$(sha256sum host-policy.json | cut -d' ' -f1)
reader/bin/python -I -B -m probity_smolagents.reader packet \
  --host-policy host-policy.json --policy-sha256 "$policy_sha" \
  --withheld WITHHELD-SOURCES.json --publish publication
~~~

The host policy stays outside the packet. Publication requires a new directory outside the packet. See [PROFILE.md](PROFILE.md) for the finite contract and trust boundaries.

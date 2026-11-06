# ADK nested compaction and shared plugin lifecycle

The unchanged [ADK #7401 head](https://github.com/google/adk-python/pull/7401) runs through `root -> AgentTool(middle) -> AgentTool(leaf)`, twice. The full source pin is `81c43680d6ebe0288b77a2e9ff746f696889c75d`. The producing operation is run by the operator's runtime; this directory holds the installed SDK-free reader, the retained CI packet from the last producing run, and the reader's fault controls. Source bytes of the producing run are held as digests in `retained/WITHHELD-SOURCES.json`.

Four cases keep token compaction, no config, window-only config and `include_plugins=False` separate. Each executes six native tool-body writes. The installed reader checks raw model and callback bytes, fresh repeated sessions, config propagation, parent config preservation, shared-plugin close and signed Observer writes.

The three covered cases can publish this finite reference. The no-plugin case keeps a nested callback coverage hold. Direct SDK summarizer requests are retained separately from plugin model callbacks. Verify consumes four lifecycle projections twice: three `supported`, one `not_established`.

The [workflow](../../../../.github/workflows/package-observer-adk-nested-compaction.yml) installs the reader from its hash lock, checks the retained record twice with public code, runs the semantic controls over the retained packet and runs the actual Verify CLI over the retained projections. The retained record includes the setup failure as well as the native attempts.

This is author-operated PEER work with fixed public responses and same-host clocks. The older 16 rows and prospective eight-task study remain separate; that study has not started.

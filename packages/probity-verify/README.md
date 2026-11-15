# probity-verify has moved to agent-evidence-verify

This name is no longer developed. The verifier is published as [agent-evidence-verify](https://pypi.org/project/agent-evidence-verify/).

```
pip install agent-evidence-verify
```

This last release of `probity-verify` installs `agent-evidence-verify` and keeps old code running: `import probity_verify` and `probity_verify.<module>` resolve to the matching `agent_evidence_verify` module with a `DeprecationWarning`, and the `probity-verify` command runs the new verifier. Change your imports to `agent_evidence_verify` and your requirement to `agent-evidence-verify`.

Downloads: [probity-verify](https://pepy.tech/projects/probity-verify) and [agent-evidence-verify](https://pepy.tech/projects/agent-evidence-verify) on pepy.tech.

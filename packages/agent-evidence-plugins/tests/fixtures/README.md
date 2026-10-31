# Fixtures

Two replayable decision bundles built from members of the done-receipt corpus in
probityai/agent-evidence-vectors at commit 20e93ccb265d13f149dbfbd59a291207289d9b30
(`vectors-done-receipt/cases/<member>`). Rebuild one with:

    probity-bundle create <member>/receipt.case.json --policy <member>/receipt.policy.json \
      --artifact-root <member> --output <member>.decision.zip

with the pinned verifier, `pip install probity-verify==0.2.4`. A bundle replays only under the
release that built it: the replay compares the stored `decision.json` byte for byte with its own, so
a release that adds a field to the decision refuses every older bundle. Rebuild both fixtures in
the pull request that moves the pin.

| file | member | decision |
| --- | --- | --- |
| honest.decision.zip | honest | supported |
| honest-failure.decision.zip | honest-failure | contradicted |

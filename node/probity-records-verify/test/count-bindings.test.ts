// The TypeScript half of the approval-count twin: the fixture is quorum.count_bindings' result on each case
// (packages/probity-records/tests/test_count_bindings_twin.py builds it and checks it equals that reader's count).
// countBindings must give the same people and the same problems, OpenID Connect sign-ins and revoked keys included.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { countBindings } from "../src/verify.ts";
import { applyRevocationList, newRevocationState, revokedAt } from "../src/revocation.ts";

const fixture = JSON.parse(readFileSync(new URL("fixtures/count-bindings.json", import.meta.url), "utf8"));

for (const c of fixture.cases) {
  test(`${c.id}: the Python count`, () => {
    let keyRevoked: ((kid: string, at: string) => boolean) | undefined;
    if (c.revocations !== null) {
      const state = c.revocations.lists.reduce(applyRevocationList, newRevocationState(c.revocations.rootKeyIds));
      keyRevoked = (kid, at) => revokedAt(state, "key", kid, at);
    }
    const { counted, problems } = countBindings(fixture.policy, c.bindings, fixture.at, { keyRevoked, oidcPins: c.pins });
    assert.deepEqual([[...counted].sort(), problems], c.expected);
  });
}


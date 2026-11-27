// Third independent review of the approver-list change. The fixture is the Python verifier's report on journals whose
// approver lists hold shapes the writer's differential did not generate
// (packages/probity-records/tests/test_many_approvers_verify_r7.py regenerates and compares it); this verifier must
// return it field for field.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { countBindings, verifyJournal } from "../src/verify.ts";

const cases = JSON.parse(readFileSync(new URL("fixtures/many-approvers-r7.json", import.meta.url), "utf8"));

for (const v of cases) {
  test(`${v.id} the Python report, field for field`, () => {
    assert.deepEqual(verifyJournal(v.journal, v.keys, v.checkpoint, v.trust), v.expected);
  });
}

// The OpenID Connect count: quorum.count_bindings' result on a token the pinned provider signed (Python raising is
// recorded as { raises }; the fixture's own Python test requires it never raises).
const count = JSON.parse(readFileSync(new URL("fixtures/many-approvers-r7-count.json", import.meta.url), "utf8"));
for (const c of count.cases) {
  test(`${c.id}: the Python count`, () => {
    let got: unknown;
    try {
      const { counted, problems } = countBindings(count.policy, c.bindings, count.at, { oidcPins: count.pins });
      got = [[...counted].sort(), problems];
    } catch (e) { got = { raises: String((e as Error).message) }; }
    assert.deepEqual(got, c.expected);
  });
}

// TrustDoc.revocations carries the auditor's lists: the journal reader must refuse what Python refuses with them.
for (const v of JSON.parse(readFileSync(new URL("fixtures/many-approvers-r7-revoked.json", import.meta.url), "utf8"))) {
  test(`${v.id} the Python report, field for field`, () => {
    assert.deepEqual(verifyJournal(v.journal, v.keys, v.checkpoint, v.trust), v.expected);
  });
}

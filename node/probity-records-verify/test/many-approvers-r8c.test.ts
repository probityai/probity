// Fourth independent review of the approver-list change. The fixture is the Python verifier's report on journals whose
// signed statements carry raw spellings Python's writer never prints (1e2, -0, a 30-digit integer, \u escapes, a member
// written twice) and approvals that name their approver with a value that is not a string
// (packages/probity-records/tests/test_many_approvers_verify_r8c.py regenerates and compares it); this verifier must
// return it field for field.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { verifyJournal } from "../src/verify.ts";

const cases = JSON.parse(readFileSync(new URL("fixtures/many-approvers-r8c.json", import.meta.url), "utf8"));

for (const v of cases) {
  test(`${v.id} the Python report, field for field`, () => {
    let got: unknown;
    try { got = verifyJournal(v.journal, v.keys, v.checkpoint, v.trust); } catch (e) { got = { raises: String((e as Error).message) }; }
    assert.deepEqual(got, v.expected);
  });
}

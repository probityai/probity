// Second independent review of the approver-list change. The fixture is the Python verifier's report on four journals
// (packages/probity-records/tests/test_many_approvers_verify_r5.py regenerates and compares it); this verifier must
// return it field for field.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { principalsDigest, verifyJournal } from "../src/verify.ts";

const load = (name: string) => JSON.parse(readFileSync(new URL(`fixtures/${name}`, import.meta.url), "utf8"));

for (const v of load("many-approvers-r5.json")) {
  test(`${v.id} the Python report, field for field`, () => {
    assert.deepEqual(verifyJournal(v.journal, v.keys, v.checkpoint, v.trust), v.expected);
  });
}

test("the digest orders an approver list by RFC 8785 bytes, not by UTF-16 units", () => {
  const { block, digest } = load("many-approvers-r5-digest.json");
  assert.equal(principalsDigest(block), digest);
  assert.equal(principalsDigest({ ...block, approver: [...block.approver].reverse() }), digest);
});

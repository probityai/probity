// The TypeScript half of the approver-shape differential. The fixture is the Python verifier's report on every
// generated approver shape, under the strict and the basic auditor
// (packages/probity-records/tests/test_approver_reader_diff.py builds it and checks it equals that reader's report);
// this verifier must return each report field for field, so the two readers give one verdict and one report.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { verifyJournal } from "../src/verify.ts";

const fixture = JSON.parse(readFileSync(new URL("fixtures/approver-shapes.json", import.meta.url), "utf8"));

for (const c of fixture.cases) {
  for (const [auditor, expected] of Object.entries(c.expected)) {
    test(`${c.id} [${auditor}] the Python report, field for field`, () => {
      assert.deepEqual(verifyJournal(c.journal, fixture.keys, c.checkpoint, fixture.trust[auditor]), expected);
    });
  }
}

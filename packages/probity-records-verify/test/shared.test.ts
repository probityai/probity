// The TypeScript verifier must return the Python verifier's report, field for field, on every
// shared vector the Python package generates (packages/probity-records/vectors/shared).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { checkPrincipals, verifyJournal } from "../src/verify.ts";

const dir = new URL("../../probity-records/vectors/shared/", import.meta.url);
const load = (name: string) => JSON.parse(readFileSync(new URL(name, dir), "utf8"));

const JOURNAL_FAMILIES = ["grants", "quorum", "constraints", "approvals", "effects"];
for (const family of JOURNAL_FAMILIES) {
  for (const v of load(`${family}.json`)) {
    test(`${v.id} ${v.description}`, () => {
      const got = verifyJournal(v.journal, v.keys, v.checkpoint, v.trust);
      assert.deepEqual(got, v.expected);
    });
  }
}

for (const v of load("identity.json")) {
  test(`${v.id} ${v.description}`, () => {
    const [problems, grade] = checkPrincipals(v.principals, v.at, v.pins, new Set(v.approvers));
    assert.deepEqual({ problems, grade }, { problems: v.expected.problems, grade: v.expected.grade });
  });
}

test("every family is non-empty", () => {
  for (const f of [...JOURNAL_FAMILIES.map((n) => `${n}.json`), "identity.json"]) assert.ok(load(f).length > 0, f);
});

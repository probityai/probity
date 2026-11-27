// The TypeScript half of the constraint value-key differential. The fixture is the Python reader's answer to every
// check and narrowing case (packages/probity-records/tests/test_constraint_value_key.py builds it and checks it equals
// that reader's answers): this reader must answer each one the same way, so true is never 1, 1.0 is 1 and member
// order is free in both. The fixture is parsed the way Python reads it (parsePy), so 1.0 stays a float.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { check, isFloat, narrows, parsePy } from "../src/verify.ts";

const fixture = parsePy(readFileSync(new URL("fixtures/constraint-value-key.json", import.meta.url), "utf8"));

test(`every check case answers as the Python reader does (${fixture.check.length} cases)`, () => {
  const wrong: string[] = [];
  for (const c of fixture.check) {
    const got = check(c.constraint, c.value, isFloat(c, "value", c.value));
    if (got !== c.expected) wrong.push(`${JSON.stringify(c.constraint)} on ${JSON.stringify(c.value)}: ${got} not ${c.expected}`);
  }
  assert.deepEqual(wrong.slice(0, 5), []);
  assert.equal(wrong.length, 0);
});

test(`every narrowing case answers as the Python reader does (${fixture.narrows.length} cases)`, () => {
  const wrong: string[] = [];
  for (const c of fixture.narrows) {
    const got = narrows(c.child, c.parent);
    if (got !== c.expected) wrong.push(`${JSON.stringify(c.child)} under ${JSON.stringify(c.parent)}: ${got} not ${c.expected}`);
  }
  assert.deepEqual(wrong.slice(0, 5), []);
  assert.equal(wrong.length, 0);
});

test("true is never 1, 1.0 is 1, and a deny list never admits a value jcs-admit refuses", () => {
  assert.equal(check({ type: "not_one_of", values: [1] }, true), true);
  assert.equal(check({ type: "not_one_of", values: [true] }, 1), true);
  assert.equal(check({ type: "subset", values: [1] }, [true]), false);
  assert.equal(narrows({ type: "subset", values: [true] }, { type: "subset", values: [1] }), false);
  assert.equal(narrows({ type: "subset", values: [1] }, { type: "subset", values: [true] }), false);
  assert.equal(check({ type: "not_one_of", values: ["x"] }, "\ud800"), false);
});

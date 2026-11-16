// The TypeScript verifier must return the Python verifier's report, field for field, on every
// shared vector the Python package generates (packages/probity-records/vectors/shared).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { canonicalBytes, canonicalOfReceived, checkPrincipals, parsePy, verifyJournal } from "../src/verify.ts";

const dir = new URL("../../../packages/probity-records/vectors/shared/", import.meta.url);
const load = (name: string) => JSON.parse(readFileSync(new URL(name, dir), "utf8"));

const JOURNAL_FAMILIES = ["grants", "quorum", "constraints", "approvals", "effects", "received"];
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

// Bytes and the canonical bytes, or the typed refusal, both twins report for them. "received" admits
// the bytes raw before anything parses them; "value" parses first, then canonicalizes the value.
for (const v of load("canonical.json")) {
  test(`${v.id} ${v.description}`, () => {
    const raw = Buffer.from(v.inputB64, "base64");
    let got: { canonicalHex: string } | { refused: string };
    try {
      const out = v.path === "received" ? canonicalOfReceived(raw) : canonicalBytes(parsePy(raw.toString("utf8")));
      got = { canonicalHex: out.toString("hex") };
    } catch (e) { got = { refused: (e as Error).message }; }
    assert.deepEqual(got, v.expected);
  });
}

test("every family is non-empty", () => {
  for (const f of [...JOURNAL_FAMILIES.map((n) => `${n}.json`), "identity.json", "canonical.json"]) assert.ok(load(f).length > 0, f);
});

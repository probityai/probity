// The TypeScript web_bot_auth/v1 reader must decide every case of the agent browser profile corpus
// (packages/agent-evidence-verify/vectors-web-bot-auth) as its manifest says, which is what the Python reader decides.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { CaseError, adjudicate } from "../src/webbotauth.ts";

const root = new URL("../../../packages/agent-evidence-verify/vectors-web-bot-auth/", import.meta.url);
const manifest = JSON.parse(readFileSync(new URL("MANIFEST.json", root), "utf8"));
const load = (dir: URL, name: string) => JSON.parse(readFileSync(new URL(name, dir), "utf8"));

for (const v of manifest.vectors) {
  test(`${v.id}: ${v.expected.decision} ${v.expected.reason}`, () => {
    const dir = new URL(`${v.path}/`, root);
    const got = adjudicate(load(dir, "case.json"), load(dir, "policy.json"), fileURLToPath(dir));
    assert.deepEqual({ decision: got.decision, reason: got.reason }, v.expected);
    if (v.expected.decision === "supported") {
      assert.deepEqual(got.scope.record.covered, ["@method", "@target-uri", "@authority", "content-digest", "probity-stamp-digest", "signature-agent"]);
      assert.deepEqual(got.scope.record.uncovered, []);
    }
  });
}

test("the corpus is the twelve profile cases", () => assert.equal(manifest.vectors.length, 12));

test("a pinned field that is malformed is invalid input, never a verdict", () => {
  const dir = new URL("cases/supported/", root);
  const policy = load(dir, "policy.json");
  const assessment = Object.values(policy.assessments)[0] as Record<string, unknown>;
  for (const bad of [{}, { "Probity-Stamp-Digest": "x" }, { "@method": "GET" }, { x: 1 }, null]) {
    assessment.pinned_fields = bad;
    assert.throws(() => adjudicate(load(dir, "case.json"), policy, fileURLToPath(dir)), CaseError);
  }
});

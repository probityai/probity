// A token or DPoP segment is read like probity_records.core.admitted_loads with TOKEN_MAX_DEPTH: nesting past the
// limit, a repeated member, a lone surrogate or bytes that are not UTF-8 are refused with the Python twin's code, and
// nothing recurses past the engine's stack. packages/probity-records/tests/test_untrusted_json_sweep.py holds the
// Python half of each case.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { checkDpop, judgeVerified } from "../src/verified.ts";

const dir = new URL("../../../packages/probity-records/vectors/shared/", import.meta.url);
const rows = JSON.parse(readFileSync(new URL("verified_identities.json", dir), "utf8"));
const b64u = (raw: Buffer | string): string => Buffer.from(raw).toString("base64url");

const HOSTILE: Record<string, Buffer> = {
  "deep": Buffer.from("[".repeat(20000) + "]".repeat(20000)),
  "one level past the limit": Buffer.from("[".repeat(33) + "]".repeat(33)),
  "repeated member": Buffer.from('{"a":1,"a":2}'),
  "lone surrogate": Buffer.from('{"a":"\\ud800"}'),
  "invalid utf-8": Buffer.from([0x7b, 0x22, 0x61, 0x22, 0x3a, 0x22, 0xff, 0x22, 0x7d]),
  "not an object": Buffer.from("[1]"),
};

for (const [name, hostile] of Object.entries(HOSTILE)) {
  for (const segment of [0, 1]) {
    test(`a ${name} token segment ${segment} is token_malformed`, () => {
      const row = structuredClone(rows.find((r: any) => r.id === "VI1"));
      const parts = row.tokens.agent.split(".");
      parts[segment] = b64u(hostile);
      row.tokens.agent = parts.join(".");
      assert.deepEqual(judgeVerified(row), { refused: "token_malformed" });
    });
  }
}

test("a segment exactly at the depth limit is still read", () => {
  const row = structuredClone(rows.find((r: any) => r.id === "VI1"));
  const parts = row.tokens.agent.split(".");
  parts[0] = b64u('{"a":' + "[".repeat(31) + "]".repeat(31) + "}");  // 32 containers
  row.tokens.agent = parts.join(".");
  assert.notDeepEqual(judgeVerified(row), { refused: "token_malformed" });
});

test("a DPoP header the strict reader refuses is dpop_malformed, and a repeated member keeps its own code", () => {
  const proof = (head: Buffer) => `${b64u(head)}.${b64u("{}")}.${b64u("x")}`;
  const run = (head: Buffer) => checkDpop(proof(head), "POST", "https://gw.example.com/x", "2026-11-27T00:00:00Z", "jkt", null, Buffer.alloc(0))[1];
  for (const name of ["deep", "one level past the limit", "lone surrogate", "invalid utf-8"]) assert.equal(run(HOSTILE[name]), "dpop_malformed", name);
  assert.equal(run(HOSTILE["repeated member"]), "dpop_duplicate_member");
});

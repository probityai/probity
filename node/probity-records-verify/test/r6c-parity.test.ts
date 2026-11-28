// The same hostile token and DPoP spellings the Python readers refuse, answered with the Python code
// (packages/probity-records/tests/parity_r6c holds the full differential over every shared vector row).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { checkDpop, judgeVerified } from "../src/verified.ts";

const dir = new URL("../../../packages/probity-records/vectors/shared/", import.meta.url);
const rows = JSON.parse(readFileSync(new URL("verified_identities.json", dir), "utf8"));

for (const [name, edit] of [["a space inside", (s: string) => s.slice(0, 4) + " " + s.slice(4)], ["one character too many", (s: string) => s + "A"]] as const) {
  test(`a token segment with ${name} is token_malformed, as in Python`, () => {
    const row = structuredClone(rows.find((r: any) => r.id === "VI8"));
    const parts = row.tokens.user.split(".");
    parts[1] = edit(parts[1]);
    row.tokens.user = parts.join(".");
    assert.deepEqual(judgeVerified(row), { refused: "token_malformed" });
  });
}

test("a DPoP proof whose claims segment is not ASCII is dpop_malformed", () => {
  const head = Buffer.from('{"alg":"EdDSA","typ":"dpop+jwt","jwk":{"kty":"OKP","crv":"Ed25519","x":"' + "A".repeat(43) + '"}}').toString("base64url");
  assert.equal(checkDpop(`${head}.e30é.AA`, "POST", "https://gw.example.com/x", "2026-11-27T00:00:00Z", "jkt", null, Buffer.alloc(0))[1], "dpop_malformed");
});

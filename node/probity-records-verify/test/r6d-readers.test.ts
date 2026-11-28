// Round r6d: one token has one spelling. strictB64url is probity_records.identity.unb64url, and every received
// segment (token header, claims and signature; DPoP header, claims and signature) goes through it.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { checkDpop, judgeVerified } from "../src/verified.ts";
import { strictB64url } from "../src/verify.ts";

const dir = new URL("../../../packages/probity-records/vectors/shared/", import.meta.url);
const rows = JSON.parse(readFileSync(new URL("verified_identities.json", dir), "utf8"));

test("strictB64url reads only the canonical unpadded spelling, as unb64url does", () => {
  for (const text of ["a b", "aaaaa", "aa==", "aé", "aa\n", "Zh", "a", "-_-"]) assert.throws(() => strictB64url(text), undefined, text);
  assert.deepEqual(strictB64url("YWJj"), Buffer.from("abc"));
  assert.deepEqual(strictB64url(""), Buffer.alloc(0));
});

for (const index of [0, 1, 2]) {
  for (const [name, edit] of [["a space inside", (s: string) => s.slice(0, 4) + " " + s.slice(4)], ["one character too many", (s: string) => s + "A"], ["a newline", (s: string) => s.slice(0, 3) + "\n" + s.slice(3)], ["padding", (s: string) => s + "="]] as const) {
    test(`token segment ${index} with ${name} is token_malformed`, () => {
      const row = structuredClone(rows.find((r: any) => r.id === "VI8"));
      const parts = row.tokens.user.split(".");
      parts[index] = edit(parts[index]);
      row.tokens.user = parts.join(".");
      // 86 digits are a 64-byte signature; one more is the canonical spelling of a 65-byte one, which does not verify.
      const expected = index === 2 && name === "one character too many" ? "token_signature_unverified" : "token_malformed";
      assert.deepEqual(judgeVerified(row), { refused: expected });
    });
  }
}

const head = Buffer.from('{"alg":"EdDSA","typ":"dpop+jwt","jwk":{"kty":"OKP","crv":"Ed25519","x":"' + "A".repeat(43) + '"}}').toString("base64url");
const check = (proof: string, token: string | null = null) => checkDpop(proof, "POST", "https://gw.example.com/x", "2026-11-27T00:00:00Z", "jkt", token, Buffer.alloc(0))[1];

test("a DPoP proof with text outside ASCII in any segment is dpop_malformed, whatever its length", () => {
  assert.equal(check(`${head}é.e30.AA`), "dpop_malformed");
  assert.equal(check(`${head}.e30.AAé`), "dpop_malformed");
  assert.equal(check("é".repeat(9000)), "dpop_malformed");
});

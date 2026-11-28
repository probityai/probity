// Round r6g: one list of private JWK members (verify.ts PRIVATE_JWK_MEMBERS, the twin of identity.PRIVATE_JWK_MEMBERS,
// held equal by packages/probity-records/tests/test_private_jwk_members.py). Every TypeScript key reader refuses a key
// carrying any of them, oth (RFC 7518 section 6.3.2.7) and priv included.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { checkDpop, parseBundle } from "../src/verified.ts";
import * as verify from "../src/verify.ts";

const dir = new URL("../../../packages/probity-records/vectors/shared/", import.meta.url);
const rows = JSON.parse(readFileSync(new URL("verified_identities.json", dir), "utf8"));
const vi1 = rows.find((r: { id: string }) => r.id === "VI1");
const members = (): readonly string[] => {
  const list = (verify as Record<string, unknown>).PRIVATE_JWK_MEMBERS;
  assert.ok(Array.isArray(list), "verify.ts exports no PRIVATE_JWK_MEMBERS: each reader keeps its own list");
  return list as string[];
};

test("the list is every private member of the JWK registries", () => {
  assert.deepEqual([...members()].sort(), ["d", "dp", "dq", "k", "oth", "p", "priv", "q", "qi"]);
});

for (const member of ["d", "p", "q", "dp", "dq", "qi", "oth", "k", "priv"]) {
  test(`a bundle key carrying ${member} is refused`, () => {
    const doc = structuredClone(vi1.bundle);
    const issuer = Object.keys(doc.issuers).find((u) => u.startsWith("https://"))!;
    doc.issuers[issuer].keys[0][member] = "AQAB";
    assert.throws(() => parseBundle(doc), (e: Error & { code?: string }) => e.code === "trust_bundle_malformed");
  });
  test(`a DPoP header key carrying ${member} is refused`, () => {
    const jwk = { kty: "OKP", crv: "Ed25519", x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo", [member]: "AQAB" };
    const head = Buffer.from(JSON.stringify({ typ: "dpop+jwt", alg: "EdDSA", jwk })).toString("base64url");
    const [, reason] = checkDpop(`${head}.e30.AA`, "POST", "https://a.example/x", "2026-11-23T12:00:00Z", "x".repeat(43), null, Buffer.alloc(0));
    assert.equal(reason, "dpop_jwk_private");
  });
}

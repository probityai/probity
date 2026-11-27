// Round r6e: one public key has one spelling. publicJwk is probity_records.identity.public_jwk: canonical base64url
// members, full-size curve coordinates, RSA n and e without a leading zero octet. A bundle that pins a second spelling
// of a key is trust_bundle_malformed in both readers (the differential in tests/parity_r6c covers every shared row).
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { judgeVerified } from "../src/verified.ts";
import { jwkThumbprint, publicJwk } from "../src/verify.ts";

const dir = new URL("../../../packages/probity-records/vectors/shared/", import.meta.url);
const rows = JSON.parse(readFileSync(new URL("verified_identities.json", dir), "utf8"));
const b64u = (b: Buffer): string => b.toString("base64url");
const EDITS: Record<string, (s: string) => unknown> = {
  padded: (s) => s + "=".repeat((4 - (s.length % 4)) % 4 || 4),
  space: (s) => s.slice(0, 4) + " " + s.slice(4),
  newline: (s) => s.slice(0, 4) + "\n" + s.slice(4),
  "stray-bits": (s) => s.slice(0, -1) + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".indexOf(s.at(-1)!) | 1],
  "leading-zero": (s) => b64u(Buffer.concat([Buffer.alloc(1), Buffer.from(s, "base64url")])),
  short: (s) => b64u(Buffer.from(s, "base64url").subarray(1)),
  "not-a-string": (s) => s.length,
};
const lenientThumbprint = (jwk: any): string =>
  createHash("sha256").update(JSON.stringify(jwk.kty === "RSA" ? { e: jwk.e, kty: jwk.kty, n: jwk.n } : { crv: jwk.crv, kty: jwk.kty, x: jwk.x })).digest("base64url");

const OKP = { crv: "Ed25519", kty: "OKP", x: "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w" };

for (const [name, edit] of Object.entries(EDITS)) {
  test(`publicJwk and jwkThumbprint refuse an Ed25519 x with ${name}`, () => {
    const jwk = { ...OKP, x: edit(OKP.x) };
    assert.throws(() => publicJwk(jwk));
    assert.throws(() => jwkThumbprint(jwk));
  });
  for (const issuer of ["https://idp.example.com/realms/agents", "gateway.example.com/t/acme", "https://sso.example.net"]) {
    test(`a bundle key of ${issuer} with ${name} is trust_bundle_malformed`, () => {
      const row = structuredClone(rows.find((r: any) => r.id === "VI8"));
      const entry = row.bundle.issuers[issuer];
      const key = entry.keys[0];
      const old = lenientThumbprint(key);
      const member = key.kty === "RSA" ? "n" : "x";
      key[member] = edit(key[member]);
      for (const pin of entry.pins) if (pin.thumbprint === old) pin.thumbprint = lenientThumbprint(key);
      assert.deepEqual(judgeVerified(row), { refused: "trust_bundle_malformed" });
    });
  }
}

test("an unknown curve has no thumbprint", () => assert.throws(() => jwkThumbprint({ ...OKP, crv: "X25519" })));

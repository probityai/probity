// The TypeScript reader of the one signed revocation list must give the Python reader's verdict on every
// shared vector (packages/probity-records/vectors/shared/revocation.json): the refusal code and the index of the
// refused list, or the state summary, with the lists applied one at a time in the given order.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { generateKeyPairSync, sign } from "node:crypto";
import * as rev from "../src/revocation.ts";
import { applyRevocationList, newRevocationState, revocationSummary, revoked, REFUSAL_CODES, REVOCATION_LIST } from "../src/revocation.ts";
import { canonicalBytes, jwkThumbprint, sha256Hex } from "../src/verify.ts";

const dir = new URL("../../../packages/probity-records/vectors/shared/", import.meta.url);
const vectors = JSON.parse(readFileSync(new URL("revocation.json", dir), "utf8"));

for (const v of vectors) {
  test(`${v.id} ${v.description}`, () => {
    let state = newRevocationState(v.roots);
    let got: unknown = null;
    for (const [index, signed] of v.lists.entries()) {
      try {
        state = applyRevocationList(state, signed);
      } catch (e) {
        got = { refused: (e as Error).message.split(":")[0], index };
        break;
      }
    }
    assert.deepEqual(got ?? { state: revocationSummary(state) }, v.expected);
  });
}

test("the vectors cover every refusal code and both kinds of verdict", () => {
  const refused = new Set(vectors.filter((v: { expected: { refused?: string } }) => v.expected.refused).map((v: { expected: { refused: string } }) => v.expected.refused));
  assert.deepEqual([...refused].sort(), [...REFUSAL_CODES].sort());
  assert.ok(vectors.some((v: { expected: { state?: unknown } }) => v.expected.state));
});

test("a refused list leaves the state unchanged", () => {
  const v = vectors.find((x: { id: string }) => x.id === "RL34");
  let state = newRevocationState(v.roots);
  for (const signed of v.lists.slice(0, v.expected.index)) state = applyRevocationList(state, signed);
  const before = revocationSummary(state);
  assert.throws(() => applyRevocationList(state, v.lists[v.expected.index]), /^Error: revocation_list_drops_entry/);
  assert.deepEqual(revocationSummary(state), before);
});

// ---------- identity provider signing keys: kind "idp-key", named by RFC 7638 thumbprint ----------

/** The RFC 7638 thumbprint of the RFC 8037 appendix A Ed25519 key, as RFC 8037 A.3 states it. */
const RFC8037_JWK = { kty: "OKP", crv: "Ed25519", x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo" };
const THUMBPRINT = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k";
const B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
/** Each id an idp-key entry must refuse, the same set as the Python reader's tests. */
const BAD_THUMBPRINTS: Record<string, string> = {
  "42 characters": THUMBPRINT.slice(0, -1),
  "44 characters": THUMBPRINT + "A",
  padded: THUMBPRINT + "=",
  "padding inside 43 characters": THUMBPRINT.slice(0, -1) + "=",
  "a padding character among the digits": THUMBPRINT.slice(0, 20) + "=" + THUMBPRINT.slice(21),
  "a 64-hex key id": "ab".repeat(32),
  "the standard base64 alphabet": THUMBPRINT.replace("_", "/"),
  "nonzero unused bits in the last digit": THUMBPRINT.slice(0, -1) + B64URL[B64URL.indexOf(THUMBPRINT.slice(-1)) | 1],
  empty: "",
};

const root = generateKeyPairSync("ed25519");
const rootRaw = Buffer.from(root.publicKey.export({ format: "jwk" }).x as string, "base64url");
const rootId = sha256Hex(rootRaw);

/** A seq-1 list holding `entries`, signed by the test root whatever its shape. */
function signedList(entries: object[], issuedAt = "2026-05-02T00:00:00Z"): object {
  const body = { entries, issuedAt, issuerKey: rootRaw.toString("base64"), listId: "rl", previous: null, seq: 1, type: REVOCATION_LIST };
  const sig = sign(null, Buffer.concat([Buffer.from("probity-revocation-v1\u0000", "latin1"), canonicalBytes(body)]), root.privateKey);
  return { body, sig: sig.toString("base64") };
}

test("the thumbprint constant is RFC 8037's", () => {
  assert.equal(jwkThumbprint(RFC8037_JWK), THUMBPRINT);
});

test("an idp-key entry is read by its thumbprint", () => {
  const entry = { kind: "idp-key", id: THUMBPRINT, revokedAt: "2026-05-01T00:00:00Z", reason: "signing key leaked" };
  const state = applyRevocationList(newRevocationState([rootId]), signedList([entry]));
  assert.ok(revoked(state, "idp-key", THUMBPRINT));
  assert.ok(!revoked(state, "key", THUMBPRINT));
  assert.deepEqual(revocationSummary(state).revoked["idp-key"], [THUMBPRINT]);
});

test("idpKeyRevoked holds at and after revokedAt only", () => {
  const entry = { kind: "idp-key", id: THUMBPRINT, revokedAt: "2026-05-01T00:00:00Z" };
  const state = applyRevocationList(newRevocationState([rootId]), signedList([entry]));
  assert.equal(rev.idpKeyRevoked(state, THUMBPRINT, "2026-04-30T23:59:59Z"), false);
  assert.equal(rev.idpKeyRevoked(state, THUMBPRINT, "2026-05-01T00:00:00Z"), true);
  assert.equal(rev.idpKeyRevoked(state, THUMBPRINT, "2026-05-01T01:00:00+01:00"), true);
  assert.equal(rev.idpKeyRevoked(state, THUMBPRINT, "2026-06-01T00:00:00Z"), true);
  assert.equal(rev.idpKeyRevoked(state, THUMBPRINT.slice(0, -1) + "A", "2026-06-01T00:00:00Z"), false);
  assert.equal(rev.revokedAt(state, "key", THUMBPRINT, "2026-06-01T00:00:00Z"), false);
});

for (const [why, id] of Object.entries(BAD_THUMBPRINTS)) {
  test(`an idp-key id is refused: ${why}`, () => {
    const list = signedList([{ kind: "idp-key", id, revokedAt: "2026-05-01T00:00:00Z" }]);
    assert.throws(() => applyRevocationList(newRevocationState([rootId]), list), /^Error: revocation_list_shape:entry_id_form:idp-key$/);
  });
}

test("a thumbprint never names a key entry", () => {
  const list = signedList([{ kind: "key", id: THUMBPRINT, revokedAt: "2026-05-01T00:00:00Z" }]);
  assert.throws(() => applyRevocationList(newRevocationState([rootId]), list), /^Error: revocation_list_shape:entry_id_form:key$/);
});

test("an idp-key entry carries no successor", () => {
  const list = signedList([{ kind: "idp-key", id: THUMBPRINT, revokedAt: "2026-05-01T00:00:00Z", successor: rootRaw.toString("base64") }]);
  assert.throws(() => applyRevocationList(newRevocationState([rootId]), list), /^Error: revocation_list_shape:successor_on_non_key_entry$/);
});

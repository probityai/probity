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
  assert.throws(() => applyRevocationList(state, v.lists[v.expected.index]), /^Error: revocation_entry_repeated:/);
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
  return chainedList(entries, 1, null, issuedAt);
}

/** List `seq` of the test root's chain, holding `entries` (the delta) after `previous`, signed whatever its shape. */
function chainedList(entries: object[], seq: number, previous: any, issuedAt = "2026-05-02T00:00:00Z", type: string = REVOCATION_LIST): any {
  const body = { entries, issuedAt, issuerKey: rootRaw.toString("base64"), listId: "rl",
    previous: previous === null ? null : rev.listDigest(previous.body), seq, type };
  const sig = sign(null, Buffer.concat([Buffer.from("probity-revocation-v1\u0000", "latin1"), canonicalBytes(body)]), root.privateKey);
  return { body, sig: sig.toString("base64") };
}

const agent = (id: string, revokedAt = "2026-05-01T00:00:00Z") => ({ kind: "agent", id, revokedAt });
const agentsOf = (state: rev.RevocationState): string[] => revocationSummary(state).revoked.agent;

// ---------- delta lists: each list carries only what it newly revokes ----------

test("the list type is v2 and a v1 list is refused for its type", () => {
  assert.ok(REVOCATION_LIST.endsWith("agent-evidence-vectors/predicate/v2/revocation-list"));
  const v1 = chainedList([], 1, null, undefined, REVOCATION_LIST.replace("/v2/", "/v1/"));
  assert.throws(() => applyRevocationList(newRevocationState([rootId]), v1), /^Error: revocation_list_shape:type$/);
});

test("the refusal codes are the delta format's", () => {
  assert.ok(!(REFUSAL_CODES as readonly string[]).includes("revocation_list_drops_entry"));
  assert.deepEqual(REFUSAL_CODES.slice(-2), ["revocation_entry_from_future", "revocation_entry_repeated"]);
});

test("deltas fold to the union, and an empty delta is a freshness list", () => {
  const one = chainedList([agent("agent:a", "1999-01-01T00:00:00Z")], 1, null);
  const two = chainedList([agent("agent:b")], 2, one);
  const three = chainedList([], 3, two, "2026-05-03T00:00:00Z");
  let state = newRevocationState([rootId]);
  for (const signed of [one, two, three]) state = applyRevocationList(state, signed);
  assert.deepEqual(agentsOf(state), ["agent:a", "agent:b"]);
  assert.equal(state.seq, 3);
  assert.equal(state.issuedAt, "2026-05-03T00:00:00Z");
  assert.equal(state.entries.size, 2);
  assert.equal(rev.revokedAt(state, "agent", "agent:a", "1999-06-01T00:00:00Z"), true);
  assert.equal(rev.revokedAt(state, "agent", "agent:b", "1999-06-01T00:00:00Z"), false);
});

for (const [edit, again] of Object.entries({
  same: agent("agent:a"),
  retime: agent("agent:a", "1999-01-01T00:00:00Z"),
  reason: { ...agent("agent:a"), reason: "found" },
})) {
  test(`a list naming a subject an earlier list revoked is refused: ${edit}`, () => {
    const one = chainedList([agent("agent:a")], 1, null);
    const state = applyRevocationList(newRevocationState([rootId]), one);
    const bad = chainedList([again, agent("agent:z")], 2, one);
    assert.throws(() => applyRevocationList(state, bad), /^Error: revocation_entry_repeated:agent:agent:a$/);
    assert.equal(state.seq, 1);
    assert.equal(revoked(state, "agent", "agent:z"), false);
  });
}

test("an older state never sees a later list's entries", () => {
  const one = chainedList([agent("agent:a")], 1, null);
  const two = chainedList([agent("agent:b")], 2, one);
  const s1 = applyRevocationList(newRevocationState([rootId]), one);
  const s2 = applyRevocationList(s1, two);
  assert.deepEqual(agentsOf(s1), ["agent:a"]);
  assert.deepEqual([...s1.entries.keys()], ["agent\u0000agent:a"]);
  assert.equal(s1.entries.size, 1);
  assert.equal(s1.entries.has("agent\u0000agent:b"), false);
  assert.equal(s1.entries.get("agent\u0000agent:b"), undefined);
  assert.deepEqual(agentsOf(s2), ["agent:a", "agent:b"]);
});

test("two successors of one state are both correct", () => {
  const one = chainedList([agent("agent:a")], 1, null);
  const base = applyRevocationList(newRevocationState([rootId]), one);
  const rightList = chainedList([agent("agent:c")], 2, one);
  const left = applyRevocationList(base, chainedList([agent("agent:b")], 2, one));
  const right = applyRevocationList(base, rightList);
  const rightNext = applyRevocationList(right, chainedList([agent("agent:b")], 3, rightList));
  assert.deepEqual(agentsOf(base), ["agent:a"]);
  assert.deepEqual(agentsOf(left), ["agent:a", "agent:b"]);
  assert.deepEqual(agentsOf(right), ["agent:a", "agent:c"]);
  assert.deepEqual(agentsOf(rightNext), ["agent:a", "agent:b", "agent:c"]);
});

test("a refused list adds nothing to any state", () => {
  const one = chainedList([agent("agent:a")], 1, null);
  const base = applyRevocationList(newRevocationState([rootId]), one);
  assert.throws(() => applyRevocationList(base, chainedList([agent("agent:a"), agent("agent:z")], 2, one)), /revocation_entry_repeated/);
  const after = applyRevocationList(base, chainedList([agent("agent:y")], 2, one));
  assert.deepEqual(agentsOf(after), ["agent:a", "agent:y"]);
  assert.equal(revoked(base, "agent", "agent:z"), false);
});

test("a state built with a plain Map still applies", () => {
  const one = chainedList([agent("agent:a")], 1, null);
  const held = new Map([["agent\u0000agent:a", agent("agent:a")]]);
  const state: rev.RevocationState = { roots: new Set([rootId]), listId: "rl", seq: 1, head: rev.listDigest(one.body),
    issuedAt: "2026-05-02T00:00:00Z", entries: held };
  const after = applyRevocationList(state, chainedList([agent("agent:b")], 2, one));
  assert.deepEqual(agentsOf(after), ["agent:a", "agent:b"]);
  assert.equal(held.size, 1);
});

test("a successor revoked by an earlier list never becomes a root", () => {
  const next = generateKeyPairSync("ed25519");
  const nextRaw = Buffer.from(next.publicKey.export({ format: "jwk" }).x as string, "base64url");
  const nextId = sha256Hex(nextRaw);
  const one = chainedList([{ kind: "key", id: nextId, revokedAt: "2026-05-01T00:00:00Z" }], 1, null);
  const two = chainedList([{ kind: "key", id: rootId, revokedAt: "2026-05-01T00:00:00Z", successor: nextRaw.toString("base64") }], 2, one);
  let state = newRevocationState([rootId]);
  for (const signed of [one, two]) state = applyRevocationList(state, signed);
  assert.deepEqual([...state.roots], []);
});

/** Median milliseconds to apply a one-entry delta onto a state already holding `held` entries. */
function deltaApplyMs(held: number, runs = 21): number {
  const first = chainedList(Array.from({ length: held }, (_, i) => agent(`agent:${String(i).padStart(7, "0")}`)), 1, null);
  let state = applyRevocationList(newRevocationState([rootId]), first);
  let previous = first;
  const times: number[] = [];
  for (let n = 0; n < runs; n++) {
    const signed = chainedList([{ kind: "stream", id: `stream:${String(n).padStart(3, "0")}`, revokedAt: "2026-05-01T00:00:00Z" }], n + 2, previous);
    const start = performance.now();
    state = applyRevocationList(state, signed);
    times.push(performance.now() - start);
    previous = signed;
  }
  assert.equal(state.entries.size, held + runs);
  return times.sort((a, b) => a - b)[Math.floor(runs / 2)];
}

test("applying a delta does not grow with the entries already revoked", () => {
  const small = deltaApplyMs(1_000);
  const large = deltaApplyMs(100_000);
  assert.ok(large < 3 * small, `${small} ms at 1,000, ${large} ms at 100,000`);
});

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

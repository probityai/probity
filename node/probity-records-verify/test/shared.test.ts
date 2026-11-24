// The TypeScript verifier must return the Python verifier's report, field for field, on every
// shared vector the Python package generates (packages/probity-records/vectors/shared).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { covers, verifyDelegation } from "../src/delegation.ts";
import { judgeVerified } from "../src/verified.ts";
import { bodyProblem, canonicalBytes, canonicalOfReceived, chainDigests, checkPrincipals, judgeDigest, judgeIdentity, parsePy, verifyGrantAllow, verifyJournal } from "../src/verify.ts";

const dir = new URL("../../../packages/probity-records/vectors/shared/", import.meta.url);
const load = (name: string) => JSON.parse(readFileSync(new URL(name, dir), "utf8"));

const JOURNAL_FAMILIES = ["grants", "autonomous", "quorum", "constraints", "approvals", "identities", "effects", "received"];
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
    const approvers = v.approvers === null ? null : new Set<string>(v.approvers);
    const [problems, grade] = checkPrincipals(v.principals, v.at, v.pins, approvers,
      { sponsors: v.sponsors === undefined ? undefined : v.sponsors, standingGrants: v.standingGrants ?? {} });
    assert.deepEqual({ problems, grade }, { problems: v.expected.problems, grade: v.expected.grade });
  });
}

// Standing grants: the same allow or refusal, and the same resolved digests, for every chain.
for (const v of load("standing_grants.json")) {
  test(`${v.id} ${v.description}`, () => {
    const { decision, reason, grantDigest } = verifyGrantAllow(v.chain, v.tool, v.args, v.at, new Set(v.roots));
    const digests = Object.keys(chainDigests(v.chain, new Set(v.roots))).sort();
    assert.deepEqual({ decision, reason, grantDigest, digests }, v.expected);
  });
}

// The grant body grammar: the code grants.validate_body names, or null. parsePy keeps 1.0 a float, as Python does.
const loadPy = (name: string) => parsePy(readFileSync(new URL(name, dir), "utf8"));
for (const v of loadPy("grant_bodies.json")) {
  test(`${v.id} ${v.description}`, () => assert.equal(bodyProblem(v.body), v.expected));
}
for (const v of loadPy("grant_calls.json")) {
  test(`${v.id} ${v.description}`, () => {
    const { decision, reason } = verifyGrantAllow(v.chain, v.tool, v.args, v.at, new Set(v.roots), v.ctx);
    assert.deepEqual({ decision, reason }, v.expected);
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

// The canonical identity string: the same outcome, or the same refusal code, for every string and document.
for (const v of load("canonical_identity.json")) {
  test(`${v.id} ${v.description}`, () => {
    assert.deepEqual(judgeIdentity(v.direction, v.input), v.expected);
  });
}

// The identity digests: the same digest, or the same refusal code and reason, for every input.
for (const v of load("identity_digests.json")) {
  test(`${v.id} ${v.description}`, () => {
    assert.deepEqual(judgeDigest(v.function, v.input), v.expected);
  });
}

// The verified identities of a request: the same identities and spend values, or the same refusal code.
for (const v of load("verified_identities.json")) {
  test(`${v.id} ${v.description}`, () => {
    assert.deepEqual(judgeVerified(v), v.expected);
  });
}

test("every family is non-empty", () => {
  for (const f of [...JOURNAL_FAMILIES.map((n) => `${n}.json`), "identity.json", "standing_grants.json", "grant_bodies.json", "grant_calls.json", "canonical.json", "canonical_identity.json", "identity_digests.json", "verified_identities.json"]) assert.ok(load(f).length > 0, f);
});

// Session-key certificates (probity-key-delegation/v2): the same scope and window, or the same refusal code, and the
// same half-open answer for every instant. parsePy keeps windowS 600.0 a float, as Python does.
for (const v of loadPy("delegation.json")) {
  test(`${v.id} ${v.description}`, () => {
    const roots = v.roots.map((r: string) => Buffer.from(r, "base64"));
    let got: object;
    let answers: boolean[] = [];
    try {
      const d = verifyDelegation(v.certificate, roots);
      got = { delegation: { custody: d.custody, hierarchy: d.hierarchy, notAfter: d.notAfter, notBefore: d.notBefore,
        rootKeyId: d.rootKeyId, sessionKeyId: d.sessionKeyId, tenant: d.tenant, windowS: d.windowS } };
      answers = v.covers.map((c: { at: string }) => covers(d, c.at));
    } catch (e) { got = { refused: (e as Error).message }; }
    assert.deepEqual(got, v.expected);
    assert.deepEqual(answers, v.covers.map((c: { expected: boolean }) => c.expected));
  });
}

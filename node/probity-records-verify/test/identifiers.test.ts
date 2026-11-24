// One host constant, two recognised spellings (see src/identifiers.ts for why both are ours). The unit tests pin the
// three functions; the reader tests move every shared vector to the probityai.org spelling, re-sign it with the
// vectors' own test keys and require the verdict, every reason code and every failure line to be identical.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { canonicalIdentifier, identifier, IDENTIFIER_HOST, RECOGNISED_HOSTS, sameIdentifier } from "../src/identifiers.ts";
import { judgeApprovalBinding, judgeUncertainEffect, parseReceived, TOOL_CALL_RECORD, verifyJournal } from "../src/verify.ts";
import { applyRevocationList, newRevocationState, REVOCATION_LIST, revocationSummary } from "../src/revocation.ts";
import { HTTP, NEW, OLD, OTHER, rehost, rehostJournal, rehostRevocations } from "./rehost.ts";

const dir = new URL("../../../packages/probity-records/vectors/shared/", import.meta.url);
const load = (name: string) => JSON.parse(readFileSync(new URL(name, dir), "utf8"));

// ---------- the three functions ----------

test("the host we write is the old one until the release that flips it, and both hosts are recognised", () => {
  assert.equal(IDENTIFIER_HOST, "probityai.github.io");
  assert.deepEqual([...RECOGNISED_HOSTS], ["probityai.github.io", "probityai.org"]);
});

test("identifier builds an identifier under the host we write", () => {
  assert.equal(identifier("agent-evidence-vectors/predicate/v1/tool-call-record"), `${OLD}agent-evidence-vectors/predicate/v1/tool-call-record`);
  assert.equal(TOOL_CALL_RECORD, `${OLD}agent-evidence-vectors/predicate/v1/tool-call-record`);
  assert.equal(REVOCATION_LIST, `${OLD}agent-evidence-vectors/predicate/v1/revocation-list`);
});

const FAMILIES = [
  "agent-evidence-vectors/predicate/v1/tool-call-record", "agent-evidence-vectors/predicate/v2/tool-call-record",
  "agent-evidence-vectors/contract/approval-binding/v1", "agent-evidence-vectors/predicate/v1/uncertain-effect",
  "agent-evidence-vectors/predicate/v1/revocation-list", "agent-evidence-vectors/schema/verdict-line/v1",
  "agent-evidence-vectors/vocab/v1/outcome", "agent-evidence-vectors/evaluator/v1/replay", "",
];

test("a recognised spelling maps to the host we write, the rest of the string unchanged", () => {
  for (const path of FAMILIES) {
    assert.equal(canonicalIdentifier(`${NEW}${path}`), `${OLD}${path}`);
    assert.equal(canonicalIdentifier(`${OLD}${path}`), `${OLD}${path}`);
  }
  assert.equal(canonicalIdentifier(`${NEW}a/b?q=1#frag`), `${OLD}a/b?q=1#frag`);
  assert.equal(canonicalIdentifier(`${NEW}https://probityai.org/x`), `${OLD}https://probityai.org/x`, "only the leading host moves");
});

const REFUSED = [
  "http://probityai.org/x", "http://probityai.github.io/x", "HTTPS://probityai.org/x", "https://PROBITYAI.ORG/x",
  "https://Probityai.org/x", "https://www.probityai.org/x", "https://probityai.org:443/x", "https://probityai.org./x",
  "https://user@probityai.org/x", "https://probityai.org@example.invalid/x", "https://probityai.org.example/x",
  "https://probityai.organisation/x", "https://xprobityai.org/x", "https://probityai.org", "https://probityai.org\\x",
  " https://probityai.org/x", "https://probityai.org x", "https://example.invalid/probityai.org/x",
  "probityai.org/x", "//probityai.org/x", "https://probityai.github.io.example/x", "https://www.probityai.github.io/x",
];

test("every other spelling stays unrecognised and comes back unchanged", () => {
  for (const s of REFUSED) assert.equal(canonicalIdentifier(s), s, s);
});

test("a value that is not a string comes back as it was", () => {
  for (const v of [null, undefined, 1, 1.5, true, ["x"], { a: `${NEW}x` }]) assert.equal(canonicalIdentifier(v), v);
});

test("sameIdentifier is true across the two hosts and false for every refused spelling", () => {
  for (const path of FAMILIES) {
    assert.ok(sameIdentifier(`${OLD}${path}`, `${NEW}${path}`));
    assert.ok(sameIdentifier(`${NEW}${path}`, `${OLD}${path}`));
    assert.ok(sameIdentifier(`${NEW}${path}`, `${NEW}${path}`));
    assert.ok(!sameIdentifier(`${OLD}${path}`, `${OLD}${path}x`));
  }
  for (const s of REFUSED) assert.ok(!sameIdentifier(`${OLD}x`, s), s);
  assert.ok(!sameIdentifier(`${OLD}a`, `${NEW}b`));
  assert.ok(!sameIdentifier(undefined, TOOL_CALL_RECORD));
  assert.ok(!sameIdentifier(null, TOOL_CALL_RECORD));
});

// ---------- the readers ----------

const JOURNAL_FAMILIES = ["grants", "autonomous", "quorum", "constraints", "approvals", "identities", "effects", "received"];

function report(v: any, spelling: { from: string; to: string }): { got: unknown; rewritten: number } {
  const moved = rehostJournal(v.journal, v.checkpoint, spelling.from, spelling.to);
  let got: unknown;
  try { got = verifyJournal(moved.lines, v.keys, moved.checkpoint, v.trust); } catch (e) { got = { threw: (e as Error).message }; }
  return { got, rewritten: moved.rewritten };
}

for (const family of JOURNAL_FAMILIES) {
  test(`${family}: every journal under the probityai.org spelling gets the verdict, failures and checkpoint it gets under the old one`, () => {
    let compared = 0, moved = 0;
    for (const v of load(`${family}.json`)) {
      const base = report(v, { from: OLD, to: OLD });
      const same = report(v, { from: OLD, to: NEW });
      assert.deepEqual(same.got, base.got, `${v.id} ${v.description}`);
      compared++;
      if (same.rewritten > 0) moved++;
    }
    assert.ok(compared > 0);
    assert.ok(moved > 0, `${family}: no journal had a line rewritten, so nothing was compared`);
  });

  test(`${family}: the http spelling is unknown and fails as a wholly unknown host fails`, () => {
    for (const v of load(`${family}.json`)) {
      const unknown = report(v, { from: OLD, to: OTHER });
      const http = report(v, { from: OLD, to: HTTP });
      assert.deepEqual(http.got, unknown.got, `${v.id} ${v.description}`);
    }
  });
}

test("the http spelling is not read as ours: some journal is judged differently from its probityai.org twin", () => {
  let differing = 0;
  for (const family of JOURNAL_FAMILIES) {
    for (const v of load(`${family}.json`)) {
      const http = report(v, { from: OLD, to: HTTP }).got, canon = report(v, { from: OLD, to: NEW }).got;
      try { assert.deepEqual(http, canon); } catch { differing++; }
    }
  }
  assert.ok(differing > 0, "no journal told the two spellings apart, so the http comparison above proves nothing");
});

function embeddedRecords(): { approvals: [any, Buffer][]; effects: any[] } {
  const approvals: [any, Buffer][] = [], effects: any[] = [];
  for (const family of JOURNAL_FAMILIES) {
    for (const v of load(`${family}.json`)) {
      for (const line of v.journal) {
        let pred: any;
        try { pred = parseReceived(Buffer.from(JSON.parse(line).payload, "base64")).predicate; } catch { continue; }
        for (const b of pred?.approvalBindings ?? []) if (b?.record && typeof b.payloadB64 === "string") approvals.push([b.record, Buffer.from(b.payloadB64, "base64")]);
        if (pred?.uncertainEffect && typeof pred.uncertainEffect === "object") effects.push(pred.uncertainEffect);
      }
    }
  }
  return { approvals, effects };
}

const outcome = (f: () => unknown): unknown => { try { return f(); } catch (e) { return { threw: (e as Error).message }; } };

test("approval-binding: a record naming its contract under probityai.org is judged as the old spelling is", () => {
  const { approvals } = embeddedRecords();
  assert.ok(approvals.length >= 10, `${approvals.length} embedded records`);
  let named = 0;
  for (const [record, payload] of approvals) {
    const base = outcome(() => judgeApprovalBinding(record, payload));
    assert.deepEqual(outcome(() => judgeApprovalBinding(rehost(record, OLD, NEW), payload)), base);
    assert.deepEqual(outcome(() => judgeApprovalBinding(rehost(record, OLD, HTTP), payload)), outcome(() => judgeApprovalBinding(rehost(record, OLD, OTHER), payload)));
    if (typeof record.contractId === "string" && record.contractId.startsWith(OLD)) named++;
  }
  assert.ok(named >= 10, `${named} records name their contract under the old host`);
});

test("approval-binding: the http spelling of the contract is refused as an unknown contract", () => {
  const { approvals } = embeddedRecords();
  const [record, payload] = approvals.find(([r]) => (r as any).contractId?.startsWith(OLD))!;
  const bad = { ...record, contractId: record.contractId.replace(OLD, HTTP) };
  assert.equal((judgeApprovalBinding(bad, payload) as any).reason, "contract_id_unknown");
  assert.equal((judgeApprovalBinding({ ...record, contractId: record.contractId.replace(OLD, NEW) }, payload) as any).reason,
    (judgeApprovalBinding(record, payload) as any).reason);
});

test("uncertain-effect: a record naming its contract under probityai.org is judged as the old spelling is", () => {
  const { effects } = embeddedRecords();
  assert.ok(effects.length >= 10, `${effects.length} embedded records`);
  let named = 0;
  for (const record of effects) {
    const base = outcome(() => judgeUncertainEffect(record));
    assert.deepEqual(outcome(() => judgeUncertainEffect(rehost(record, OLD, NEW))), base);
    assert.deepEqual(outcome(() => judgeUncertainEffect(rehost(record, OLD, HTTP))), outcome(() => judgeUncertainEffect(rehost(record, OLD, OTHER))));
    if (typeof record.contractId === "string" && record.contractId.startsWith(OLD)) named++;
  }
  assert.ok(named >= 10, `${named} records name their contract under the old host`);
});

test("uncertain-effect: the http spelling of the contract is refused as an unknown contract", () => {
  const record = embeddedRecords().effects.find((r) => typeof r.contractId === "string" && r.contractId.startsWith(OLD))!;
  const bad = judgeUncertainEffect({ ...record, contractId: record.contractId.replace(OLD, HTTP) });
  assert.equal(bad.reason, "contract_id_unknown");
});

function applyAll(roots: string[], lists: any[]): unknown {
  let state = newRevocationState(roots);
  for (const [index, signed] of lists.entries()) {
    try { state = applyRevocationList(state, signed); } catch (e) { return { refused: (e as Error).message.split(":")[0], index }; }
  }
  // The head is a digest of the list's own bytes, which differ by spelling; the chain it links is proved by the lists applying.
  return { state: { ...revocationSummary(state), head: state.head === null ? null : "sha256:<digest of the list in force>" } };
}

test("revocation: every list under the probityai.org spelling gets the verdict it gets under the old one", () => {
  let moved = 0;
  for (const v of load("revocation.json")) {
    const base = applyAll(v.roots, v.lists);
    const same = rehostRevocations(v.lists, OLD, NEW);
    assert.deepEqual(applyAll(v.roots, same.lists), base, `${v.id} ${v.description}`);
    if (same.rewritten > 0) moved++;
    const http = rehostRevocations(v.lists, OLD, HTTP);
    const other = rehostRevocations(v.lists, OLD, OTHER);
    assert.deepEqual(applyAll(v.roots, http.lists), applyAll(v.roots, other.lists), `${v.id} http`);
  }
  assert.ok(moved >= 10, `${moved} vectors had a list rewritten`);
});

test("revocation: a list typed with the http spelling is refused as a shape fault", () => {
  const v = load("revocation.json").find((x: any) => x.id === "RL01");
  const http = rehostRevocations(v.lists, OLD, HTTP);
  assert.deepEqual(applyAll(v.roots, http.lists), { refused: "revocation_list_shape", index: 0 });
});

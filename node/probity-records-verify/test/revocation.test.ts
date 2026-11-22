// The TypeScript reader of the one signed revocation list must give the Python reader's verdict on every
// shared vector (packages/probity-records/vectors/shared/revocation.json): the refusal code and the index of the
// refused list, or the state summary, with the lists applied one at a time in the given order.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { applyRevocationList, newRevocationState, revocationSummary, REFUSAL_CODES } from "../src/revocation.ts";

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

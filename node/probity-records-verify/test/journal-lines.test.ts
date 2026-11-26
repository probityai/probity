// A journal's records are its whole lines: a torn tail a writer killed mid-append left is counted apart, never read,
// as the Python reader does (probity_records.journal._whole_lines).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { journalLines, verifyJournal, verifyJournalText } from "../src/verify.ts";

const dir = new URL("../../../packages/probity-records/vectors/shared/", import.meta.url);
const load = (name: string) => JSON.parse(readFileSync(new URL(name, dir), "utf8"));

test("the bytes after the last newline are not a line and are counted apart", () => {
  assert.deepEqual(journalLines(""), { lines: [], tornTailBytes: 0 });
  assert.deepEqual(journalLines("a\nb\n"), { lines: ["a", "b"], tornTailBytes: 0 });
  assert.deepEqual(journalLines("a\nb\n{\"pay"), { lines: ["a", "b"], tornTailBytes: 5 });
  assert.deepEqual(journalLines("{\"payload\":\"é"), { lines: [], tornTailBytes: 14 });
  assert.deepEqual(journalLines("a\n\nb\n"), { lines: ["a", "", "b"], tornTailBytes: 0 });
});

test("a shared journal with a torn tail verifies as the journal without it", () => {
  for (const v of load("grants.json")) {
    const whole = v.journal.map((line: string) => line + "\n").join("");
    const last: string = v.journal.at(-1) ?? "";
    for (const cut of [1, Math.floor(last.length / 2), last.length]) {
      const { lines, tornTailBytes } = journalLines(whole + last.slice(0, cut));
      assert.equal(tornTailBytes, cut);
      assert.deepEqual(verifyJournal(lines, v.keys, v.checkpoint, v.trust), v.expected, `${v.id} cut ${cut}`);
    }
  }
});

test("torn bytes still on disk keep a journal from PASS, as the Python verifier does", () => {
  for (const v of [...load("grants.json"), ...load("loss.json")]) {
    const whole = v.journal.map((line: string) => line + "\n").join("");
    assert.deepEqual(verifyJournalText(whole, v.keys, v.checkpoint, v.trust), { ...v.expected, tornTailBytes: 0 }, v.id);
    const torn = verifyJournalText(whole + '{"payload":"eyJ', v.keys, v.checkpoint, v.trust);
    const verdict = v.expected.verdict === "PASS" ? "NOT_ESTABLISHED" : v.expected.verdict;
    assert.deepEqual(torn, { ...v.expected, verdict, tornTailBytes: 15 }, v.id);
  }
});

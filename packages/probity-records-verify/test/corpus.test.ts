import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { lines } from "../src/corpus.ts";

const corpus = (suite: string, vectors: unknown[]) => {
  const dir = mkdtempSync(join(tmpdir(), "corpus-"));
  writeFileSync(join(dir, "MANIFEST.json"), JSON.stringify({ suite, corpusDigest: "a".repeat(64), vectors }));
  return dir;
};

test("an unimplemented suite is not-applicable member by member", () => {
  const out = lines(corpus("other/v1", [{ id: "one", path: "x" }, { id: "two", path: "y" }])).map((l) => JSON.parse(l));
  assert.deepEqual(out.map((l) => [l.vector, l.verdict, l.reason]), [["one", "not-applicable", "suite-not-implemented"], ["two", "not-applicable", "suite-not-implemented"]]);
});

test("an unreadable member is an error line, never a pass", () => {
  const [line] = lines(corpus("approval-binding/v1", [{ id: "gone", path: "cases/gone" }])).map((l) => JSON.parse(l));
  assert.equal(line.verdict, "error");
});

test("a manifest without a vectors list is refused", () => {
  assert.throws(() => lines(corpus("approval-binding/v1", undefined as never)));
});

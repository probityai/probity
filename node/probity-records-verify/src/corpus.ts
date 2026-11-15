// probity-records-verify corpus DIR [DIR ...]: one verdict line per corpus member, in the shared
// verdict-line format (agent-evidence-vectors vectors/verdict-line.schema.json). Two suites are
// answered by this package's readers: approval-binding/v1 and uncertain-effect/v1. Every member of
// any other suite is answered not-applicable, so the output always covers the whole manifest.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { judgeApprovalBinding, judgeUncertainEffect, parsePy } from "./verify.ts";

const SCHEMA_ID = "https://probityai.github.io/agent-evidence-vectors/schema/verdict-line/v1";
const APPROVAL_SUITE = "approval-binding/v1";
const UNCERTAIN_SUITE = "uncertain-effect/v1";
const ACCEPTED_EFFECT = "effect_held";
const VERIFIER = { name: "probity-records-verify", version: JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")).version };

type Answer = { verdict: string; reason: string | null };

function answer(suite: string, root: string, entry: { path: string }): Answer {
  if (suite === APPROVAL_SUITE) {
    const dir = join(root, entry.path);
    const record = parsePy(readFileSync(join(dir, "record.json"), "utf8"));
    const name = String((record.use ?? {}).payloadFile ?? "payload.bin");
    const payload = name.includes("/") || ["", ".", ".."].includes(name) ? Buffer.alloc(0) : readFileSync(join(dir, name));
    const d = judgeApprovalBinding(record, payload);
    return { verdict: d.decision === "allow" ? "accept" : "reject", reason: d.reason };
  }
  if (suite === UNCERTAIN_SUITE) {
    const d = judgeUncertainEffect(parsePy(readFileSync(join(root, entry.path, "record.json"), "utf8")));
    return d.decision === "supported" ? { verdict: "accept", reason: ACCEPTED_EFFECT } : { verdict: "reject", reason: d.reason };
  }
  return { verdict: "not-applicable", reason: "suite-not-implemented" };
}

/** The sorted-key compact JSON line of every member of the corpus at `root`. */
export function lines(root: string): string[] {
  const manifest = JSON.parse(readFileSync(join(root, "MANIFEST.json"), "utf8"));
  const { suite, corpusDigest, vectors } = manifest;
  if (typeof suite !== "string" || typeof corpusDigest !== "string" || !Array.isArray(vectors))
    throw new Error(`${root}/MANIFEST.json names no suite, corpusDigest or vectors list`);
  return vectors.map((entry: { id: string; path: string }) => {
    let a: Answer;
    try { a = answer(suite, root, entry); } catch (e) { a = { verdict: "error", reason: `${(e as Error).name}: ${(e as Error).message}` }; }
    const line = { corpusDigest, reason: a.reason, schema: SCHEMA_ID, suite, vector: entry.id, verdict: a.verdict, verifier: VERIFIER };
    return JSON.stringify(line);
  });
}

export function main(dirs: string[]): number {
  if (!dirs.length) { console.error("probity-records-verify corpus: NOT RUN: no corpus directory named"); return 2; }
  let out: string[];
  try { out = dirs.flatMap(lines); } catch (e) { console.error(`probity-records-verify corpus: NOT RUN: ${(e as Error).message}`); return 2; }
  process.stdout.write(out.map((l) => l + "\n").join(""));
  return 0;
}

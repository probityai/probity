#!/usr/bin/env node
// probity-records-verify JOURNAL.jsonl --key PUB.pem [--key ...] [--checkpoint CP.json] [--trust TRUST.json]
// probity-records-verify corpus DIR [DIR ...]
// probity-records-verify jcs {rfc8785|card-signing-input} INPUT.json: the external-verifier contract of
//   agent-evidence-vectors' a2a-jcs corpus (agent_evidence_vectors.a2ajcs): exit 0 with
//   {"canonical_utf8_hex": ...} on the last line, exit 1 for a refusal, exit 2 when it cannot run.
import { readFileSync } from "node:fs";
import { canonicalBytes, canonicalOfReceived, parseReceived, verifyJournal } from "./verify.ts";
import { main as corpusMain } from "./corpus.ts";

const argv = process.argv.slice(2);
if (argv[0] === "corpus") process.exit(corpusMain(argv.slice(1)));
if (argv[0] === "jcs") process.exit(jcsMain(argv[1], argv[2]));

function jcsMain(target: string | undefined, path: string | undefined): number {
  if ((target !== "rfc8785" && target !== "card-signing-input") || !path) {
    console.error("usage: probity-records-verify jcs {rfc8785|card-signing-input} INPUT.json");
    return 2;
  }
  let raw: Buffer;
  try { raw = readFileSync(path); } catch (e) { console.error(`NOT RUN: ${(e as Error).message}`); return 2; }
  let out: Buffer;
  try {
    if (target === "rfc8785") out = canonicalOfReceived(raw);
    else {
      // The bytes an Agent Card signature covers: the card without its top-level signatures member.
      const card = parseReceived(raw);
      if (card !== null && typeof card === "object" && !Array.isArray(card)) delete card.signatures;
      out = canonicalBytes(card);
    }
  } catch (e) { console.log(JSON.stringify({ refused: (e as Error).message })); return 1; }
  console.log(JSON.stringify({ canonical_utf8_hex: out.toString("hex") }));
  return 0;
}
const keys: string[] = [];
let journal = "", checkpoint: unknown = null, trust: unknown = null;
for (let i = 0; i < argv.length; i++) {
  if (argv[i] === "--key") keys.push(readFileSync(argv[++i], "utf8"));
  else if (argv[i] === "--checkpoint") checkpoint = parseReceived(readFileSync(argv[++i]));
  else if (argv[i] === "--trust") trust = parseReceived(readFileSync(argv[++i]));
  else journal = argv[i];
}
let text: string;
// A journal that is not UTF-8 is refused, never read through replacement characters.
try { text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(readFileSync(journal)); }
catch { console.error(`probity-records-verify: NOT RUN: ${journal} is not UTF-8`); process.exit(2); }
const report = verifyJournal(text.split("\n"), keys, checkpoint, trust as never);
console.log(JSON.stringify(report, null, 2));
process.exit(report.verdict === "PASS" ? 0 : 1);

#!/usr/bin/env node
// probity-records-verify JOURNAL.jsonl --key PUB.pem [--key ...] [--checkpoint CP.json] [--trust TRUST.json]
import { readFileSync } from "node:fs";
import { verifyJournal } from "./verify.ts";
import { main as corpusMain } from "./corpus.ts";

const argv = process.argv.slice(2);
if (argv[0] === "corpus") process.exit(corpusMain(argv.slice(1)));
const keys: string[] = [];
let journal = "", checkpoint: unknown = null, trust: unknown = null;
for (let i = 0; i < argv.length; i++) {
  if (argv[i] === "--key") keys.push(readFileSync(argv[++i], "utf8"));
  else if (argv[i] === "--checkpoint") checkpoint = JSON.parse(readFileSync(argv[++i], "utf8"));
  else if (argv[i] === "--trust") trust = JSON.parse(readFileSync(argv[++i], "utf8"));
  else journal = argv[i];
}
const report = verifyJournal(readFileSync(journal, "utf8").split("\n"), keys, checkpoint, trust as never);
console.log(JSON.stringify(report, null, 2));
process.exit(report.verdict === "PASS" ? 0 : 1);

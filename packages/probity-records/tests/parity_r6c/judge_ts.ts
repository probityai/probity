// The TypeScript twin's verdict on every case gen_cases.py wrote. Usage: node judge_ts.ts <cases.json> <out.json>
import { readFileSync, writeFileSync } from "node:fs";
import { judgeVerified } from "../../../../node/probity-records-verify/src/verified.ts";

const cases = JSON.parse(readFileSync(process.argv[2], "utf8"));
const out: Record<string, unknown> = {};
for (const c of cases) {
  try { out[c.case] = judgeVerified(c.row); }
  catch (e) { out[c.case] = `RAISED:${(e as Error).constructor.name}:${String((e as Error).message).slice(0, 60)}`; }
}
writeFileSync(process.argv[3], JSON.stringify(out));
console.log(`TS_CASES ${Object.keys(out).length}`);

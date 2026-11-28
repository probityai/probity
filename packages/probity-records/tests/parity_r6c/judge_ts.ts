// The TypeScript twin's verdict on every case gen_cases.py wrote, by case kind. Usage: node judge_ts.ts <cases.json> <out.json>
import { readFileSync, writeFileSync } from "node:fs";
import { parseDictionary, SFError } from "../../../../node/probity-records-verify/src/sf.ts";
import { checkPossession, httpUriParts, judgeVerified, proofDocument } from "../../../../node/probity-records-verify/src/verified.ts";
import { duplicateProofs, possessionRecordProblem, ts } from "../../../../node/probity-records-verify/src/verify.ts";
import { CertificateRefused, certificateFacts, spkiKey } from "../../../../node/probity-records-verify/src/x509.ts";

type J = any;  // eslint-disable-line @typescript-eslint/no-explicit-any
const buf = (b64: string | null): Buffer | null => (b64 === null ? null : Buffer.from(b64, "base64"));
const JUDGES: Record<string, (c: J) => J> = {
  request: judgeVerified,
  possession: (c) => {
    const r = c.request;
    const facts = { method: r.method, url: r.url, content: buf(r.contentB64), dpop: r.dpop, clientCertificate: buf(r.clientCertificateB64), headers: r.headers };
    const [proof, reason] = checkPossession(c.cnf, facts, c.at, c.accessToken);
    return proof === null ? { refused: reason } : { proof: proofDocument(proof) };
  },
  record: (c) => {
    const problem = possessionRecordProblem(c.record, c.cnf);
    return problem === null ? { ok: true } : { refused: problem };
  },
  spent: (c) => {
    const found = duplicateProofs(c.records).map((s) => { const m = /^line_(\d+):(.*)$/.exec(s)!; return [Number(m[1]), m[2]]; });
    return found.length ? { found, refused: String(found[0][1]).split(":")[0] } : { found };
  },
  // The readers of one received text, judged alone (grammar_cases.py).
  timestamp: (c) => { try { return { micros: ts(c.text).toString(10) }; } catch (e) { return { refused: (e as Error).message }; } },
  uri: (c) => { try { return httpUriParts(c.text); } catch (e) { return { refused: (e as Error).message }; } },
  certificate: (c) => {
    let facts;
    try { facts = certificateFacts(Buffer.from(c.derB64, "base64")); } catch (e) { if (e instanceof CertificateRefused) return { refused: e.message }; throw e; }
    const key = spkiKey(facts.spki);
    const shown = key === null ? null : { kty: key.kty, crv: key.crv, x: key.x.toString("hex"), ...(key.y === undefined ? {} : { y: key.y.toString("hex") }) };
    return { notBefore: facts.notBefore.toString(10), notAfter: facts.notAfter.toString(10), key: shown };
  },
  "sf-bytes": (c) => {
    let member;
    try { member = parseDictionary(`a=:${c.text}:`).get("a"); } catch (e) { if (e instanceof SFError) return { refused: "sf" }; throw e; }
    return member !== undefined && member.kind === "item" && Buffer.isBuffer(member.value) && member.params.size === 0 ? { hex: member.value.toString("hex") } : { other: true };
  },
};

const cases = JSON.parse(readFileSync(process.argv[2], "utf8"));
const out: Record<string, unknown> = {};
for (const c of cases) {
  try { out[c.case] = JUDGES[c.kind ?? "request"](c.row); }
  catch (e) { out[c.case] = `RAISED:${(e as Error).constructor.name}:${String((e as Error).message).slice(0, 60)}`; }
}
writeFileSync(process.argv[3], JSON.stringify(out));
console.log(`TS_CASES ${Object.keys(out).length}`);

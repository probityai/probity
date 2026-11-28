// The grammar files (packages/probity-records/grammar/*.json) are what the readers implement: each pattern and bound
// in a file is the one in this reader's code, and each accepted and refused text is judged as the file says. The
// Python package has the same test (tests/test_grammar.py).
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { parseDictionary, SFError } from "../src/sf.ts";
import { PORT, httpUriParts } from "../src/verified.ts";
import { TIMESTAMP, URL_GRAMMAR, URL_HOST_MAX, URL_PORT_MAX, decimal, exactInt, ts, urlParts } from "../src/verify.ts";
import { GENERALIZED_TIME, SPKI_ED25519, SPKI_P256, UTC_TIME } from "../src/x509.ts";

type J = any;  // eslint-disable-line @typescript-eslint/no-explicit-any
const rules = (name: string): J => JSON.parse(readFileSync(new URL(`../../../packages/probity-records/grammar/${name}.json`, import.meta.url), "utf8")).productions;
const anchored = (pattern: string): string => `^${pattern}$`;

test("the timestamp reader is the grammar", () => {
  const rule = rules("timestamp")["date-time"];
  assert.equal(TIMESTAMP.source, anchored(rule.pattern));
  for (const [text, micros] of rule.accept) assert.equal(ts(text).toString(10), micros, text);
  for (const [text, code] of rule.refuse) assert.throws(() => ts(text), { message: code }, text);
});

test("the integer reader is the grammar", () => {
  const doc = rules("integer"), rule = doc["exact-integer"];
  assert.deepEqual([rule.bounds.min, rule.bounds.max], [-Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER]);
  // read as the readers read a claim: from JSON text, where 1.0 is a float spelling and 2**53 + 1 keeps its digits
  for (const value of [0, 1, -1, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER]) assert.equal(exactInt({ v: value }, "v"), true);
  for (const value of [2 ** 53, 2 ** 53 + 2, -(2 ** 53), 1.5, 1e300, true, false, null, "1", "", [1], { 0: 1 }, undefined]) assert.equal(exactInt({ v: value }, "v"), false);
  for (const text of ["", "1".repeat(16), "\u0661", "\uff11", "+1", "-1", " 1", "1 ", "1_0", "1.0"]) assert.throws(() => decimal(text), { message: "decimal takes 1 to 15 of the digits 0 to 9" });
  assert.equal(decimal("000000000000015"), 15);
  assert.equal(doc["decimal-digits"].pattern, "[0-9]{1,15}");
});

test("the target URI reader is the grammar", () => {
  const doc = rules("target-uri"), port = doc.port, alphabet: string = doc["uri-text"].alphabet;
  assert.equal(PORT.source, anchored(port.pattern));
  for (const [text, value] of port.accept) assert.equal(httpUriParts(`https://a.example:${text}/x`)[2], value, text);
  for (const text of port.refuse) assert.throws(() => httpUriParts(`https://a.example:${text}/x`), text);
  for (const zeros of port.long.zeros) assert.equal(httpUriParts(`https://a.example:${"0".repeat(zeros)}443/x`)[2], 443);
  for (const code of [...Array(0x100).keys(), 0x3002, 0xff0f, 0x2028]) {
    const ch = String.fromCodePoint(code);
    if (ch === "%") continue;
    let read = true;
    try { httpUriParts(`https://a.example/${ch}`); } catch { read = false; }
    assert.equal(read, alphabet.includes(ch), code.toString(16));
  }
});

test("the constraint URL reader is the grammar", () => {
  const doc = JSON.parse(readFileSync(new URL("../../../packages/probity-records/grammar/constraint-url.json", import.meta.url), "utf8"));
  assert.deepEqual({ ...URL_GRAMMAR }, Object.fromEntries(Object.entries(doc.productions).map(([n, r]: [string, J]) => [n, r.pattern])));
  assert.deepEqual([URL_PORT_MAX, URL_HOST_MAX], [doc.productions.authority.bounds.portMax, doc.productions["host-label"].bounds.hostMax]);
  for (const [url, ...parts] of doc.cases.accept) assert.deepEqual(urlParts(url), parts, url);
  for (const url of doc.cases.refuse) assert.equal(urlParts(url), null, JSON.stringify(url));
});

test("the certificate reader is the grammar", () => {
  const doc = rules("x509");
  assert.equal(UTC_TIME.source, anchored(doc.time.utcTime.pattern));
  assert.equal(GENERALIZED_TIME.source, anchored(doc.time.generalizedTime.pattern));
  assert.equal(SPKI_ED25519.toString("hex"), doc.spki.ed25519);
  assert.equal(SPKI_P256.toString("hex"), doc.spki.p256);
});

test("the structured-field byte sequence is the grammar", () => {
  const seq = rules("stamp")["byte-sequence"];
  for (const [text, hexed] of seq.accept) assert.equal((parseDictionary(`a=:${text}:`).get("a") as J).value.toString("hex"), hexed, text);
  for (const text of seq.refuse) assert.throws(() => parseDictionary(`a=:${text}:`), SFError, JSON.stringify(text));
});

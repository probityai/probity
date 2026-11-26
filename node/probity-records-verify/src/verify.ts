// Offline verifier for probity-records journals, in TypeScript.
//
// It re-runs, from the journal bytes and the trust an auditor pins, the checks the Python
// verifier (probity_records.verify_journal) runs: every DSSE signature, the hash chain, the
// checkpoint, grant chains (signatures, narrowing on every axis, CEL conditions, context,
// budgets recounted across the journal), M-of-N quorum evidence (proposer separation, roles,
// deputies) and the four-principal identity block. Failure codes are the Python verifier's,
// character for character; test/shared.test.ts holds the two to the shared vectors.
//
// The two published per-record readers are ported too: approval-binding/v1 (the twenty-two ordered
// checks of agent_evidence_vectors.approvalbinding 0.38, with the M-of-N recount under the quorum policy
// the auditor pinned) and uncertain_effect/v1 (the thirteen ordered checks of agent-evidence-verify's
// built-in adapter). A governance-step record is still reported as not ported, never passed.

import { createHash, createPublicKey, verify as edVerify, type KeyObject } from "node:crypto";
import { celEnv, isCelError, parse as celParse, plan as celPlan } from "@bufbuild/cel";
import { admit, JcsError } from "jcs-admit";
import { canonicalIdentifier, identifier, sameIdentifier } from "./identifiers.ts";

export { CanonicalIdentity, Evidence, IdentityStringError, Ref, judgeIdentity } from "./identity.ts";

export const TOOL_CALL_RECORD = identifier("agent-evidence-vectors/predicate/v1/tool-call-record");
/** True when a signed body names the tool-call-record predicate under either recognised host spelling. */
const isToolCall = (body: J): boolean => sameIdentifier(body.predicateType, TOOL_CALL_RECORD);
const IN_TOTO = "application/vnd.in-toto+json";
const GRANT_DOMAIN = "probity-grant-v1\u0000";
const VOTE_DOMAIN = "probity-quorum-vote-v1\u0000";
const DEPUTY_DOMAIN = "probity-quorum-deputy-v1\u0000";
const APPROVAL_DOMAIN = "probity-approval-v1\u0000";
const GENESIS = "0".repeat(64);
type J = any; // eslint-disable-line @typescript-eslint/no-explicit-any

// ---------- canonical bytes (RFC 8785) and digests ----------
//
// Both twins canonicalize through one native core, jcs-admit (this package through its npm build,
// the Python verifier through its PyPI build), so a value has canonical bytes in one twin exactly
// when it has them in the other. Before the bytes reach the core, an integer JCS cannot print
// exactly is refused: 2**53 and 2**53 + 1 print the same bytes, so a signature over one would hold
// for the other. Every refusal is a typed code both twins report, never a lossy rewrite: a lone
// surrogate, a duplicate member or invalid UTF-8 has no canonical form (jcs_refused:<variant>).

/** The integer bound JCS prints exactly; the Python twin's MAX_EXACT_INT. */
const MAX_EXACT_INT = Number.MAX_SAFE_INTEGER;
/** Per holder object, the source text of each integer the parse read beyond MAX_EXACT_INT. */
const INEXACT_SOURCE = new WeakMap<object, Map<string, string>>();

/** A jcs-admit refusal as the code both twins report: `jcs_refused:<native variant>`. */
function jcsRefusal(e: unknown): Error {
  return e instanceof JcsError ? new Error(`jcs_refused:${e.variant}`) : (e as Error);
}

/** Refuse what JCS cannot print exactly: a non-finite number, or an integer beyond MAX_EXACT_INT. */
function refuseUnprintable(v: J, holder: J, key: string, depth: number): void {
  if (depth > 256) throw new Error("value_too_deep");
  if (typeof v === "number") {
    if (!Number.isFinite(v)) throw new Error("jcs_number");
    if (Number.isInteger(v) && !isFloat(holder, key, v) && Math.abs(v) > MAX_EXACT_INT) {
      const source = holder !== null && typeof holder === "object" ? INEXACT_SOURCE.get(holder)?.get(key) : undefined;
      throw new Error(`integer_beyond_exact_json_range:${source ?? BigInt(v).toString()}`);
    }
  } else if (Array.isArray(v)) v.forEach((x, i) => refuseUnprintable(x, v, String(i), depth + 1));
  else if (v !== null && typeof v === "object") for (const k of Object.keys(v)) refuseUnprintable(v[k], v, k, depth + 1);
}

/** The RFC 8785 bytes of a parsed JSON value, through jcs-admit; refused when there are none. */
export function canonicalBytes(v: J): Buffer {
  refuseUnprintable(v, null, "", 0);
  const text = JSON.stringify(v);
  if (text === undefined) throw new Error("jcs_not_json");
  try { return Buffer.from(admit(Buffer.from(text, "utf8"))); } catch (e) { throw jcsRefusal(e); }
}

/** canonicalBytes as text. */
export function canonical(v: J): string {
  return canonicalBytes(v).toString("utf8");
}

/** jcs-admit over raw bytes, before anything decodes or parses them. */
function admitGate(raw: Uint8Array): void {
  try { admit(raw); } catch (e) { throw jcsRefusal(e); }
}

export const sha256Hex = (data: string | Buffer): string => createHash("sha256").update(data).digest("hex");
const digestOf = (v: J): string => sha256Hex(canonicalBytes(v));
// Equality for constraint checks: the Python twin compares with ==, which never refuses, so this is a
// structural comparison (sorted keys, JSON.stringify leaves), not canonical bytes.
function structural(v: J): string {
  if (Array.isArray(v)) return "[" + v.map(structural).join(",") + "]";
  if (v !== null && typeof v === "object") {
    const keys = Object.keys(v).sort();
    return "{" + keys.map((k) => JSON.stringify(k) + ":" + structural(v[k])).join(",") + "}";
  }
  return String(JSON.stringify(v));
}
const same = (a: J, b: J): boolean => structural(a) === structural(b);
const isObj = (v: J): boolean => v !== null && typeof v === "object" && !Array.isArray(v);
/** Whether `o` holds `k` itself: an inherited name (constructor, toString, __proto__) is never a member. */
const own = (o: J, k: string): boolean => isObj(o) && Object.hasOwn(o, k);
/** Code point order, which is Python's `sorted` over str: JavaScript's default sort compares UTF-16 code units. */
const byCodePoint = (a: string, b: string): number => Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));
const sortedKeys = (o: J): string[] => Object.keys(o).sort(byCodePoint);

// Python's json.loads keeps `3.0` a float, `3` an int and `1e2` a float, and the constraint checks
// (`type(v) is type(c["value"])`) tell them apart; JSON.parse folds all of them into one number.
// The parse below records, per holder object, which keys held an integral value written as a float,
// and the source text of any integer beyond MAX_EXACT_INT (Python keeps it exact; JSON.parse rounds).
const FLOAT_KEYS = new WeakMap<object, Set<string>>();
export function parsePy(text: string): J {
  return JSON.parse(text, function (this: J, key: string, value: J, context?: { source?: string }) {
    if (typeof value === "number" && Number.isInteger(value) && context?.source !== undefined) {
      if (/[.eE]/.test(context.source)) {
        let keys = FLOAT_KEYS.get(this);
        if (!keys) FLOAT_KEYS.set(this, (keys = new Set()));
        keys.add(key);
      } else if (Math.abs(value) > MAX_EXACT_INT) {
        let sources = INEXACT_SOURCE.get(this);
        if (!sources) INEXACT_SOURCE.set(this, (sources = new Map()));
        sources.set(key, context.source);
      }
    }
    return value;
  });
}

const UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/**
 * Parse RECEIVED bytes. jcs-admit reads them first and refuses a duplicate member, invalid UTF-8,
 * a lone surrogate (raw or escaped) and every other input with no canonical form, so a record is
 * never read as something other than the bytes that were signed. The Python twin's
 * probity_records.core.admitted_loads does the same.
 */
export function parseReceived(raw: Uint8Array): J {
  admitGate(raw);
  return parsePy(UTF8.decode(raw));
}

/** The RFC 8785 bytes of received bytes: admitted, parsed, then canonicalized (probity_records.canonical_of_received). */
export function canonicalOfReceived(raw: Uint8Array): Buffer {
  return canonicalBytes(parseReceived(raw));
}

/** Whether `value`, read from `holder[key]`, is a Python float: a fractional number, or an integral one written as a float. */
export function isFloat(holder: J, key: string | number, value: J): boolean {
  return typeof value === "number" && (!Number.isInteger(value) || (holder !== null && typeof holder === "object" && (FLOAT_KEYS.get(holder)?.has(String(key)) ?? false)));
}

function unb64(text: J): Buffer {
  if (typeof text !== "string") throw new Error("expected base64 text");
  const data = Buffer.from(text, "base64");
  if (data.toString("base64") !== text) throw new Error("expected canonical base64");
  return data;
}

// ---------- keys and signatures ----------

export function rawKey(raw: Buffer): KeyObject {
  return createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: raw.toString("base64url") }, format: "jwk" });
}
export function keyId(key: KeyObject): string {
  return sha256Hex(Buffer.from(String((key.export({ format: "jwk" }) as J).x), "base64url"));
}
export function edOk(key: KeyObject, data: Buffer, sig: Buffer): boolean {
  try { return edVerify(null, data, key, sig); } catch { return false; }
}
const sigOk = (rawB64: J, domain: string, body: J, sig: J): boolean => {
  try { return edOk(rawKey(unb64(rawB64)), Buffer.concat([Buffer.from(domain, "latin1"), canonicalBytes(body)]), unb64(sig)); }
  catch { return false; }
};

function pae(type: string, payload: Buffer): Buffer {
  const t = Buffer.from(type, "utf8");
  return Buffer.concat([Buffer.from(`DSSEv1 ${t.length} `), t, Buffer.from(` ${payload.length} `), payload]);
}

function openEnvelope(env: J, keys: KeyObject[]): [Buffer, string] {
  if (!isObj(env) || !["payload", "payloadType", "signatures"].every((k) => k in env)) throw new Error("envelope_shape");
  const payload = unb64(env.payload);
  if (!Array.isArray(env.signatures) || env.signatures.length === 0) throw new Error("envelope_shape");
  const pre = pae(env.payloadType, payload);
  for (const key of keys) {
    for (const entry of env.signatures) {
      let sig: Buffer;
      try { sig = unb64(isObj(entry) ? entry.sig : null); } catch { continue; }
      if (!edOk(key, pre, sig)) continue;
      if (env.payloadType !== IN_TOTO) throw new Error("payload_type_unexpected");
      return [payload, keyId(key)];
    }
  }
  throw new Error("signature_unverified");
}

// ---------- time ----------

// The one timestamp grammar (grants.ts): RFC 3339 date-time, at most six fraction digits, an explicit offset. Microseconds
// since the epoch; throws grant_timestamp_offset_missing for a date-time with no offset (it names no instant) and
// grant_timestamp_invalid for anything else, a field out of range included (Date.UTC would roll month 13 into January).
export function ts(text: J): number {
  const m = typeof text === "string" ? /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?(Z|[+-]\d{2}:\d{2})?$/.exec(text) : null;
  if (!m) throw new Error("grant_timestamp_invalid");
  if (m[8] === undefined) throw new Error("grant_timestamp_offset_missing");
  const [y, mo, d, h, mi, sec] = m.slice(1, 7).map(Number);
  const base = Date.UTC(y, mo - 1, d, h, mi, sec);
  const back = new Date(base);
  if (y < 1 || back.getUTCFullYear() !== y || back.getUTCMonth() !== mo - 1 || back.getUTCDate() !== d || h > 23 || mi > 59 || sec > 59)
    throw new Error("grant_timestamp_invalid");
  let off = 0;
  if (m[8] !== "Z") {
    const oh = +m[8].slice(1, 3), om = +m[8].slice(4, 6);
    if (oh > 23 || om > 59) throw new Error("grant_timestamp_invalid");
    off = (m[8][0] === "-" ? -1 : 1) * (oh * 60 + om) * 60000;
  }
  return (base - off) * 1000 + Number((m[7] ?? "").padEnd(6, "0"));
}

// Every instant a grant names parses (grants._validate_times): "<code>:<member>" for the first that does not.
function timesProblem(body: J): string | null {
  for (const member of "reviewBy" in body ? ["notBefore", "expiresAt", "reviewBy"] : ["notBefore", "expiresAt"]) {
    try { ts(body[member]); } catch (e) { return `${(e as Error).message}:${member}`; }
  }
  return null;
}

// ---------- CEL ----------

const INT64 = 2n ** 63n;
function toCel(v: J, asFloat = false): J {
  if (v === null || v === undefined) return null;
  if (typeof v === "number") return !asFloat && Number.isInteger(v) && BigInt(v) >= -INT64 && BigInt(v) < INT64 ? BigInt(v) : v;
  if (Array.isArray(v)) return v.map((x, i) => toCel(x, isFloat(v, i, x)));
  if (isObj(v)) return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, toCel(x, isFloat(v, k, x))]));
  return v;
}
export function celHolds(expr: string, bindings: Record<string, J>, valueIsFloat = false): boolean {
  if (celSyntaxProblem(expr) !== null) return false;
  try {
    const data: Record<string, J> = {};
    for (const name of ["value", "args", "tool", "ctx"]) data[name] = toCel(bindings[name] ?? null, name === "value" && valueIsFloat);
    const out = celPlan(celEnv(), celParse(expr + "\n"))(data);
    return !isCelError(out) && out === true;
  } catch { return false; }
}

// The syntax check a verifier runs on a grant (celexpr.syntax_problem): cel-cpp's parser, which @bufbuild/cel's
// parser does not match on its own. The probed differences are closed here: a line comment at the very end (bufbuild
// needs the newline cel-cpp does not), an unknown or short escape in a string or bytes literal and a \u or \U escape
// in bytes (bufbuild keeps them), a lone surrogate, an integer literal outside 64 bits (bufbuild keeps the bigint) and a has() over
// anything but a field (bufbuild leaves it a call). Type checking is not part of it: cel-cpp's checker has no twin
// here, and an expression that parses but does not type-check never holds in either verifier.
const CEL_BLANK = /^[ \t\n\r\f]*$/;
const CEL_SIMPLE_ESCAPES = "abfnrtv\\?\"'`";
function celLiteralsOk(src: string): boolean {
  let i = 0;
  while (i < src.length) {
    const ch = src[i];
    if (ch === "/" && src[i + 1] === "/") { while (i < src.length && src[i] !== "\n") i++; continue; }
    if (ch !== "'" && ch !== '"') { i++; continue; }
    const p1 = src[i - 1] ?? "", p2 = src[i - 2] ?? "";
    const raw = p1 === "r" || p1 === "R", bytes = p1 === "b" || p1 === "B" || (raw && (p2 === "b" || p2 === "B"));
    const quote = src.startsWith(ch.repeat(3), i) ? ch.repeat(3) : ch;
    i += quote.length;
    for (;;) {
      if (i >= src.length) return true; // unterminated: the parser refuses it
      if (src.startsWith(quote, i)) { i += quote.length; break; }
      if (raw || src[i] !== "\\") { i++; continue; } // a raw literal has no escapes: a backslash is itself
      const e = src[i + 1] ?? "";
      if (CEL_SIMPLE_ESCAPES.includes(e) && e !== "") { i += 2; continue; }
      const hex = (n: number): boolean => /^[0-9A-Fa-f]+$/.test(src.slice(i + 2, i + 2 + n)) && src.slice(i + 2, i + 2 + n).length === n;
      if ((e === "x" || e === "X") && hex(2)) { i += 4; continue; }
      if (e === "u" && !bytes && hex(4)) { i += 6; continue; }
      if (e === "U" && !bytes && hex(8)) { i += 10; continue; }
      if (/^[0-3][0-7][0-7]$/.test(src.slice(i + 1, i + 4))) { i += 4; continue; }
      return false;
    }
  }
  return true;
}
const INT64_MAX = 2n ** 63n - 1n, UINT64_MAX = 2n ** 64n - 1n;
function celAstOk(e: J): boolean {
  if (!isObj(e) || !isObj(e.exprKind)) return true;
  const v = e.exprKind.value;
  switch (e.exprKind.case) {
    case "constExpr": {
      const k = v.constantKind;
      if (k?.case === "int64Value") return k.value >= -INT64 && k.value <= INT64_MAX;
      if (k?.case === "uint64Value") return k.value >= 0n && k.value <= UINT64_MAX;
      return true;
    }
    case "callExpr":
      if (v.function === "has" && !v.target && v.args.length === 1) return false;
      return celAstOk(v.target) && v.args.every(celAstOk);
    case "selectExpr": return celAstOk(v.operand);
    case "listExpr": return v.elements.every(celAstOk);
    case "structExpr": return v.entries.every((x: J) => celAstOk(x.keyKind?.value) && celAstOk(x.value));
    case "comprehensionExpr": return [v.iterRange, v.accuInit, v.loopCondition, v.loopStep, v.result].every(celAstOk);
    default: return true;
  }
}
export function celSyntaxProblem(expr: J): string | null {
  if (typeof expr !== "string" || CEL_BLANK.test(expr)) return "cel_expression_empty";
  if (!expr.isWellFormed() || !celLiteralsOk(expr)) return "cel_syntax_invalid"; // a lone surrogate is no UTF-8 text
  let parsed: J;
  try { parsed = celParse(expr + "\n"); } catch { return "cel_syntax_invalid"; }
  return celAstOk(parsed.expr) ? null : "cel_syntax_invalid";
}

// ---------- constraints ----------

function globRe(p: string): RegExp {
  let re = "";
  for (let i = 0; i < p.length; i++) {
    const c = p[i];
    if (c === "*") re += ".*";
    else if (c === "?") re += ".";
    else if (c === "[") {
      const j = p.indexOf("]", i + 2);
      if (j < 0) re += "\\[";
      else { let cls = p.slice(i + 1, j); if (cls[0] === "!") cls = "^" + cls.slice(1); re += "[" + cls.replace(/\\/g, "\\\\") + "]"; i = j; }
    } else re += c.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&");
  }
  return new RegExp("^(?:" + re + ")$", "s");
}
const fnmatch = (s: string, p: string): boolean => globRe(p).test(s);
const num = (v: J): boolean => typeof v === "number";
function normpath(p: string): string {
  const out: string[] = [];
  for (const part of p.split("/")) {
    if (part === "" || part === ".") continue;
    if (part === "..") { if (out.length && out[out.length - 1] !== "..") out.pop(); else if (!p.startsWith("/")) out.push(".."); }
    else out.push(part);
  }
  const lead = p.startsWith("//") && !p.startsWith("///") ? "//" : p.startsWith("/") ? "/" : "";
  return lead + out.join("/") || ".";
}
function urlParts(v: J): [string, string, string] | null {
  if (typeof v !== "string" || /[\x00\r\n\t ]/.test(v)) return null;
  let u: URL;
  try { u = new URL(v); } catch { return null; }
  if (u.username || u.password || !u.hostname) return null;
  return [u.protocol.replace(/:$/, "").toLowerCase(), u.hostname.toLowerCase().replace(/^\[|\]$/g, ""), u.pathname || "/"];
}
const hostOk = (h: string, ps: string[]): boolean => ps.some((p) => fnmatch(h, p.toLowerCase()));
const starOnly = (p: string): boolean => !p.includes("[") && !p.includes("?");
const hostsNarrow = (c: string[], p: string[]): boolean =>
  c.every((h) => p.includes(h) || (starOnly(h) && hostOk(h, p.filter(starOnly))));
// ---------- IP addresses, as Python's ipaddress module reads them ----------

type Ip = { bits: 32 | 128; n: bigint };
function parseV4(s: string): bigint | null {
  const parts = s.split(".");
  if (parts.length !== 4) return null;
  let n = 0n;
  for (const p of parts) {
    if (!/^[0-9]{1,3}$/.test(p) || (p.length > 1 && p[0] === "0") || +p > 255) return null;
    n = (n << 8n) | BigInt(p);
  }
  return n;
}
function parseV6(text: string): bigint | null {
  let s = text;
  const pct = s.indexOf("%");
  if (pct >= 0) { if (pct === s.length - 1 || /[/%]/.test(s.slice(pct + 1))) return null; s = s.slice(0, pct); }
  let tail: bigint[] = [];
  const dot = s.lastIndexOf(".");
  if (dot >= 0) {
    const colon = s.lastIndexOf(":");
    const v4 = parseV4(s.slice(colon + 1));
    if (v4 === null) return null;
    tail = [v4 >> 16n, v4 & 0xffffn];
    s = s.slice(0, colon + 1) + "0:0";
  }
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const group = (h: string): bigint[] | null => {
    if (h === "") return [];
    const out: bigint[] = [];
    for (const g of h.split(":")) { if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null; out.push(BigInt("0x" + g)); }
    return out;
  };
  const head = group(halves[0]), rest = halves.length === 2 ? group(halves[1]) : [];
  if (head === null || rest === null) return null;
  let groups: bigint[];
  if (halves.length === 2) {
    const fill = 8 - head.length - rest.length;
    if (fill < 1) return null;
    groups = [...head, ...Array<bigint>(fill).fill(0n), ...rest];
  } else groups = head;
  if (groups.length !== 8) return null;
  if (tail.length) groups = [...groups.slice(0, 6), ...tail];
  return groups.reduce((acc, g) => (acc << 16n) | g, 0n);
}
function parseIp(s: J): Ip | null {
  if (typeof s !== "string") return null;
  const v4 = parseV4(s);
  if (v4 !== null) return { bits: 32, n: v4 };
  const v6 = parseV6(s);
  return v6 === null ? null : { bits: 128, n: v6 };
}
const ones = (len: number, bits: number): bigint => (((1n << BigInt(len)) - 1n) << BigInt(bits - len));
/** ipaddress.ip_network(text), strict: null when Python raises ValueError. */
function parseNetwork(text: string): { bits: 32 | 128; n: bigint; len: number } | null {
  const slash = text.indexOf("/");
  const addr = parseIp(slash < 0 ? text : text.slice(0, slash));
  if (addr === null || (slash >= 0 && text.indexOf("/", slash + 1) >= 0)) return null;
  let len: number = addr.bits;
  if (slash >= 0) {
    const m = text.slice(slash + 1);
    if (/^[0-9]+$/.test(m) && m.length <= 3) len = +m;
    else if (addr.bits === 32 && m.includes(".")) {
      const mask = parseV4(m);
      if (mask === null) return null;
      const fits = (mask: bigint): number => { for (let l = 0; l <= 32; l++) if (ones(l, 32) === mask) return l; return -1; };
      len = fits(mask);
      if (len < 0) { len = fits(~mask & 0xffffffffn); if (len < 0) return null; }
    } else return null;
    if (len > addr.bits) return null;
  }
  const host = addr.n & ~ones(len, addr.bits) & ((1n << BigInt(addr.bits)) - 1n);
  return host === 0n ? { bits: addr.bits, n: addr.n, len } : null;
}
function cidrOk(net: string, v: J): boolean {
  const ip = parseIp(v), network = parseNetwork(net);
  if (ip === null || network === null || ip.bits !== network.bits) return false;
  const mask = ones(network.len, network.bits);
  return (ip.n & mask) === (network.n & mask);
}
const inNet = (ip: Ip, net: string): boolean => cidrOk(net, ipText(ip));
function ipText(ip: Ip): string {
  if (ip.bits === 32) return [24n, 16n, 8n, 0n].map((sh) => String((ip.n >> sh) & 255n)).join(".");
  return Array.from({ length: 8 }, (_, i) => ((ip.n >> BigInt(112 - 16 * i)) & 0xffffn).toString(16)).join(":");
}
// CPython 3.13 ipaddress: the networks `is_private` covers, and the global exceptions inside them.
const PRIVATE_V4 = ["0.0.0.0/8", "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/29", "192.0.0.170/31",
  "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "255.255.255.255/32"];
const GLOBAL_V4_EXCEPT = ["192.0.0.9/32", "192.0.0.10/32"];
const PRIVATE_V6 = ["::1/128", "::/128", "::ffff:0:0/96", "64:ff9b:1::/48", "100::/64", "2001::/23", "2001:db8::/32", "2002::/16",
  "3fff::/20", "5f00::/16", "fc00::/7", "fe80::/10"];
const GLOBAL_V6_EXCEPT = ["2001:1::1/128", "2001:1::2/128", "2001:3::/32", "2001:4:112::/48", "2001:20::/28", "2001:30::/28"];
function isGlobalIp(ip: Ip): boolean {
  if (ip.bits === 32) {
    if (GLOBAL_V4_EXCEPT.some((n) => inNet(ip, n))) return true;
    return !PRIVATE_V4.some((n) => inNet(ip, n)) && !inNet(ip, "100.64.0.0/10");
  }
  if ((ip.n >> 32n) === 0xffffn) return isGlobalIp({ bits: 32, n: ip.n & 0xffffffffn });
  if (GLOBAL_V6_EXCEPT.some((n) => inNet(ip, n))) return true;
  return !PRIVATE_V6.some((n) => inNet(ip, n));
}
function privateHost(h: string): boolean {
  if (h === "localhost" || h === "localhost.localdomain" || h.endsWith(".localhost")) return true;
  const ip = parseIp(h);
  return ip !== null && !isGlobalIp(ip);
}
function subpathOk(c: J, v: J): boolean {
  if (typeof v !== "string" || v.includes("\x00") || !v.startsWith("/")) return false;
  const root = c.root.replace(/\/+$/, "") || "/";
  const n = normpath(v);
  return n === root || n.startsWith(root === "/" ? root : root + "/");
}
/** shlex.split(v) in POSIX mode for text with no backslash: words, 'single' and "double" quoted runs joined; null on an open quote. */
function shlexSplit(text: string): string[] | null {
  const out: string[] = [];
  let cur: string | null = null, quote: string | null = null;
  for (const ch of text) {
    if (quote !== null) { if (ch === quote) quote = null; else cur += ch; continue; }
    if (ch === "'" || ch === '"') { quote = ch; cur ??= ""; continue; }
    if (" \t\r\n".includes(ch)) { if (cur !== null) { out.push(cur); cur = null; } continue; }
    cur = (cur ?? "") + ch;
  }
  if (quote !== null) return null;
  if (cur !== null) out.push(cur);
  return out;
}

const CHECKS: Record<string, (c: J, v: J, vf: boolean) => boolean> = {
  wildcard: () => true,
  exact: (c, v, vf) => same(v, c.value) && typeof v === typeof c.value && vf === isFloat(c, "value", c.value),
  one_of: (c, v, vf) => c.values.some((x: J, i: number) => same(v, x) && typeof v === typeof x && vf === isFloat(c.values, i, x)),
  not_one_of: (c, v) => !c.values.some((x: J) => same(v, x)),
  range: (c, v) => num(v) && (!("min" in c) || v >= c.min) && (!("max" in c) || v <= c.max),
  pattern: (c, v) => typeof v === "string" && fnmatch(v, c.pattern),
  regex: (c, v) => typeof v === "string" && new RegExp("^(?:" + c.regex + ")$").test(v),
  cidr: (c, v) => cidrOk(c.network, v),
  url_pattern: (c, v) => {
    const p = urlParts(v); if (!p) return false;
    const norm = p[2] !== "/" ? normpath(p[2]) : "/";
    const prefix = (c.pathPrefix ?? "/").replace(/\/+$/, "");
    return c.schemes.includes(p[0]) && hostOk(p[1], c.hosts) && (!prefix || norm === prefix || norm.startsWith(prefix + "/"));
  },
  url_safe: (c, v) => {
    const p = urlParts(v); if (!p) return false;
    if (!(c.schemes ?? ["https"]).includes(p[0])) return false;
    if ((c.denyPrivate ?? true) && privateHost(p[1])) return false;
    return !("hosts" in c) || hostOk(p[1], c.hosts);
  },
  subpath: subpathOk,
  shlex: (c, v) => {
    if (typeof v !== "string" || /[;&|`$<>\n\r(){}\\*?!#~]/.test(v)) return false;
    const argv = shlexSplit(v);
    return argv !== null && argv.length > 0 && c.allow.some((a: J) => pyEq(a, argv[0]));
  },
  contains: (c, v) => Array.isArray(v) && c.values.every((x: J) => v.some((y: J) => same(x, y))),
  subset: (c, v) => Array.isArray(v) && v.every((x: J) => c.values.some((y: J) => same(x, y))),
  all: (c, v, vf) => c.of.every((x: J) => check(x, v, vf)),
  any: (c, v, vf) => c.of.some((x: J) => check(x, v, vf)),
  not: (c, v, vf) => !check(c.of, v, vf),
  cel: (c, v, vf) => celHolds(c.expr, { value: v }, vf),
};
const REQUIRED: Record<string, string[]> = { exact: ["value"], one_of: ["values"], not_one_of: ["values"], pattern: ["pattern"],
  regex: ["regex"], cidr: ["network"], url_pattern: ["schemes", "hosts"], subpath: ["root"], shlex: ["allow"],
  contains: ["values"], subset: ["values"], all: ["of"], any: ["of"], not: ["of"], cel: ["expr"] };

// Per type, in check order, each member's shape (constraints._SHAPES): [member, kind, required].
const MEMBER_SHAPES: Record<string, [string, string, boolean][]> = {
  one_of: [["values", "list", true]], not_one_of: [["values", "list", true]],
  range: [["min", "number", false], ["max", "number", false]], pattern: [["pattern", "str", true]],
  regex: [["regex", "str", true]], cidr: [["network", "str", true]],
  url_pattern: [["schemes", "strlist", true], ["hosts", "strlist", true], ["pathPrefix", "str", false]],
  url_safe: [["schemes", "strlist", false], ["hosts", "strlist", false], ["denyPrivate", "bool", false]],
  subpath: [["root", "str", true]], shlex: [["allow", "list", true]], contains: [["values", "list", true]],
  subset: [["values", "list", true]], all: [["of", "nonempty", true]], any: [["of", "nonempty", true]],
  cel: [["expr", "str", true]],
};
function shapeOk(kind: string, v: J): boolean {
  switch (kind) {
    case "number": return typeof v === "number";
    case "str": return typeof v === "string";
    case "bool": return typeof v === "boolean";
    case "strlist": return Array.isArray(v) && v.every((x) => typeof x === "string");
    default: return Array.isArray(v) && (kind === "list" || v.length > 0);
  }
}
/** constraints.problem: null for a well-formed constraint, else the code both verifiers report. */
export function constraintProblem(c: J): string | null {
  if (!isObj(c) || typeof c.type !== "string" || !Object.hasOwn(CHECKS, c.type)) return "constraint_unknown";
  const t: string = c.type;
  const missing = (REQUIRED[t] ?? []).find((k) => !own(c, k));
  if (missing !== undefined) return `constraint_member_missing:${t}.${missing}`;
  if (t === "range" && !own(c, "min") && !own(c, "max")) return "constraint_range_unbounded";
  for (const [member, kind, required] of MEMBER_SHAPES[t] ?? [])
    if ((required || own(c, member)) && !shapeOk(kind, c[member])) return `constraint_member_invalid:${t}.${member}`;
  for (const nested of t === "all" || t === "any" ? c.of : t === "not" ? [c.of] : []) {
    const found = constraintProblem(nested);
    if (found) return found;
  }
  if (t === "regex") { try { new RegExp(c.regex); } catch { return "constraint_regex_invalid"; } }
  if (t === "cidr" && parseNetwork(c.network) === null) return "constraint_cidr_invalid";
  if (t === "cel") return celSyntaxProblem(c.expr);
  return null;
}
function validateC(c: J): void { const found = constraintProblem(c); if (found) throw new Error(found); }
export function check(c: J, v: J, vf: boolean = typeof v === "number" && !Number.isInteger(v)): boolean { validateC(c); return CHECKS[c.type](c, v, vf); }

function sameTypeNarrows(ch: J, p: J): boolean {
  switch (p.type) {
    case "range": return (!("min" in p) || ("min" in ch && ch.min >= p.min)) && (!("max" in p) || ("max" in ch && ch.max <= p.max));
    case "pattern": {
      const pp: string = p.pattern;
      return ch.pattern === pp || (pp.endsWith("*") && !pp.includes("[") && !pp.slice(0, -1).includes("?")
        && !pp.slice(0, -1).includes("*") && ch.pattern.startsWith(pp.slice(0, -1)));
    }
    case "cidr": { const [cb, cn] = ch.network.split("/"); const [, pn] = p.network.split("/"); return +(cn ?? 32) >= +(pn ?? 32) && cidrOk(p.network, cb); }
    case "subpath": return subpathOk(p, ch.root);
    case "url_pattern": {
      const cp = (ch.pathPrefix ?? "/").replace(/\/+$/, ""), pp = (p.pathPrefix ?? "/").replace(/\/+$/, "");
      return ch.schemes.every((s: string) => p.schemes.includes(s)) && (!pp || cp === pp || cp.startsWith(pp + "/")) && hostsNarrow(ch.hosts, p.hosts);
    }
    case "url_safe":
      return (ch.schemes ?? ["https"]).every((s: string) => (p.schemes ?? ["https"]).includes(s))
        && (!("hosts" in p) || ("hosts" in ch && hostsNarrow(ch.hosts, p.hosts)))
        && ((ch.denyPrivate ?? true) || !(p.denyPrivate ?? true));
    case "shlex": case "subset": { const k = p.type === "shlex" ? "allow" : "values"; return ch[k].every((x: J) => p[k].some((y: J) => same(x, y))); }
    case "contains": case "not_one_of": return p.values.every((x: J) => ch.values.some((y: J) => same(x, y)));
    default: return same(ch, p);
  }
}
export function narrows(ch: J, p: J): boolean {
  validateC(ch); validateC(p);
  if (p.type === "wildcard" || same(ch, p)) return true;
  if (ch.type === "exact" || ch.type === "one_of") return (ch.type === "exact" ? [ch.value] : ch.values).every((v: J, i: number) => check(p, v, isFloat(ch.type === "exact" ? ch : ch.values, ch.type === "exact" ? "value" : i, v)));
  if (ch.type === "any") return ch.of.every((x: J) => narrows(x, p));
  if (p.type === "all") return p.of.every((x: J) => narrows(ch, x));
  if (ch.type === "all") return ch.of.some((x: J) => narrows(x, p));
  if (p.type === "any") return p.of.some((x: J) => narrows(ch, x));
  if (ch.type !== p.type) return false;
  return sameTypeNarrows(ch, p);
}

// ---------- quorum ----------

export function requestHash(tool: string, args: string, permit: string, proposer?: J, history?: J): string {
  const body: J = { argsSha256: args, permitId: permit, tool };
  if (proposer !== undefined && proposer !== null) body.proposer = proposer;
  if (history !== undefined && history !== null) body.historyDigest = history;
  return digestOf(body);
}

function deputyProblem(vote: J, policy: J, at: string): [string | null, string | null] {
  const body = vote.body, d = vote.delegation, db = isObj(d) ? d.body : null;
  if (!isObj(db)) return ["deputy_without_delegation", null];
  const who = String(body.onBehalfOf), raw = policy.approvers[who];
  if (raw === undefined || db.delegator !== who) return ["deputy_for_unknown_approver", null];
  if (!sigOk(raw, DEPUTY_DOMAIN, db, d.sig)) return ["deputy_delegation_unverified", null];
  if (db.policyId !== policy.policyId || db.deputy !== body.approver) return ["deputy_delegation_mismatch", null];
  if (db.deputy in policy.approvers || Object.values(policy.approvers).includes(db.deputyKey)) return ["deputy_is_an_approver", null];
  if ("role" in body && !(db.roles ?? []).includes(body.role)) return ["deputy_role_not_delegated", null];
  try { if (!(ts(db.notBefore) <= ts(at) && ts(at) <= ts(db.expiresAt))) return ["deputy_delegation_outside_window", null]; }
  catch { return ["deputy_delegation_outside_window", null]; }
  return [null, String(db.deputyKey)];
}

function voteProblem(vote: J, policy: J, request: string, at: string, proposer: J): string | null {
  const body = isObj(vote) ? vote.body : null;
  if (!isObj(body)) return "vote_shape";
  let raw: J, countedAs: string;
  if ("onBehalfOf" in body) {
    const [problem, k] = deputyProblem(vote, policy, at);
    if (problem) return problem;
    raw = k; countedAs = String(body.onBehalfOf);
  } else { raw = policy.approvers[String(body.approver)]; countedAs = String(body.approver); }
  if (raw === undefined || raw === null) return "vote_from_unknown_approver";
  if (proposer !== undefined && proposer !== null && (proposer === countedAs || proposer === String(body.approver))) return "vote_by_proposer";
  if (!sigOk(raw, VOTE_DOMAIN, body, vote.sig)) return "vote_signature_unverified";
  if (body.policyId !== policy.policyId) return "vote_for_another_policy";
  if (body.requestHash !== request) return "vote_for_another_request";
  const roles = policy.roles ?? {};
  if (Object.keys(roles).length) {
    if (!(body.role in roles) || !roles[body.role].members.includes(countedAs)) return "vote_role_not_held";
  }
  let live: boolean;
  try { live = ts(body.issuedAt) <= ts(at) && ts(at) <= ts(body.expiresAt); } catch { return "vote_time_invalid"; }
  return live ? null : "vote_outside_window";
}

export function countVotes(policy: J, request: string, votes: J[], at: string, proposer?: J): { status: string; ignored: string[] } {
  const seen = new Map<string, J>(), ignored: string[] = [];
  for (const vote of votes) {
    const problem = voteProblem(vote, policy, request, at, proposer);
    if (problem) { ignored.push(problem); continue; }
    const who = vote.body.onBehalfOf ?? vote.body.approver;
    if (seen.has(who)) { ignored.push("vote_duplicate_approver"); continue; }
    seen.set(who, vote);
  }
  const yes = [...seen.keys()].filter((w) => seen.get(w).body.decision === "approve");
  const no = [...seen.keys()].filter((w) => seen.get(w).body.decision === "reject");
  const roles = policy.roles ?? {};
  const rolesMet = Object.entries(roles).every(([r, s]: J) => yes.filter((w) => seen.get(w).body.role === r).length >= s.min);
  const rolesDead = Object.entries(roles).some(([r, s]: J) => s.members.length - no.filter((w) => seen.get(w).body.role === r).length < s.min);
  let n = Object.keys(policy.approvers).length;
  if (proposer !== undefined && proposer !== null && proposer in policy.approvers) n -= 1;
  const status = yes.length >= policy.threshold && rolesMet ? "approved" : n - no.length < policy.threshold || rolesDead ? "refused" : "pending";
  return { status, ignored };
}

function verifyQuorumEvidence(ev: J, pinned: Record<string, J>, request: string, at: string): string {
  const policy = ev.policy ?? {}, trusted = pinned[String(policy.policyId)];
  if (trusted === undefined) return "quorum_policy_not_pinned";
  if (digestOf(trusted) !== ev.policyDigest || digestOf(policy) !== digestOf(trusted)) return "quorum_policy_differs_from_pinned";
  if (ev.requestHash !== request) return "quorum_for_another_request";
  if (trusted.proposerBound && !ev.proposer) return "quorum_proposer_unbound";
  const r = countVotes(trusted, request, ev.votes ?? [], at, ev.proposer);
  if (r.ignored.length) return `quorum_vote_invalid:${r.ignored[0]}`;
  if (r.status === "approved") return "ok";
  return r.status === "refused" ? "quorum_refused" : "quorum_pending";
}

// ---------- quorum policy shape ----------

/** quorum._key_identity: the text of a raw key or the canonical JSON of a key object; null names no key. */
function keyIdentity(v: J): string | null {
  if (typeof v === "string" && v) return "s:" + v;
  if (isObj(v)) { try { return "o:" + canonical(v); } catch { return null; } }
  return null;
}
const isInt = (holder: J, key: string | number, v: J): boolean => typeof v === "number" && Number.isInteger(v) && !isFloat(holder, key, v);
/** quorum.policy_problem: null for a well-formed policy, else the code both verifiers report. */
export function quorumPolicyProblem(policy: J): string | null {
  if (!isObj(policy)) return "quorum_policy_shape";
  const approvers = own(policy, "approvers") ? policy.approvers : null, m = own(policy, "threshold") ? policy.threshold : null;
  if (!isObj(approvers) || !Object.keys(approvers).length) return "quorum_policy_without_approvers";
  const n = Object.keys(approvers).length;
  if (!isInt(policy, "threshold", m) || m < 1 || m > n) return "quorum_threshold_out_of_range";
  const keys = Object.values(approvers).map(keyIdentity);
  if (keys.includes(null)) return "quorum_approver_key_shape";
  if (new Set(keys).size !== n) return "quorum_approvers_share_a_key";
  if (own(policy, "proposerBound") && typeof policy.proposerBound !== "boolean") return "quorum_proposer_bound_shape";
  const roles = own(policy, "roles") ? policy.roles : {};
  if (!isObj(roles)) return "quorum_roles_shape";
  for (const role of sortedKeys(roles)) {
    const spec = roles[role], members = own(spec, "members") ? spec.members : null, k = own(spec, "min") ? spec.min : null;
    if (!Array.isArray(members) || !members.length || !members.every((x) => typeof x === "string" && own(approvers, x))
      || !isInt(spec, "min", k) || k < 1 || k > members.length) return `quorum_role_invalid:${role}`;
  }
  if (Object.values(roles).reduce((sum: number, spec: J) => sum + spec.min, 0) > n) return "quorum_roles_unsatisfiable";
  return null;
}

// ---------- grants ----------

// RFC 7800 confirmation: exactly one method, jkt (RFC 9449) or x5t#S256 (RFC 8705), a SHA-256 thumbprint in
// canonical base64url. A grant without one is a bearer token and is refused, as by the Python verifier.
const CNF_METHODS = ["jkt", "x5t#S256"];
export function cnfProblem(cnf: J): string | null {
  if (cnf === undefined || cnf === null) return "cnf_missing";
  if (!isObj(cnf) || Object.keys(cnf).length !== 1) return "cnf_invalid";
  const [[method, value]] = Object.entries(cnf) as [string, J][];
  if (!CNF_METHODS.includes(method) || typeof value !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(value)) return "cnf_invalid";
  const raw = Buffer.from(value, "base64url");
  return raw.length === 32 && raw.toString("base64url") === value ? null : "cnf_invalid";
}

// A standing grant (grants.py): "sponsor" {issuer, subject} and "reviewBy" together, notBefore < reviewBy <= expiresAt.
function standingProblem(body: J): string | null {
  if (("sponsor" in body) !== ("reviewBy" in body)) return "grant_standing_incomplete";
  if (!("sponsor" in body)) return null;
  const s = body.sponsor;
  if (!isObj(s) || Object.keys(s).sort().join(",") !== "issuer,subject" || !Object.values(s).every((v) => typeof v === "string" && v)) return "grant_sponsor_invalid";
  try { sponsorId(s.issuer, s.subject); } catch { return "grant_sponsor_invalid"; }
  const r = ts(body.reviewBy);  // each parsed by timesProblem first
  return ts(body.notBefore) < r && r <= ts(body.expiresAt) ? null : "grant_review_invalid";
}

const nonNegInt = (holder: J, key: string): boolean => own(holder, key) && isInt(holder, key, holder[key]) && holder[key] >= 0;
function budgetProblem(b: J): string | null {
  if (b === undefined || b === null) return null;
  if (!isObj(b) || !Object.keys(b).length || Object.keys(b).some((k) => k !== "uses" && k !== "spend")) return "grant_budget_shape";
  if (own(b, "uses") && !nonNegInt(b, "uses")) return "grant_budget_uses";
  const sp = b.spend;
  if (own(b, "spend") && (!isObj(sp) || Object.keys(sp).sort().join(",") !== "arg,max" || typeof sp.arg !== "string"
    || typeof sp.max !== "number" || sp.max < 0)) return "grant_budget_spend";
  return null;
}
function toolsProblem(tools: J): string | null {
  if (!isObj(tools) || !Object.keys(tools).length) return "grant_tools_empty";
  for (const tool of sortedKeys(tools)) {
    const spec = tools[tool];
    if (!isObj(spec) || !own(spec, "args") || !isObj(spec.args)) return `grant_tool_shape:${tool}`;
    const level = own(spec, "approval") ? spec.approval : "none";
    if (level !== "none" && level !== "required") return `grant_approval_level:${tool}`;
    for (const arg of sortedKeys(spec.args)) {
      const found = constraintProblem(spec.args[arg]);
      if (found) return `grant_arg_constraint_invalid:${tool}.${arg}:${found}`;
    }
    const when = own(spec, "when") ? spec.when : [];
    if (!Array.isArray(when) || !when.every((w) => typeof w === "string")) return `grant_when_shape:${tool}`;
    for (let n = 0; n < when.length; n++) {
      const found = celSyntaxProblem(when[n]);
      if (found) return `grant_when_invalid:${tool}.${n}:${found}`;
    }
    if (own(spec, "quorum")) {
      const found = quorumPolicyProblem(spec.quorum);
      if (found) return `grant_quorum_invalid:${tool}:${found}`;
      if (spec.quorum.proposerBound !== true) return `grant_quorum_must_bind_proposer:${tool}`;
      if (spec.approval !== "required") return `grant_quorum_without_required_approval:${tool}`;
    }
  }
  return null;
}
function issuerKeyOk(text: J): boolean {
  try { const raw = unb64(text); if (raw.length !== 32) return false; rawKey(raw); return true; } catch { return false; }
}
/** grants.validate_body, code for code and in its order: null for a well-formed grant body, else the first defect. */
export function bodyProblem(body: J): string | null {
  if (!isObj(body)) return "grant_shape";
  const found = cnfProblem(body.cnf) ?? timesProblem(body) ?? toolsProblem(body.tools);
  if (found) return found;
  if (!nonNegInt(body, "maxDepth")) return "grant_max_depth";
  const ctx = own(body, "context") ? body.context : null;
  if (!isObj(ctx)) return "grant_context_shape";
  for (const key of sortedKeys(ctx)) {
    const c = constraintProblem(ctx[key]);
    if (c) return `grant_context_constraint_invalid:${key}:${c}`;
  }
  const rest = budgetProblem(body.budget) ?? standingProblem(body);
  if (rest) return rest;
  return issuerKeyOk(body.issuerKey) ? null : "grant_issuer_key_invalid";
}

function narrowingProblem(ch: J, p: J): string | null {
  if (ch.issuerKey !== p.holderKey) return "child_not_issued_by_parent_holder";
  if (ts(ch.notBefore) < ts(p.notBefore) || ts(ch.expiresAt) > ts(p.expiresAt)) return "child_window_wider_than_parent";
  if ("sponsor" in p) {
    if (!isObj(ch.sponsor) || ch.sponsor.issuer !== p.sponsor.issuer || ch.sponsor.subject !== p.sponsor.subject) return "child_changes_sponsor";
    if (ts(ch.reviewBy) > ts(p.reviewBy)) return "child_review_later_than_parent";
  } else if ("sponsor" in ch) return "child_adds_sponsor";
  if ((p.maxDepth ?? 0) < 1) return "parent_forbids_delegation";
  if ((ch.maxDepth ?? 0) > p.maxDepth - 1) return "child_depth_wider_than_parent";
  for (const k of sortedKeys(p.context ?? {})) {
    if (!own(ch.context ?? {}, k)) return `child_drops_context:${k}`;
    if (!narrows(ch.context[k], p.context[k])) return `child_widens_context:${k}`;
  }
  const pb = p.budget, cb = ch.budget;
  if (pb !== undefined && pb !== null) {
    if (cb === undefined || cb === null) return "child_drops_budget";
    if ("uses" in pb && (cb.uses ?? pb.uses + 1) > pb.uses) return "child_budget_wider_than_parent";
    if ("spend" in pb && (!cb.spend || cb.spend.arg !== pb.spend.arg || cb.spend.max > pb.spend.max)) return "child_spend_wider_than_parent";
  }
  for (const tool of sortedKeys(ch.tools)) {
    const spec = ch.tools[tool], ps = own(p.tools, tool) ? p.tools[tool] : undefined;
    if (ps === undefined) return `child_adds_tool:${tool}`;
    if ((ps.approval ?? "none") === "required" && (spec.approval ?? "none") !== "required") return `child_drops_approval:${tool}`;
    if ((ps.when ?? []).some((w: string) => !(spec.when ?? []).includes(w))) return `child_drops_condition:${tool}`;
    if ("quorum" in ps) { const q = quorumWidening(spec.quorum, ps.quorum); if (q) return `${q}:${tool}`; }
    const added = sortedKeys(spec.args).filter((n) => !own(ps.args, n));
    if (added.length) return `child_adds_argument:${tool}.${added[0]}`;
    const dropped = sortedKeys(ps.args).filter((n) => !own(spec.args, n));
    if (dropped.length) return `child_drops_argument:${tool}.${dropped[0]}`;
    for (const name of sortedKeys(spec.args)) if (!narrows(spec.args[name], ps.args[name])) return `child_widens_constraint:${tool}.${name}`;
  }
  return null;
}
function quorumWidening(ch: J, p: J): string | null {
  if (ch === undefined || ch === null) return "child_drops_quorum";
  if (p.proposerBound && !ch.proposerBound) return "child_unbinds_proposer";
  for (const [who, k] of Object.entries(p.approvers)) if (ch.approvers[who] !== k) return "child_removes_approver";
  const added = Object.keys(ch.approvers).filter((w) => !(w in p.approvers)).length;
  if (ch.threshold < p.threshold + added) return "child_lowers_threshold";
  for (const [r, s] of Object.entries(p.roles ?? {}) as [string, J][]) {
    const cs = (ch.roles ?? {})[r];
    if (cs === undefined) return `child_drops_role:${r}`;
    if (cs.min < s.min || !cs.members.every((m: string) => s.members.includes(m))) return `child_widens_role:${r}`;
  }
  return null;
}

function verifyChain(chain: J[], roots: Set<string>, at: string): [J | null, string] {
  if (!chain.length) return [null, "grant_chain_empty"];
  let when: number;
  try { when = ts(at); } catch { return [null, "grant_use_time_invalid"]; }
  const issuers: string[] = [], digests: string[] = [];
  let result = "ok", prev: J = null;
  for (let depth = 0; depth < chain.length; depth++) {
    const body = isObj(chain[depth]) ? chain[depth].body : null;
    if (!isObj(body)) { result = `grant_shape:${depth}`; break; }
    const problem = bodyProblem(body);
    if (problem) { result = `grant_invalid:${depth}:${problem}`; break; }
    const issuer = keyId(rawKey(unb64(body.issuerKey)));  // bodyProblem proved it decodes
    if (!sigOk(body.issuerKey, GRANT_DOMAIN, body, chain[depth].sig)) { result = `grant_signature_unverified:${depth}`; break; }
    if (prev === null) { if (body.parent !== null || !roots.has(issuer)) { result = "grant_root_untrusted"; break; } }
    else {
      if (body.parent !== digests[digests.length - 1]) { result = `grant_parent_mismatch:${depth}`; break; }
      const problem = narrowingProblem(body, prev);
      if (problem) { result = `${problem}:${depth}`; break; }
    }
    issuers.push(issuer); digests.push(digestOf(body)); prev = body;
  }
  for (let depth = 0; depth < issuers.length; depth++) {
    const body = chain[depth].body;
    if (!(ts(body.notBefore) <= when && when <= ts(body.expiresAt))) return [null, `grant_outside_window:${depth}`];
    if ("reviewBy" in body && when >= ts(body.reviewBy)) return [null, `grant_review_overdue:${depth}`];
  }
  return result !== "ok" ? [null, result] : [chain[chain.length - 1].body, "ok"];
}

// Every body of a structurally verified chain by digest (grants.chain_digests); empty when the chain does not verify.
export function chainDigests(chain: J[], roots: Set<string>): Record<string, J> {
  const out: Record<string, J> = {};
  let prev: J = null;
  for (let depth = 0; depth < chain.length; depth++) {
    const body = isObj(chain[depth]) ? chain[depth].body : null;
    if (!isObj(body) || bodyProblem(body)) return {};
    const issuer = keyId(rawKey(unb64(body.issuerKey)));
    if (!sigOk(body.issuerKey, GRANT_DOMAIN, body, chain[depth].sig)) return {};
    if (prev === null) { if (body.parent !== null || !roots.has(issuer)) return {}; }
    else if (body.parent !== digestOf(prev) || narrowingProblem(body, prev)) return {};
    out[digestOf(body)] = body; prev = body;
  }
  return out;
}

function checkCall(leaf: J, tool: string, args: J, ctx: J): string {
  for (const k of sortedKeys(leaf.context ?? {})) if (!own(ctx, k) || !check(leaf.context[k], ctx[k], isFloat(ctx, k, ctx[k]))) return `context_violation:${k}`;
  const spec = own(leaf.tools, tool) ? leaf.tools[tool] : undefined;
  if (spec === undefined) return "tool_not_granted";
  if (!isObj(args)) return "arguments_not_an_object";
  const extra = sortedKeys(args).filter((k) => !own(spec.args, k));
  if (extra.length) return `argument_not_granted:${extra[0]}`;
  for (const name of sortedKeys(spec.args)) if (!check(spec.args[name], own(args, name) ? args[name] : null, isFloat(args, name, args[name]))) return `constraint_violation:${name}`;
  const when: string[] = spec.when ?? [];
  for (let n = 0; n < when.length; n++) if (!celHolds(when[n], { args, tool, ctx })) return `condition_violation:${n}`;
  return (spec.approval ?? "none") === "required" ? "approval_required" : "ok";
}

export function verifyGrantAllow(chain: J[], tool: string, args: J, at: string, roots: Set<string>, ctx: J = {}): J {
  const [leaf, reason] = verifyChain(chain, roots, at);
  if (leaf === null) return { decision: "deny", reason, grantDigest: null };
  const v = checkCall(leaf, tool, args, ctx ?? {});
  return { decision: v === "ok" ? "allow" : v === "approval_required" ? "needs_approval" : "deny", reason: v, grantDigest: digestOf(leaf) };
}

// ---------- identity ----------

const MEMBERS = ["issuer", "subject", "clientId", "audience", "authMethod", "source", "tokenDigest", "issuedAt", "expiresAt", "kid", "key", "keyThumbprint", "jwksDigest"];
const OPTIONAL = ["tenant", "act", "cnf"];
const SOURCES = ["jwt-access-token", "id-token", "jwt-assertion", "id-jag"];
const AUTH = ["none", "client_secret_post", "client_secret_basic", "client_secret_jwt", "private_key_jwt", "tls_client_auth", "self_signed_tls_client_auth"];
const THUMB: Record<string, string[]> = { RSA: ["e", "kty", "n"], EC: ["crv", "kty", "x", "y"], OKP: ["crv", "kty", "x"] };

export function jwkThumbprint(jwk: J): string {
  const m = THUMB[String(jwk.kty)];
  if (!m || m.some((k) => !(k in jwk))) throw new Error("jwk_unsupported");
  const obj: J = {}; for (const k of m) obj[k] = jwk[k];
  return createHash("sha256").update(JSON.stringify(obj)).digest("base64url");
}
function principalShape(p: J): string | null {
  if (!isObj(p)) return "principal_malformed";
  if (MEMBERS.some((m) => !(m in p))) return "principal_member_missing";
  if (Object.keys(p).some((k) => !MEMBERS.includes(k) && !OPTIONAL.includes(k))) return "principal_member_unknown";
  if (typeof p.issuer !== "string" || !p.issuer.startsWith("https://")) return "principal_issuer_invalid";
  if (!["subject", "clientId", "kid", "keyThumbprint"].every((m) => typeof p[m] === "string" && p[m])) return "principal_malformed";
  if (!Array.isArray(p.audience) || !p.audience.length || new Set(p.audience.map(String)).size !== p.audience.length) return "principal_malformed";
  if (!SOURCES.includes(p.source) || !AUTH.includes(p.authMethod)) return "principal_malformed";
  if (["tokenDigest", "jwksDigest"].some((m) => typeof p[m] !== "string" || !/^[0-9a-f]{64}$/.test(p[m]))) return "principal_malformed";
  if (!isObj(p.key) || ["d", "p", "q", "dp", "dq", "qi", "k"].some((k) => k in p.key)) return "principal_key_invalid";
  if ("cnf" in p && cnfProblem(p.cnf)) return "principal_cnf_invalid";
  return null;
}
function actSubjects(act: J): string[] | null {
  const out: string[] = [];
  while (act !== undefined && act !== null) { if (!isObj(act) || typeof act.sub !== "string") return null; out.push(act.sub); act = act.act; }
  return out;
}
function checkPrincipal(p: J, at: string, pins: Record<string, string[]>): string | null {
  const s = principalShape(p); if (s) return s;
  let thumb: string;
  try { thumb = jwkThumbprint(p.key); } catch { return "principal_key_invalid"; }
  if (thumb !== p.keyThumbprint) return "principal_thumbprint_mismatch";
  if (p.key.kid !== p.kid) return "principal_kid_mismatch";
  let i: number, e: number, w: number;
  try { i = ts(p.issuedAt); e = ts(p.expiresAt); w = ts(at); } catch { return "principal_malformed"; }
  if (e <= i) return "principal_malformed";
  if (w < i) return "principal_not_yet_valid";
  if (w >= e) return "principal_expired";
  const pinned = pins[p.issuer];
  if (pinned === undefined) return "principal_issuer_untrusted";
  // an issuer's pins are a list of thumbprints; a pin written as one string is refused, never searched as text
  if (!Array.isArray(pinned) || !pinned.includes(thumb)) return "principal_key_not_pinned";
  if ("act" in p && actSubjects(p.act) === null) return "principal_act_malformed";
  return null;
}
const ROLES = ["user", "agent", "sponsor", "approver"];
const AUTONOMOUS = ["session", "standingGrant"];
const SESSION_ID_MAX = 256;
const PRINTABLE = /^[\x21-\x7e]+$/;
export function sponsorId(issuer: J, subject: J): string {
  if (typeof issuer !== "string" || !issuer.startsWith("https://") || issuer.includes("#") || typeof subject !== "string" || !subject) throw new Error("sponsor_id_invalid");
  const id = `${issuer}#${subject}`;
  if (id.length > 512 || !PRINTABLE.test(id)) throw new Error("sponsor_id_invalid");
  return id;
}
export interface AutonomousTrust { sponsors?: Record<string, [string, string][]> | null; standingGrants?: Record<string, J> | null }
function sessionProblem(s: J, at: string): string | null {
  if (!isObj(s) || Object.keys(s).sort().join(",") !== "id,startedAt" || typeof s.id !== "string" || !s.id.length || s.id.length > SESSION_ID_MAX || !PRINTABLE.test(s.id)) return "principals_session_malformed";
  let started: number;
  try { started = ts(s.startedAt); } catch { return "principals_session_malformed"; }
  return started > ts(at) ? "principals_session_not_started" : null;
}
function grantProblems(block: J, at: string, grants: Record<string, J>): string[] {
  const d = block.standingGrant;
  if (typeof d !== "string" || !/^[0-9a-f]{64}$/.test(d)) return ["principals_standing_grant_malformed"];
  const g = Object.prototype.hasOwnProperty.call(grants, d) ? grants[d] : undefined;
  if (g === undefined) return ["principals_standing_grant_unknown"];
  if (!("sponsor" in g) || !("reviewBy" in g)) return ["principals_standing_grant_not_standing"];
  const out: string[] = [], w = ts(at);
  if (w < ts(g.notBefore)) out.push("principals_standing_grant_not_yet_valid");
  else if (w >= ts(g.expiresAt)) out.push("principals_standing_grant_expired");
  else if (w >= ts(g.reviewBy)) out.push("principals_standing_grant_unreviewed");
  const cnf = block.agent.cnf;
  if (cnf === undefined || cnf === null || !pyEq(cnf, g.cnf ?? null)) out.push("principals_standing_grant_not_held_by_agent");
  if (block.sponsor.issuer !== g.sponsor.issuer || block.sponsor.subject !== g.sponsor.subject || Object.keys(g.sponsor).length !== 2) out.push("principals_sponsor_not_the_grant_sponsor");
  return out;
}
function checkAutonomous(block: J, at: string, pins: Record<string, string[]>, approvers: Set<string> | null, auto: AutonomousTrust): [string[], string | null] {
  if ("user" in block) return [["principals_autonomous_has_user"], null];
  let problems: string[] = ([["principals_need_agent", "agent"], ["principals_need_sponsor", "sponsor"], ["principals_need_session", "session"], ["principals_need_standing_grant", "standingGrant"]] as const)
    .filter(([, m]) => !(m in block)).map(([code]) => code);
  if (problems.length) return [problems, null];
  const grants = auto.standingGrants ?? {};
  const grant = typeof block.standingGrant === "string" && Object.prototype.hasOwnProperty.call(grants, block.standingGrant) ? grants[block.standingGrant] : undefined;
  for (const r of ["agent", "approver"]) if (r in block) { const p = checkPrincipal(block[r], at, pins); if (p) problems.push(`principal_${r}:${p}`); }
  // the sponsor answered for the grant when it was issued; with no resolved grant the grant's own refusal decides
  const sp = grant === undefined || !("notBefore" in grant) ? null : checkPrincipal(block.sponsor, String(grant.notBefore), pins);
  if (sp) problems.push(`principal_sponsor:${sp}`);
  const sess = sessionProblem(block.session, at); if (sess) problems.push(sess);
  if (problems.length) return [problems, null];
  problems = grantProblems(block, at, grants);
  if (auto.sponsors === undefined || auto.sponsors === null) problems.push("principals_sponsors_not_pinned");
  else if (!(auto.sponsors[block.agent.clientId] ?? []).some(([i, s]) => i === block.sponsor.issuer && s === block.sponsor.subject)) problems.push("principal_sponsor_not_registered");
  if ("approver" in block && approvers === null) problems.push("principal_approver_without_approval");
  else if (approvers !== null && !("approver" in block)) problems.push("principals_need_approver");
  else if ("approver" in block && approvers !== null && !approvers.has(block.approver.subject)) problems.push("principal_approver_not_an_approval_signer");
  return problems.length ? [problems, null] : [[], "autonomous"];
}
export function checkPrincipals(block: J, at: string, pins: Record<string, string[]>, approvers: Set<string> | null, auto: AutonomousTrust = {}): [string[], string | null] {
  if (!isObj(block) || !Object.keys(block).length || Object.keys(block).some((k) => !ROLES.includes(k) && !AUTONOMOUS.includes(k))) return [["principals_malformed"], null];
  if (Object.keys(block).some((k) => AUTONOMOUS.includes(k))) return checkAutonomous(block, at, pins, approvers, auto);
  const problems: string[] = [];
  for (const r of ROLES) if (r in block) { const p = checkPrincipal(block[r], at, pins); if (p) problems.push(`principal_${r}:${p}`); }
  if (!("user" in block) || !("agent" in block)) problems.push("principals_need_user_and_agent");
  if (problems.length) return [problems, null];
  const chain = "act" in block.user ? actSubjects(block.user.act) ?? [] : [];
  if (chain.length && ![block.agent.subject, block.agent.clientId].includes(chain[0])) return [["principal_act_names_another_agent"], null];
  if ("approver" in block && (approvers === null || approvers.size === 0)) return [["principal_approver_without_approval"], null];
  if ("approver" in block && !approvers!.has(block.approver.subject)) return [["principal_approver_not_an_approval_signer"], null];
  return [[], strictShortfall(block, approvers) === null ? "strict" : "basic"];
}

// What keeps a human-session block that passed from strict (identity.strict_shortfall): the user credential's act
// chain, the sponsor, and the approver exactly when an approval admitted the call.
export function strictShortfall(block: J, approvers: Set<string> | null): string | null {
  if (!("act" in (block.user ?? {}))) return "act-absent";
  if (!("sponsor" in block)) return "sponsor-absent";
  if (approvers !== null && approvers.size > 0 && !("approver" in block)) return "approver-absent";
  return null;
}

// ---------- journal ----------

export interface TrustDoc { grantRootKeyIds?: string[]; quorumPolicies?: Record<string, J>; identityIssuers?: Record<string, string[]>; identityProfile?: string; possessionSkewSeconds?: number; agentSponsors?: Record<string, [string, string][]>; standingGrants?: J[][] }

// The proof an allow rested on (possession.possession_record): it must name the key the leaf grant's cnf confirms.
const POSSESSION_MEMBERS: Record<string, string[]> = { dpop: ["iat", "jkt", "jti", "method"], mtls: ["method", "x5t#S256"] };
const MAX_JTI_BYTES = 128, DEFAULT_SKEW = 120, REPLAY_GRACE = 5;
function possessionRecordProblem(record: J, cnf: J): string | null {
  if (!isObj(record) || typeof record.method !== "string" || !Object.hasOwn(POSSESSION_MEMBERS, record.method)) return "possession_record_malformed";
  const want = POSSESSION_MEMBERS[record.method], keys = Object.keys(record).sort();
  if (keys.length !== want.length || keys.some((k, i) => k !== want[i])) return "possession_record_malformed";
  if (record.method === "dpop" && (typeof record.iat !== "number" || !Number.isInteger(record.iat) || typeof record.jti !== "string"
      || !record.jti || Buffer.byteLength(record.jti, "utf8") > MAX_JTI_BYTES)) return "possession_record_malformed";
  const member = record.method === "dpop" ? "jkt" : "x5t#S256";
  if (!isObj(cnf) || !Object.hasOwn(cnf, member) || typeof record[member] !== "string" || record[member] !== String(cnf[member])) return "possession_not_the_grant_key";
  return null;
}

// A DPoP proof spent by two permits inside its lifetime (possession.duplicate_proofs): a replay.
function duplicateProofs(bodies: [number, J][], skew: number): string[] {
  const found: string[] = [], first = new Map<string, [number, number, J]>();
  for (const [n, body] of bodies) {
    const pred = body.predicate;
    if (!isObj(pred) || pred.phase !== "authorize" || !isObj(pred.authority)) continue;
    const rec = pred.authority.possession;
    if (!isObj(rec) || rec.method !== "dpop" || typeof rec.jkt !== "string" || typeof rec.jti !== "string"
        || typeof rec.iat !== "number" || !Number.isInteger(rec.iat)) continue;
    const key = `${rec.jkt}.${rec.jti}`, permit = pred.permitId ?? null;
    let used: number;
    try { used = ts(pred.at) / 1e6; } catch { found.push(`line_${n}:dpop_proof_use_time_invalid`); continue; }
    const earlier = first.get(key);
    const live = earlier !== undefined && used <= earlier[1] + skew + REPLAY_GRACE;
    if (live && earlier![2] !== permit) { found.push(`line_${n}:dpop_proof_replayed:${earlier![0]}`); continue; }
    if (!live) first.set(key, [n, rec.iat, permit]);
  }
  return found;
}

function checkAuthority(pred: J, trust: TrustDoc | null, problems: string[], where: string): boolean {
  const reason = pred.reason;
  if (reason !== "grant" && reason !== "quorum") return false;
  const ev = pred.authority;
  if (!isObj(ev) || ev.kind !== reason) { problems.push(`${where}:authority_evidence_missing:${reason}`); return true; }
  if (trust === null) { problems.push(`${where}:authority_trust_not_pinned:${reason}`); return true; }
  const at = String(pred.at), pinned = { ...(trust.quorumPolicies ?? {}) };
  const quorumOutcome = (q: J, carried?: J): string => {
    if (carried) pinned[String(carried.policyId)] = carried;
    return verifyQuorumEvidence(q, pinned, requestHash(String(pred.tool), String(pred.argsSha256), String(pred.permitId), q.proposer, q.historyDigest), at);
  };
  if (reason === "quorum") { const o = quorumOutcome(ev); if (o !== "ok") problems.push(`${where}:${o}`); return true; }
  const raw = Buffer.from(ev.argsB64 ?? "", "base64");
  if (sha256Hex(raw) !== pred.argsSha256) problems.push(`${where}:authority_args_are_not_the_call_arguments`);
  const args = raw.length ? parseReceived(raw) : null;
  const v = verifyGrantAllow(ev.chain ?? [], String(pred.tool), args, at, new Set(trust.grantRootKeyIds ?? []), ev.ctx ?? {});
  if (v.decision === "needs_approval" && isObj(ev.quorum)) {
    const o = quorumOutcome(ev.quorum, ev.chain[ev.chain.length - 1].body.tools[String(pred.tool)].quorum);
    if (o !== "ok") problems.push(`${where}:grant_approval_failed:${o}`);
  } else if (v.decision !== "allow") problems.push(`${where}:grant_${v.decision}:${v.reason}`);
  if (v.grantDigest && v.grantDigest !== pred.grantDigest) problems.push(`${where}:grant_digest_differs_from_record`);
  if ("possession" in ev && v.grantDigest) {
    const p = possessionRecordProblem(ev.possession, ev.chain[ev.chain.length - 1].body.cnf);
    if (p) problems.push(`${where}:${p}`);
  }
  return true;
}

// The approving voters of the quorum an allow's authority carries (journal._vote_signers): read only once that quorum
// held, and a quorum with an invalid vote does not hold, so each was counted.
function voteSigners(pred: J): Set<string> {
  const names = new Set<string>();
  const a = pred.authority ?? {}, q = a.quorum ?? a;
  for (const v of q.votes ?? []) if (isObj(v) && v.body?.decision === "approve") names.add(String(v.body?.onBehalfOf ?? v.body?.approver));
  return names;
}

// ---------- approval-binding/v1 reader ----------

const APPROVAL_BINDING_CONTRACT = identifier("agent-evidence-vectors/contract/approval-binding/v1");
const APPROVAL_CHECKS = ["contract_id_missing", "contract_id_unknown", "approval_not_cited", "approval_not_issued",
  "approval_id_ambiguous", "approval_request_completed_twice", "approval_not_granted", "approval_not_enforced",
  "approval_replayed", "transition_status_unknown", "approval_superseded", "renewal_transition_missing",
  "renewal_binding_invalid", "key_not_bound", "key_retired", "principal_mismatch", "event_phase_mismatch",
  "payload_mismatch", "approval_outside_validity", "effect_already_closed", "comparison_unavailable",
  "release_not_served_at_decision"] as const;
const BOUND_FIELDS = ["event", "payloadSha256", "phase", "principal", "target", "tool"];
const CLOSED_EFFECT_STATES = ["CONSUMED", "UNCERTAIN_CLOSE"];
const GRANTS = ["approved", "approved-with-corrections"];
const TRANSITION_STATUSES = ["proposed", "accepted"];
/** The reason a record the reader cannot read is denied with (records.BINDING_MALFORMED). */
export const BINDING_MALFORMED = "approval_binding_malformed";

/** Python's `==` on parsed JSON: 1 == 1.0 == True, dicts by members, lists by position. */
function pyEq(a: J, b: J): boolean {
  if (a === undefined) a = null;
  if (b === undefined) b = null;
  const num = (x: J): J => (typeof x === "boolean" ? Number(x) : x);
  if (Array.isArray(a) || Array.isArray(b))
    return Array.isArray(a) && Array.isArray(b) && a.length === b.length && a.every((x: J, i: number) => pyEq(x, b[i]));
  if (isObj(a) || isObj(b)) {
    if (!isObj(a) || !isObj(b)) return false;
    const ka = Object.keys(a);
    return ka.length === Object.keys(b).length && ka.every((k) => k in b && pyEq(a[k], b[k]));
  }
  return num(a) === num(b);
}
/** Python truthiness of a parsed JSON value. */
const truthy = (x: J): boolean => !(x === null || x === undefined || x === false || x === 0 || x === "" ||
  (Array.isArray(x) && x.length === 0) || (isObj(x) && Object.keys(x).length === 0));
/** `obj[key]` that raises where Python raises KeyError, so a record missing a field read is refused, not read as a pass. */
function req(obj: J, key: string): J {
  if (!isObj(obj) || !(key in obj)) throw new Error(`KeyError: ${key}`);
  return obj[key];
}
const getOr = (obj: J, key: string, dflt: J): J => (isObj(obj) && key in obj ? obj[key] : dflt);
const instant = (text: J): number => ts(text);
/** Python's `x in container` on parsed JSON: a list by `==`, a string by substring, an object by key; a TypeError
 *  where Python raises one (a non-string in a string, an unhashable key, a number or null container). */
function pyIn(x: J, container: J): boolean {
  if (Array.isArray(container)) return container.some((e: J) => pyEq(x, e));
  if (typeof container === "string") { if (typeof x !== "string") throw new TypeError("in <string> needs a string"); return container.includes(x); }
  if (isObj(container)) { if (Array.isArray(x) || isObj(x)) throw new TypeError("unhashable type"); return typeof x === "string" && Object.hasOwn(container, x); }
  throw new TypeError("argument of this type is not iterable");
}
/** Python's `record.get(key, default)`: an AttributeError where the record is not an object. */
function pyGet(obj: J, key: string, dflt: J): J {
  if (!isObj(obj)) throw new TypeError("not a mapping");
  return key in obj ? obj[key] : dflt;
}

function approvalAmbiguous(record: J): boolean {
  const approval = req(record, "approval");
  return getOr(record, "presentedApprovals", []).some((o: J) => pyEq(req(o, "approvalId"), req(approval, "approvalId")) && !pyEq(o, approval));
}
function requestCompletedTwice(record: J): boolean {
  const approval = req(record, "approval");
  return getOr(record, "presentedApprovals", []).some((o: J) => pyEq(req(o, "requestId"), req(approval, "requestId")) &&
    !pyEq(req(o, "approvalId"), req(approval, "approvalId")));
}
function transitionStatusUnknown(record: J): boolean {
  const id = req(req(record, "approval"), "approvalId");
  return getOr(record, "transitions", []).some((t: J) => !TRANSITION_STATUSES.some((s) => pyEq(req(t, "status"), s)) &&
    [req(t, "predecessorApprovalId"), req(t, "successorApprovalId")].some((x: J) => pyEq(id, x)));
}
/** The earliest instant any `retiredKeys` entry retires the approval's key, or null; every entry naming it is read. */
function retiredAt(record: J): number | null {
  const approval = req(record, "approval");
  const entries = pyGet(pyGet(record, "retiredKeys", {}), String(req(approval, "approver")), []);
  const instants = entries.filter((e: J) => pyEq(req(e, "keyId"), req(approval, "keyId"))).map((e: J) => instant(req(e, "retiredAt")));
  return instants.length ? Math.min(...instants) : null;
}
function approvalSuperseded(record: J): boolean {
  const approval = req(record, "approval"), used = instant(req(req(record, "use"), "usedAt"));
  return getOr(record, "transitions", []).some((t: J) => pyEq(req(t, "status"), "accepted") &&
    pyEq(req(t, "predecessorApprovalId"), req(approval, "approvalId")) && instant(req(t, "acceptedAt")) <= used);
}
function acceptedInto(record: J): J[] {
  const approval = req(record, "approval"), used = instant(req(req(record, "use"), "usedAt"));
  return getOr(record, "transitions", []).filter((t: J) => pyEq(req(t, "status"), "accepted") &&
    pyEq(req(t, "successorApprovalId"), req(approval, "approvalId")) && instant(req(t, "acceptedAt")) <= used);
}
const renewed = (record: J): boolean => pyEq(getOr(req(record, "use"), "authorityForm", null), "renewed");
function transitionBinds(record: J, approval: J, t: J): boolean {
  const candidates: J[] = [];
  for (const p of getOr(record, "presentedApprovals", []))
    if (pyEq(req(p, "approvalId"), req(t, "predecessorApprovalId")) && !candidates.some((c) => pyEq(c, p))) candidates.push(p);
  if (candidates.length !== 1 || !pyEq(req(t, "mode"), "exclusive-replacement")) return false;
  const pred = candidates[0], decision = getOr(approval, "decisionId", null);
  return decision !== null && pyEq(req(t, "successorDecisionId"), decision) &&
    pyEq(req(t, "predecessorDecisionId"), getOr(pred, "decisionId", null)) && !pyEq(decision, getOr(pred, "decisionId", null)) &&
    BOUND_FIELDS.every((f) => pyEq(getOr(pred, f, null), getOr(approval, f, null)));
}
function renewalInvalid(record: J): boolean {
  if (!renewed(record)) return false;
  const approval = req(record, "approval"), accepted = acceptedInto(record);
  return accepted.length > 0 && !accepted.some((t) => transitionBinds(record, approval, t));
}
function useMatchesApproval(record: J, used: Buffer): boolean {
  const approval = req(record, "approval"), use = req(record, "use");
  return pyEq(req(use, "tool"), req(approval, "tool")) && pyEq(req(use, "target"), req(approval, "target")) &&
    sha256Hex(used) === req(approval, "payloadSha256");
}

/** The decision and reason of the published approval-binding/v1 reader for one record and its payload bytes. */
export function judgeApprovalBinding(record: J, payload: Buffer): { decision: string; reason: string } {
  const name = String(getOr(getOr(record, "use", {}), "payloadFile", "payload.bin"));
  if (name.includes("/") || ["", ".", ".."].includes(name)) return { decision: "deny", reason: "payload_file_unsafe" };
  try { return approvalVerdict(record, payload); } catch { return { decision: "deny", reason: BINDING_MALFORMED }; }
}

function approvalVerdict(record: J, payload: Buffer): { decision: string; reason: string } {
  const approval = req(record, "approval"), use = req(record, "use");
  const failures: Record<string, () => boolean> = {
    contract_id_missing: () => !("contractId" in record),
    contract_id_unknown: () => !pyEq(canonicalIdentifier(getOr(record, "contractId", APPROVAL_BINDING_CONTRACT)), APPROVAL_BINDING_CONTRACT),
    approval_not_cited: () => !pyEq(getOr(use, "approvalId", null), req(approval, "approvalId")),
    approval_not_issued: () => !pyIn(req(approval, "approvalId"), pyGet(record, "issuedApprovalIds", [])),
    approval_id_ambiguous: () => approvalAmbiguous(record),
    approval_request_completed_twice: () => requestCompletedTwice(record),
    approval_not_granted: () => !GRANTS.some((g) => pyEq(pyGet(approval, "outcome", null), g)),
    approval_not_enforced: () => !pyEq(pyGet(record, "enforcement", null), "enforce"),
    approval_replayed: () => pyIn(req(approval, "approvalId"), pyGet(record, "consumedApprovalIds", [])),
    transition_status_unknown: () => transitionStatusUnknown(record),
    approval_superseded: () => approvalSuperseded(record),
    renewal_transition_missing: () => renewed(record) && acceptedInto(record).length === 0,
    renewal_binding_invalid: () => renewalInvalid(record),
    key_not_bound: () => !pyEq(pyGet(req(record, "trustedKeys"), String(req(approval, "approver")), null), req(approval, "keyId")) &&
      retiredAt(record) === null,
    key_retired: () => { const r = retiredAt(record); return r !== null && instant(req(approval, "issuedAt")) >= r; },
    principal_mismatch: () => !pyEq(req(use, "principal"), req(approval, "principal")),
    event_phase_mismatch: () => !(pyEq(req(use, "event"), req(approval, "event")) && pyEq(req(use, "phase"), req(approval, "phase"))),
    payload_mismatch: () => !useMatchesApproval(record, payload),
    approval_outside_validity: () => {
      const at = instant(req(use, "usedAt"));
      return !(instant(req(approval, "issuedAt")) <= at && at < instant(req(approval, "expiresAt")));
    },
    effect_already_closed: () => {
      const key = getOr(use, "effectKey", null);
      return key !== null && CLOSED_EFFECT_STATES.includes(getOr(getOr(record, "effectRegistry", {}), String(key), null));
    },
    comparison_unavailable: () => !pyEq(req(req(record, "policyRelease"), "lookup"), "ok"),
    release_not_served_at_decision: () => {
      const rel = req(record, "policyRelease"), decided = instant(req(record, "decisionTime"));
      return !(instant(req(rel, "firstServedAt")) <= decided && decided <= instant(req(rel, "lastServedAt")) + Number(req(rel, "graceSeconds")) * 1e6);
    },
  };
  for (const check of APPROVAL_CHECKS) if (failures[check]()) return { decision: "deny", reason: check };
  return { decision: "allow", reason: "bound" };
}

// ---------- uncertain_effect/v1 reader ----------

const EFFECT_CONTRACT = identifier("agent-evidence-vectors/predicate/v1/uncertain-effect");
const UNKNOWN_REPLIES = ["timeout", "connection_lost", "worker_crashed"];
// What set an attempt off when it is not a first dispatch or a plain retry: the engine redelivered
// the task, a replay or rewind re-ran the step, or a completion signal ran it.
const TRIGGER_KINDS = ["redelivery", "replay", "completion"];
const REPLIES = ["confirmed", "no_effect", ...UNKNOWN_REPLIES];
const ANSWERS = ["present", "absent"];
const OUTCOMES = ["committed", "not_run", "unknown"];
const STOP_REPORTS = ["quiescent", "effect_after_stop", "not_established"];
const AUTHORITY_ANSWERS = ["accepted", "refused"];
const EFFECT_CHECKS = ["contract_id_missing", "contract_id_unknown", "operation_identity_missing", "idempotency_key_args_changed",
  "idempotency_key_follows_trigger", "dispatch_beyond_lease", "retry_after_unknown", "owner_effect_unaccounted", "duplicate_effect",
  "unknown_released", "outcome_settled_without_authority",
  "outcome_disagrees_with_authority", "authority_used_after_revocation", "effect_after_stop_reported_quiescent",
  "stop_straddle_reported_settled"];

function finalAbsentBetween(record: J, start: number, end: number | null): boolean {
  return req(record, "reconciliations").some((r: J) => pyEq(req(r, "result"), "absent") && truthy(req(r, "final")) &&
    instant(req(r, "at")) >= start && (end === null || instant(req(r, "at")) <= end));
}
function settledOutcome(record: J): string {
  const attempts: J[] = req(record, "attempts");
  if (attempts.some((a) => pyEq(req(a, "reply"), "confirmed")) || req(record, "reconciliations").some((r: J) => pyEq(req(r, "result"), "present")))
    return "committed";
  const unknown = attempts.filter((a) => UNKNOWN_REPLIES.includes(req(a, "reply"))).map((a) => instant(req(a, "dispatchedAt")));
  return !unknown.length || finalAbsentBetween(record, Math.max(...unknown), null) ? "not_run" : "unknown";
}
function outsideLease(attempt: J, leases: J[]): boolean {
  const held = leases.filter((l) => pyEq(req(l, "worker"), getOr(attempt, "worker", null)) && pyEq(req(l, "fencingToken"), getOr(attempt, "fencingToken", null)));
  if (!held.length) return true;
  const sent = instant(req(attempt, "dispatchedAt")), lease = held[0];
  if (!(instant(req(lease, "acquiredAt")) <= sent && sent < instant(req(lease, "expiresAt")))) return true;
  return leases.some((o) => req(o, "fencingToken") > req(lease, "fencingToken") && instant(req(o, "acquiredAt")) <= sent);
}
function protectedRetry(record: J, earlier: J, later: J): boolean {
  const owner = req(record, "effectOwner"), sent = instant(req(earlier, "dispatchedAt")), resent = instant(req(later, "dispatchedAt"));
  const retention = getOr(owner, "keyRetentionSeconds", null);
  const dedup = truthy(req(owner, "deduplicatesByKey")) && pyEq(getOr(later, "idempotencyKey", null), getOr(earlier, "idempotencyKey", null)) &&
    (retention === null || (resent - sent) / 1e6 <= retention);
  return dedup || finalAbsentBetween(record, sent, resent);
}
function unprotectedRetry(record: J): boolean {
  const attempts = [...req(record, "attempts")].sort((a: J, b: J) => instant(req(a, "dispatchedAt")) - instant(req(b, "dispatchedAt")));
  return attempts.some((earlier: J, i: number) => UNKNOWN_REPLIES.includes(req(earlier, "reply")) &&
    attempts.slice(i + 1).some((later: J) => !protectedRetry(record, earlier, later)));
}
function stopOf(record: J): J | null {
  const stop = getOr(record, "stop", null);
  return isObj(stop) && truthy(stop) ? stop : null;
}
/** True when the owner's commit lies wholly after the acknowledgement, false when wholly at or before, null when it straddles it. */
function commitAfterAck(stop: J): boolean | null {
  const commit = getOr(stop, "ownerCommit", null);
  if (!truthy(commit)) return false;
  const ack = instant(req(stop, "acknowledgedAt"));
  if (instant(req(commit, "notBefore")) > ack) return true;
  if (instant(req(commit, "notAfter")) <= ack) return false;
  return null;
}
function effectFirstFailure(record: J): string | null {
  const failures: Record<string, () => boolean> = {
    contract_id_missing: () => !("contractId" in record),
    contract_id_unknown: () => !pyEq(canonicalIdentifier(getOr(record, "contractId", EFFECT_CONTRACT)), EFFECT_CONTRACT),
    operation_identity_missing: () => [req(record, "operation"), ...req(record, "attempts")].some((item: J) =>
      ["idempotencyKey", "argsDigest"].some((k) => !truthy(getOr(item, k, null)))),
    idempotency_key_args_changed: () => { const op = req(record, "operation");
      return req(record, "attempts").some((a: J) => pyEq(getOr(a, "idempotencyKey", null), getOr(op, "idempotencyKey", null)) &&
        !pyEq(getOr(a, "argsDigest", null), getOr(op, "argsDigest", null))); },
    idempotency_key_follows_trigger: () => { const key = getOr(req(record, "operation"), "idempotencyKey", null);
      return req(record, "attempts").some((a: J) => { const trigger = getOr(a, "trigger", null);
        return truthy(trigger) && TRIGGER_KINDS.includes(getOr(trigger, "kind", null)) && !pyEq(getOr(a, "idempotencyKey", null), key); }); },
    dispatch_beyond_lease: () => { const leases = getOr(record, "leases", null) ?? []; return leases.length > 0 && req(record, "attempts").some((a: J) => outsideLease(a, leases)); },
    retry_after_unknown: () => unprotectedRetry(record),
    owner_effect_unaccounted: () =>
      req(record, "ownerEffects") > req(record, "attempts").filter((a: J) => !pyEq(req(a, "reply"), "no_effect")).length,
    duplicate_effect: () => req(record, "ownerEffects") > 1,
    unknown_released: () => { const r = getOr(record, "reservation", null); return r !== null && settledOutcome(record) === "unknown" && !truthy(req(r, "charged")); },
    outcome_settled_without_authority: () => settledOutcome(record) === "unknown" && ["committed", "not_run"].includes(req(req(record, "reported"), "outcome")),
    outcome_disagrees_with_authority: () => { const s = settledOutcome(record); return s !== "unknown" && !pyEq(req(req(record, "reported"), "outcome"), s); },
    authority_used_after_revocation: () => { const stop = stopOf(record); if (stop === null) return false; const revoked = instant(req(stop, "revokedAt"));
      return getOr(stop, "authorityChecks", []).some((c: J) => pyEq(req(c, "result"), "accepted") && instant(req(c, "at")) >= revoked); },
    effect_after_stop_reported_quiescent: () => { const stop = stopOf(record); return stop !== null && commitAfterAck(stop) === true && pyEq(req(stop, "reported"), "quiescent"); },
    stop_straddle_reported_settled: () => { const stop = stopOf(record); return stop !== null && commitAfterAck(stop) === null && !pyEq(req(stop, "reported"), "not_established"); },
  };
  for (const name of EFFECT_CHECKS) if (failures[name]()) return name;
  return null;
}
function domainRequire(ok: boolean, field: string): void { if (!ok) throw new Error(`record: ${field} is outside the contract`); }
function domainObjects(record: J, name: string): J[] {
  const items = getOr(record, name, null);
  domainRequire(items === null || (Array.isArray(items) && items.every(isObj)), name);
  return items ?? [];
}
function domainObject(record: J, name: string): J {
  const item = getOr(record, name, null);
  domainRequire(item === null || isObj(item), name);
  return item ?? {};
}
const domainWord = (item: J, name: string, allowed: string[]): void => domainRequire(!(name in item) || allowed.includes(item[name]), name);
const domainFlag = (item: J, name: string): void => domainRequire(typeof getOr(item, name, false) === "boolean", name);
/** Refuse a value the contract does not allow before any check reads it (Python raises CaseError here, and so do we). */
function checkEffectDomains(record: J): void {
  const count = getOr(record, "ownerEffects", 0);
  domainRequire(Number.isInteger(count) && count >= 0, "ownerEffects");
  for (const a of domainObjects(record, "attempts")) {
    domainWord(a, "reply", REPLIES);
    const trigger = getOr(a, "trigger", null);
    domainRequire(trigger === null || (isObj(trigger) && typeof getOr(trigger, "kind", null) === "string"), "trigger");
  }
  for (const r of domainObjects(record, "reconciliations")) { domainWord(r, "result", ANSWERS); domainFlag(r, "final"); }
  domainObjects(record, "leases");
  const owner = domainObject(record, "effectOwner");
  domainFlag(owner, "deduplicatesByKey");
  const retention = getOr(owner, "keyRetentionSeconds", null);
  domainRequire(retention === null || (typeof retention === "number" && retention >= 0), "keyRetentionSeconds");
  domainWord(domainObject(record, "reported"), "outcome", OUTCOMES);
  domainFlag(domainObject(record, "reservation"), "charged");
  const stop = domainObject(record, "stop");
  domainWord(stop, "reported", STOP_REPORTS);
  for (const c of domainObjects(stop, "authorityChecks")) domainWord(c, "result", AUTHORITY_ANSWERS);
}

/** The decision of the built-in uncertain_effect/v1 adapter: supported or contradicted, the first failing check, and the reported outcome. */
export function judgeUncertainEffect(record: J): { decision: string; reason: string; reported_outcome: string | null } {
  if (!isObj(record)) throw new Error("record: expected a JSON object");
  checkEffectDomains(record);
  const failure = effectFirstFailure(record);
  let reported: string | null = null;
  try { settledOutcome(record); reported = req(req(record, "reported"), "outcome"); } catch { reported = null; }
  return failure === null ? { decision: "supported", reason: "effect_held", reported_outcome: reported } : { decision: "contradicted", reason: failure, reported_outcome: reported };
}

// ---------- M-of-N recount of embedded human approvals ----------

function validatePolicy(policy: J): void {
  const approvers = policy.approvers, m = policy.threshold;
  if (!isObj(approvers) || !Object.keys(approvers).length) throw new Error("quorum_policy_without_approvers");
  if (!Number.isInteger(m) || m < 1 || m > Object.keys(approvers).length) throw new Error("quorum_threshold_out_of_range");
  if (new Set(Object.values(approvers).map(String)).size !== Object.keys(approvers).length) throw new Error("quorum_approvers_share_a_key");
  if (typeof (policy.proposerBound ?? false) !== "boolean") throw new Error("quorum_proposer_bound_shape");
  const roles = policy.roles ?? {};
  if (!isObj(roles)) throw new Error("quorum_roles_shape");
  let total = 0;
  for (const [role, spec] of Object.entries<J>(roles)) {
    const members = spec?.members, k = spec?.min;
    if (!Array.isArray(members) || !members.length || !members.every((x: J) => x in approvers) || !Number.isInteger(k) || k < 1 || k > members.length)
      throw new Error(`quorum_role_invalid:${role}`);
    total += k;
  }
  if (total > Object.keys(approvers).length) throw new Error("quorum_roles_unsatisfiable");
}

function countBindings(policy: J, bindings: J[]): { counted: Set<string>; problems: string[] } {
  validatePolicy(policy);
  const counted = new Set<string>(), problems: string[] = [];
  bindings.forEach((embedded, n) => {
    const approval = embedded?.record?.approval ?? {}, who = String(approval.approver ?? "");
    const raw = policy.approvers[who];
    if (raw === undefined) { problems.push(`binding_${n}:approver_not_in_policy`); return; }
    if (!sigOk(raw, APPROVAL_DOMAIN, approval, embedded.approvalSig)) { problems.push(`binding_${n}:approval_signature_unverified`); return; }
    if (approval.keyId !== keyId(rawKey(unb64(raw)))) { problems.push(`binding_${n}:approval_key_id_is_not_the_pinned_key`); return; }
    if (counted.has(who)) { problems.push(`binding_${n}:duplicate_approver`); return; }
    counted.add(who);
  });
  return { counted, problems };
}

const NO_APPROVAL_REQUIRED = "no_approval_required";
const RECONCILED_RETRY = "reconciled_absent_retry";

// The approvers an authorize record COUNTS (journal._check_approval), the only people its approver principal may name;
// null when no approval admitted the call.
function checkApproval(pred: J, problems: string[], where: string, trust: TrustDoc | null): Set<string> | null {
  if (pred.decision === "allow") {
    const before = problems.length;
    if (checkAuthority(pred, trust, problems, where)) {
      const votes = voteSigners(pred);
      return problems.length === before && votes.size ? votes : null;
    }
  }
  const bindings: J[] = pred.approvalBindings ?? [];
  if (!bindings.length) {
    if (pred.decision === "allow" && ![NO_APPROVAL_REQUIRED, RECONCILED_RETRY].includes(pred.reason)) problems.push(`${where}:allow_without_approval_binding`);
    return null;
  }
  const readerAllowed = new Set<string>();
  bindings.forEach((embedded, n) => {
    const payload = unb64(embedded.payloadB64);
    if (sha256Hex(payload) !== pred.argsSha256) problems.push(`${where}:binding_${n}:approval_payload_is_not_the_call_arguments`);
    const verdict = judgeApprovalBinding(embedded.record, payload);
    if (verdict.decision === "allow") readerAllowed.add(String(embedded.record?.approval?.approver));
    else if (pred.decision === "deny" && verdict.reason !== pred.reason && bindings.length === 1)
      problems.push(`${where}:deny_reason_mismatch:${pred.reason}:${verdict.reason}`);
  });
  // a deny counts nobody; its approver principal may name any approver whose binding it carries
  if (pred.decision !== "allow") return new Set(bindings.map((b) => String(b?.record?.approval?.approver)));
  if (trust === null) { problems.push(`${where}:authority_trust_not_pinned:approval`); return null; }
  const policy = (trust.quorumPolicies ?? {})[String(pred.approvalPolicyId)];
  if (policy === undefined) { problems.push(`${where}:approval_policy_not_pinned`); return null; }
  if (!pyEq(pred.threshold, policy.threshold)) problems.push(`${where}:threshold_not_pinned:${pyRepr(pred.threshold, isFloat(pred, "threshold", pred.threshold))}:${pyRepr(policy.threshold, isFloat(policy, "threshold", policy.threshold))}`);
  const { counted: signed, problems: sigProblems } = countBindings(policy, bindings);
  problems.push(...sigProblems.map((p) => `${where}:${p}`));
  const counted = [...signed].filter((a) => readerAllowed.has(a));
  if (counted.length < policy.threshold) problems.push(`${where}:approvals_below_threshold:${counted.length}:${policy.threshold}`);
  return counted.length ? new Set(counted) : null;
}

function checkEffect(pred: J, problems: string[], where: string): void {
  const record = pred.uncertainEffect;
  if (!truthy(record)) { problems.push(`${where}:effect_without_uncertain_effect_record`); return; }
  const verdict = judgeUncertainEffect(record);
  if (verdict.decision !== "supported") problems.push(`${where}:uncertain_effect_not_supported:${verdict.decision}:${verdict.reason}`);
  if (!pyEq(getOr(getOr(record, "operation", {}), "argsDigest", null), "sha256:" + String(pred.argsSha256))) problems.push(`${where}:effect_args_differ_from_call`);
  if (!pyEq(pred.outcome ?? null, verdict.reported_outcome)) problems.push(`${where}:outcome_field_differs_from_record`);
}

/** Python's str() of a parsed JSON scalar, for the failure text. */
function pyRepr(v: J, asFloat = false): string {
  if (v === null || v === undefined) return "None";
  if (typeof v === "boolean") return v ? "True" : "False";
  return asFloat && Number.isInteger(v) ? `${v}.0` : String(v);
}

// An autonomous call runs on the standing grant its block names (journal.py _standing_problems): an allow rests on
// it (a grant allow whose leaf it is), judged in the block's own agent and session; every intent and effect names it.
function standingProblems(pred: J, block: J): string[] {
  const named = block.standingGrant;
  const phase = pred.phase;
  if (phase === "intent" || phase === "effect") return pred.grantDigest === named ? [] : ["principals_standing_grant_not_the_authority"];
  if (phase !== "authorize" || pred.decision !== "allow") return [];
  const ev = pred.authority;
  const chain = isObj(ev) && Array.isArray(ev.chain) ? ev.chain : null;
  let leaf: string | null = null;
  try { leaf = chain && chain.length ? digestOf(chain[chain.length - 1].body) : null; } catch { leaf = null; }
  if (pred.reason !== "grant" || !isObj(ev) || ev.kind !== "grant" || leaf !== named || pred.grantDigest !== named)
    return ["principals_standing_grant_not_the_authority"];
  const ctx = ev.ctx ?? {};
  const own: Record<string, J> = { agent: block.agent.clientId, session: block.session.id };
  if (!isObj(ctx) || Object.entries(own).some(([k, v]) => k in ctx && !pyEq(ctx[k], v)))
    return ["principals_standing_context_not_the_block"];
  return [];
}

function checkLine(i: number, line: string, keys: KeyObject[], prev: string, trust: TrustDoc | null, seen: Record<string, J>,
                   counted: Map<string, Set<string> | null>): [J | null, string[]] {
  const where = `line_${i}`, problems: string[] = [];
  let body: J;
  try { const [payload] = openEnvelope(parseReceived(Buffer.from(line, "utf8")), keys); body = parseReceived(payload); }
  catch (e) { return [null, [`${where}:${(e as Error).message}`]]; }
  const pred = body.predicate ?? {};
  if (pred.seq !== i) problems.push(`${where}:seq_mismatch:${pred.seq ?? "None"}:${i}`);
  if (pred.prev !== prev) problems.push(`${where}:chain_broken`);
  // The approvals are judged first, because an approver principal may name only an approver this record counts; their
  // problems are reported after the identity's.
  const approvalProblems: string[] = [];
  let approvers: Set<string> | null = null;
  if (isToolCall(body)) {
    const pid = String(pred.permitId);
    if (pred.phase === "authorize") {
      approvers = checkApproval(pred, approvalProblems, where, trust);
      if (pred.decision === "allow" && !counted.has(pid)) counted.set(pid, approvers);
    } else approvers = counted.get(pid) ?? null; // an intent or effect answers to the approvers its permit's allow counted
  }
  if (isToolCall(body) && (pred.principals === undefined || pred.principals === null)
      && pred.phase === "authorize" && trust !== null && trust.identityProfile === "strict")
    problems.push(`${where}:principals_missing`);
  if (isToolCall(body) && pred.principals !== undefined && pred.principals !== null) {
    if (trust === null) problems.push(`${where}:principals_but_no_trust_pinned`);
    else {
      const block = pred.principals;
      const autonomous = isObj(block) && Object.keys(block).some((k) => AUTONOMOUS.includes(k));
      let grants: Record<string, J> | null = null;
      if (autonomous) {
        grants = { ...seen };
        const roots = new Set(trust.grantRootKeyIds ?? []);
        const chains = [...(trust.standingGrants ?? [])];
        if (isObj(pred.authority) && Array.isArray(pred.authority.chain)) chains.push(pred.authority.chain);
        for (const chain of chains) Object.assign(grants, chainDigests(chain, roots));
      }
      const sponsors = trust.agentSponsors && Object.keys(trust.agentSponsors).length ? trust.agentSponsors : null;
      const [found, grade] = checkPrincipals(block, String(pred.at), trust.identityIssuers ?? {}, approvers, { sponsors, standingGrants: grants });
      problems.push(...found.map((p) => `${where}:${p}`));
      if (grade === "autonomous") problems.push(...standingProblems(pred, block).map((p) => `${where}:${p}`));
      if (grade !== null && trust.identityProfile === "strict" && grade !== "strict" && grade !== "autonomous")
        problems.push(`${where}:principals_below_strict:${strictShortfall(block, approvers)}`);
    }
  }
  // Keep the verified bodies of an allow's authority chain, so later intent and effect lines resolve the standing
  // grant they name without the auditor pinning it.
  if (isToolCall(body) && trust !== null && pred.phase === "authorize" && pred.decision === "allow"
      && isObj(pred.authority) && Array.isArray(pred.authority.chain))
    Object.assign(seen, chainDigests(pred.authority.chain, new Set(trust.grantRootKeyIds ?? [])));
  if (isToolCall(body)) {
    problems.push(...approvalProblems);
    if (pred.phase === "effect") checkEffect(pred, problems, where);
  } else if (!isToolCall(body) && pred.phase === undefined && body.predicateType?.endsWith("/governance-step"))
    problems.push(`${where}:governance_step_not_ported`);
  return [body, problems];
}

function spendOf(budget: J, args: J): number {
  if (!budget || !("spend" in budget) || !isObj(args)) return 0;
  const v = args[budget.spend.arg] ?? 0;
  return typeof v === "number" ? v : Infinity;
}

function parties(block: J): J {
  if (!isObj(block)) return null;
  const out: Record<string, J> = {};
  for (const [role, p] of Object.entries(block)) out[role] = isObj(p) ? [p.issuer ?? null, p.subject ?? null] : p;
  return out;
}

function crossChecks(bodies: [number, J][], skew: number): string[] {
  const problems: string[] = [];
  const uses = new Map<string, number>(), spent = new Map<string, number>(), charged = new Set<J>();
  for (const [i, body] of bodies) {
    const pred = body.predicate ?? {};
    if (!isToolCall(body) || pred.phase !== "authorize" || pred.decision !== "allow" || charged.has(pred.permitId)) continue;
    const ev = pred.authority;
    if (!isObj(ev) || ev.kind !== "grant") continue;
    let charges: [string, J, J][];
    try {
      const args = ev.argsB64 ? parseReceived(Buffer.from(ev.argsB64, "base64")) : null;
      // A malformed body is skipped: its allow is refused already (grant_deny), and its budget has no members to count.
      charges = (ev.chain ?? []).filter((g: J) => isObj(g) && isObj(g.body) && bodyProblem(g.body) === null)
        .map((g: J) => [digestOf(g.body), g.body.budget, args]);
    } catch { continue; }
    if (charges.length) charged.add(pred.permitId);
    for (const [d, budget, args] of charges) {
      if (!budget) continue;
      uses.set(d, (uses.get(d) ?? 0) + 1);
      spent.set(d, (spent.get(d) ?? 0) + spendOf(budget, args));
      if ("uses" in budget && uses.get(d)! > budget.uses) problems.push(`line_${i}:grant_budget_exceeded:${d.slice(0, 12)}`);
      if ("spend" in budget && spent.get(d)! > budget.spend.max) problems.push(`line_${i}:grant_spend_exceeded:${d.slice(0, 12)}`);
    }
  }
  problems.push(...duplicateProofs(bodies.filter(([, b]) => isToolCall(b)), skew));
  const grantOf = new Map<J, J>(), allowed = new Set<J>(), effects = new Map<J, number>(), intents = new Map<J, number>();
  const partiesOf = new Map<J, J>(); // pid -> who its first allow names, role by role (journal._parties)
  for (const [i, body] of bodies) {
    if (!isToolCall(body)) continue;
    const pred = body.predicate, pid = pred.permitId ?? null, phase = pred.phase;
    const later = phase === "intent" || phase === "effect" || (phase === "authorize" && pred.decision === "allow");
    // a credential may be refreshed between a permit's records; the parties they name may not change
    if (later && partiesOf.has(pid) && pred.principals !== undefined && pred.principals !== null && !pyEq(parties(pred.principals), partiesOf.get(pid)))
      problems.push(`line_${i}:principals_differ_from_permit:${phase}`);
    if (phase === "authorize" && pred.decision === "allow") {
      if (!partiesOf.has(pid)) partiesOf.set(pid, parties(pred.principals));
      if (pred.reason === "reconciled_absent_retry" && !allowed.has(pid)) problems.push(`line_${i}:reconciled_retry_without_earlier_permit`);
      allowed.add(pid);
      if (!grantOf.has(pid)) grantOf.set(pid, pred.grantDigest ?? null);
    } else if ((phase === "intent" || phase === "effect") && grantOf.has(pid) && (pred.grantDigest ?? null) !== grantOf.get(pid))
      problems.push(`line_${i}:grant_differs_from_permit:${phase}`);
    if (phase === "intent") {
      if (!allowed.has(pid)) problems.push(`line_${i}:intent_without_permit`);
      if (!intents.has(pid)) intents.set(pid, i);
    } else if (phase === "effect") {
      if (!allowed.has(pid)) problems.push(`line_${i}:effect_without_permit`);
      if (effects.has(pid) && pred.outcome === "committed") problems.push(`line_${i}:second_effect_record_for_permit`);
      effects.set(pid, i);
    }
  }
  for (const [pid, i] of intents) if (!effects.has(pid)) problems.push(`line_${i}:open_intent_no_effect_record:${String(pid).slice(0, 12)}`);
  return problems;
}

export interface Report { verdict: string; records: number; verified: number; failures: string[]; checkpoint: string }

// A journal file's records are its whole lines. Bytes after the last newline are an append a writer killed mid-write
// never finished: not a record, and counted apart (probity_records.journal._whole_lines; the writer's next append
// cuts them). Pass `lines` to verifyJournal.
export function journalLines(text: string): { lines: string[]; tornTailBytes: number } {
  const end = text.lastIndexOf("\n") + 1;
  return { lines: text.slice(0, end).split("\n").slice(0, -1), tornTailBytes: Buffer.byteLength(text.slice(end), "utf8") };
}

export function verifyJournal(lines: string[], publicPems: string[], checkpointEnv: J | null, trust: TrustDoc | null): Report {
  const keys = publicPems.map((p) => createPublicKey(p));
  if (!keys.length) throw new Error("verify_journal needs at least one trusted public key");
  let prev = GENESIS, verified = 0;
  const failures: string[] = [], bodies: [number, J][] = [];
  lines = lines.filter((l) => l.trim());
  const seen: Record<string, J> = {}; // grant bodies of the authority chains verified so far, by digest
  const counted = new Map<string, Set<string> | null>(); // permit id -> the approvers its first allow counted
  lines.forEach((line, n) => {
    const i = n + 1;
    const [body, problems] = checkLine(i, line, keys, prev, trust, seen, counted);
    prev = sha256Hex(Buffer.from(line, "utf8"));
    failures.push(...problems);
    if (body === null) return;
    bodies.push([i, body]);
    if (!problems.length) verified++;
  });
  failures.push(...crossChecks(bodies, trust?.possessionSkewSeconds ?? DEFAULT_SKEW));
  let checkpoint = "not_supplied";
  if (checkpointEnv !== null) {
    try {
      const cp = parseReceived(openEnvelope(checkpointEnv, keys)[0]).predicate;
      if (cp.count !== lines.length) { failures.push(`checkpoint_count_mismatch:${cp.count}:${lines.length}`); checkpoint = "mismatch"; }
      else if (cp.head !== prev) { failures.push("checkpoint_head_mismatch"); checkpoint = "mismatch"; }
      else checkpoint = "matches";
    } catch (e) { failures.push(`checkpoint_invalid:${(e as Error).message}`); checkpoint = "invalid"; }
  }
  const verdict = failures.length ? "FAIL" : checkpoint !== "matches" ? "NOT_ESTABLISHED" : "PASS";
  return { verdict, records: lines.length, verified, failures, checkpoint };
}

// ---------- identity digests (packages/probity-records/docs/identity-digests.md) ----------
//
// The Python twin is probity_records.digests; test/shared.test.ts holds the two to
// packages/probity-records/vectors/shared/identity_digests.json. The walk order is the spec's: a
// container's depth, then at an object every member name, then its values in sorted member order.

export const DIGEST_PREFIX = "sha256:";
const ID_MAX_DEPTH = 64;
const ID_MAX_ACTORS = 32;
const ID_ROLES = new Set(["user", "agent", "sponsor", "approver"]);
const HEX64 = /^[0-9a-f]{64}$/;
const LONE_SURROGATE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;
const PRINTABLE_ASCII = /^[\x20-\x7e]*$/;

/** A value with no identity digest: `code`, and for identity_out_of_domain the `reason`. */
export class IdentityDigestError extends Error {
  readonly code: string;
  readonly reason: string | null;
  constructor(code: string, reason: string | null = null, detail = "") {
    super([code, reason ?? "", detail].filter(Boolean).join(":"));
    this.code = code;
    this.reason = reason;
  }
}

const outOfDomain = (reason: string): never => { throw new IdentityDigestError("identity_out_of_domain", reason); };

function admitIdentity(v: J, holder: J, key: string, depth: number): void {
  if (v === null || typeof v === "boolean") return;
  if (typeof v === "string") { if (LONE_SURROGATE.test(v)) outOfDomain("lone_surrogate"); return; }
  if (typeof v === "number") {
    if (!Number.isFinite(v) || isFloat(holder, key, v)) outOfDomain("float");
    if (Math.abs(v) > MAX_EXACT_INT) outOfDomain("integer_out_of_range");
    return;
  }
  if (Array.isArray(v)) {
    if (depth >= ID_MAX_DEPTH) outOfDomain("too_deep");
    v.forEach((x, i) => admitIdentity(x, v, String(i), depth + 1));
    return;
  }
  if (typeof v === "object") {
    if (depth >= ID_MAX_DEPTH) outOfDomain("too_deep");
    const names = Object.keys(v);
    if (!names.every((n) => PRINTABLE_ASCII.test(n))) outOfDomain("member_name_not_ascii");
    for (const n of names.sort()) admitIdentity(v[n], v, n, depth + 1);
    return;
  }
  outOfDomain("unsupported_type");
}

function identityDigestOf(v: J): string {
  try { return DIGEST_PREFIX + sha256Hex(canonicalBytes(v)); } catch (e) {
    throw new IdentityDigestError("identity_out_of_domain", "no_canonical_form", (e as Error).message);
  }
}

const isDigest = (v: J): boolean => typeof v === "string" && v.startsWith(DIGEST_PREFIX) && HEX64.test(v.slice(7));

function principalsDoc(block: J, holder: J, key: string): J {
  admitIdentity(block, holder, key, 0);
  if (!isObj(block) || Object.keys(block).length === 0) throw new IdentityDigestError("identity_principals_malformed");
  for (const [role, member] of Object.entries(block)) {
    if (!ID_ROLES.has(role) || !isObj(member)) throw new IdentityDigestError("identity_principals_malformed");
  }
  return block;
}

/** probity_records.digests.principals_digest. */
export function principalsDigest(block: J, holder: J = null, key = ""): string {
  return identityDigestOf(principalsDoc(block, holder, key));
}

/** probity_records.digests.act_chain_digest. */
export function actChainDigest(act: J, holder: J = null, key = ""): string {
  if (act === null || act === undefined) throw new IdentityDigestError("identity_act_missing");
  admitIdentity(act, holder, key, 0);
  let level = act;
  for (let actors = 1; ; actors++) {
    if (!isObj(level) || typeof level.sub !== "string" || level.sub === "") throw new IdentityDigestError("identity_act_malformed");
    if (actors > ID_MAX_ACTORS) throw new IdentityDigestError("identity_act_malformed");
    if (!("act" in level)) return identityDigestOf(act);
    level = level.act;
  }
}

/** probity_records.digests.grant_chain_digest_of. */
export function grantChainDigestOf(digests: J, holder: J = null, key = ""): string {
  admitIdentity(digests, holder, key, 0);
  if (!Array.isArray(digests)) throw new IdentityDigestError("identity_grant_chain_malformed");
  if (digests.length === 0) throw new IdentityDigestError("identity_grant_chain_empty");
  if (!digests.every((d) => typeof d === "string" && HEX64.test(d))) throw new IdentityDigestError("identity_grant_chain_malformed");
  return identityDigestOf(digests);
}

/** probity_records.digests.grant_chain_digest: the digest of the links' grant digests, root first. */
export function grantChainDigest(links: J): string {
  if (!Array.isArray(links)) throw new IdentityDigestError("identity_grant_chain_malformed");
  if (links.length === 0) throw new IdentityDigestError("identity_grant_chain_empty");
  const digests = links.map((link) => {
    if (!isObj(link) || !isObj(link.body)) throw new IdentityDigestError("identity_grant_chain_malformed");
    try { return digestOf(link.body); } catch (e) {
      throw new IdentityDigestError("identity_grant_chain_malformed", null, (e as Error).message);
    }
  });
  return grantChainDigestOf(digests);
}

/** probity_records.digests.stamp_digest: null for an absent act claim or grant chain. */
export function stampDigest(principals: J, act: J, grants: J): string {
  if (!isDigest(principals) || !(act === null || isDigest(act)) || !(grants === null || isDigest(grants)))
    throw new IdentityDigestError("identity_digest_malformed");
  return identityDigestOf({ act, grants, principals });
}

/** probity_records.digests.stamp_digest_of. */
export function stampDigestOf(block: J, links: J = null, holder: J = null, key = ""): string {
  const doc = principalsDoc(block, holder, key);
  const user = doc.user ?? {};
  const act = "act" in user ? actChainDigest(user.act, user, "act") : null;
  return stampDigest(identityDigestOf(doc), act, links === null ? null : grantChainDigest(links));
}

/** What the shared vectors expect for `fn` over the JSON text `input` of its argument array. */
export function judgeDigest(fn: string, input: string): { digest: string } | { refused: string; reason: string | null } {
  const args = parsePy(input);
  try {
    const digest = (() => {
      switch (fn) {
        case "principals_digest": return principalsDigest(args[0], args, "0");
        case "act_chain_digest": return actChainDigest(args[0], args, "0");
        case "grant_chain_digest": return grantChainDigest(args[0]);
        case "grant_chain_digest_of": return grantChainDigestOf(args[0], args, "0");
        case "stamp_digest": return stampDigest(args[0], args[1], args[2]);
        case "stamp_digest_of": return stampDigestOf(args[0], args[1], args, "0");
        default: throw new Error(`unknown digest function ${fn}`);
      }
    })();
    return { digest };
  } catch (e) {
    if (e instanceof IdentityDigestError) return { refused: e.code, reason: e.reason };
    throw e;
  }
}

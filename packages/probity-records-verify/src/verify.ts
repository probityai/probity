// Offline verifier for probity-records journals, in TypeScript.
//
// It re-runs, from the journal bytes and the trust an auditor pins, the checks the Python
// verifier (probity_records.verify_journal) runs: every DSSE signature, the hash chain, the
// checkpoint, grant chains (signatures, narrowing on every axis, CEL conditions, context,
// budgets recounted across the journal), M-of-N quorum evidence (proposer separation, roles,
// deputies) and the four-principal identity block. Failure codes are the Python verifier's,
// character for character; test/shared.test.ts holds the two to the shared vectors.
//
// The two published per-record readers are ported too: approval-binding/v1 (the sixteen ordered
// checks of agent_evidence_vectors.approvalbinding, with the M-of-N recount under the quorum policy
// the auditor pinned) and uncertain_effect/v1 (the thirteen ordered checks of agent-evidence-verify's
// built-in adapter). A governance-step record is still reported as not ported, never passed.

import { createHash, createPublicKey, verify as edVerify, type KeyObject } from "node:crypto";
import { run, isCelError } from "@bufbuild/cel";

export const TOOL_CALL_RECORD = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/tool-call-record";
const IN_TOTO = "application/vnd.in-toto+json";
const GRANT_DOMAIN = "probity-grant-v1\u0000";
const VOTE_DOMAIN = "probity-quorum-vote-v1\u0000";
const DEPUTY_DOMAIN = "probity-quorum-deputy-v1\u0000";
const APPROVAL_DOMAIN = "probity-approval-v1\u0000";
const GENESIS = "0".repeat(64);
type J = any; // eslint-disable-line @typescript-eslint/no-explicit-any

// ---------- canonical bytes (RFC 8785) and digests ----------

export function canonical(v: J): string {
  if (v === null || typeof v === "boolean") return JSON.stringify(v);
  if (typeof v === "number") {
    if (!Number.isFinite(v)) throw new Error("jcs_number");
    return JSON.stringify(v);
  }
  if (typeof v === "string") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(canonical).join(",") + "]";
  const keys = Object.keys(v).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonical(v[k])).join(",") + "}";
}

export const sha256Hex = (data: string | Buffer): string => createHash("sha256").update(data).digest("hex");
const digestOf = (v: J): string => sha256Hex(Buffer.from(canonical(v), "utf8"));
const same = (a: J, b: J): boolean => canonical(a) === canonical(b);
const isObj = (v: J): boolean => v !== null && typeof v === "object" && !Array.isArray(v);

// Python's json.loads keeps `3.0` a float, `3` an int and `1e2` a float, and the constraint checks
// (`type(v) is type(c["value"])`) tell them apart; JSON.parse folds all of them into one number.
// The parse below records, per holder object, which keys held an integral value written as a float.
const FLOAT_KEYS = new WeakMap<object, Set<string>>();
export function parsePy(text: string): J {
  return JSON.parse(text, function (this: J, key: string, value: J, context?: { source?: string }) {
    if (typeof value === "number" && Number.isInteger(value) && context?.source !== undefined && /[.eE]/.test(context.source)) {
      let keys = FLOAT_KEYS.get(this);
      if (!keys) FLOAT_KEYS.set(this, (keys = new Set()));
      keys.add(key);
    }
    return value;
  });
}
/** Whether `value`, read from `holder[key]`, is a Python float: a fractional number, or an integral one written as a float. */
function isFloat(holder: J, key: string | number, value: J): boolean {
  return typeof value === "number" && (!Number.isInteger(value) || (holder !== null && typeof holder === "object" && (FLOAT_KEYS.get(holder)?.has(String(key)) ?? false)));
}

function unb64(text: J): Buffer {
  if (typeof text !== "string") throw new Error("expected base64 text");
  const data = Buffer.from(text, "base64");
  if (data.toString("base64") !== text) throw new Error("expected canonical base64");
  return data;
}

// ---------- keys and signatures ----------

function rawKey(raw: Buffer): KeyObject {
  return createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: raw.toString("base64url") }, format: "jwk" });
}
export function keyId(key: KeyObject): string {
  return sha256Hex(Buffer.from(String((key.export({ format: "jwk" }) as J).x), "base64url"));
}
function edOk(key: KeyObject, data: Buffer, sig: Buffer): boolean {
  try { return edVerify(null, data, key, sig); } catch { return false; }
}
const sigOk = (rawB64: J, domain: string, body: J, sig: J): boolean => {
  try { return edOk(rawKey(unb64(rawB64)), Buffer.concat([Buffer.from(domain, "latin1"), Buffer.from(canonical(body))]), unb64(sig)); }
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

function ts(text: J): number {
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?(Z|[+-]\d{2}:\d{2})$/.exec(String(text));
  if (!m) throw new Error("time_invalid");
  const base = Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]);
  let off = 0;
  if (m[8] !== "Z") off = (m[8][0] === "-" ? -1 : 1) * (+m[8].slice(1, 3) * 60 + +m[8].slice(4, 6)) * 60000;
  return (base - off) * 1000 + Number((m[7] ?? "").padEnd(6, "0"));
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
  try {
    const data: Record<string, J> = {};
    for (const name of ["value", "args", "tool", "ctx"]) data[name] = toCel(bindings[name] ?? null, name === "value" && valueIsFloat);
    const out = run(expr, data);
    return !isCelError(out) && out === true;
  } catch { return false; }
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

function validateC(c: J): void {
  if (!isObj(c) || !(c.type in CHECKS)) throw new Error(`unknown constraint`);
  if ((REQUIRED[c.type] ?? []).some((k) => !(k in c))) throw new Error(`${c.type} needs`);
  if (c.type === "range" && !("min" in c) && !("max" in c)) throw new Error("range needs min or max");
  if (c.type === "all" || c.type === "any") { if (!Array.isArray(c.of) || !c.of.length) throw new Error("list"); c.of.forEach(validateC); }
  if (c.type === "not") validateC(c.of);
}
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
  return r.status === "approved" ? "ok" : `quorum_${r.status}`;
}

// ---------- grants ----------

function narrowingProblem(ch: J, p: J): string | null {
  if (ch.issuerKey !== p.holderKey) return "child_not_issued_by_parent_holder";
  if (ts(ch.notBefore) < ts(p.notBefore) || ts(ch.expiresAt) > ts(p.expiresAt)) return "child_window_wider_than_parent";
  if ((p.maxDepth ?? 0) < 1) return "parent_forbids_delegation";
  if ((ch.maxDepth ?? 0) > p.maxDepth - 1) return "child_depth_wider_than_parent";
  for (const [k, c] of Object.entries(p.context ?? {})) {
    if (!(k in (ch.context ?? {}))) return `child_drops_context:${k}`;
    if (!narrows(ch.context[k], c)) return `child_widens_context:${k}`;
  }
  const pb = p.budget, cb = ch.budget;
  if (pb !== undefined && pb !== null) {
    if (cb === undefined || cb === null) return "child_drops_budget";
    if ("uses" in pb && (cb.uses ?? pb.uses + 1) > pb.uses) return "child_budget_wider_than_parent";
    if ("spend" in pb && (!cb.spend || cb.spend.arg !== pb.spend.arg || cb.spend.max > pb.spend.max)) return "child_spend_wider_than_parent";
  }
  for (const [tool, spec] of Object.entries(ch.tools) as [string, J][]) {
    const ps = p.tools[tool];
    if (ps === undefined) return `child_adds_tool:${tool}`;
    if ((ps.approval ?? "none") === "required" && (spec.approval ?? "none") !== "required") return `child_drops_approval:${tool}`;
    if ((ps.when ?? []).some((w: string) => !(spec.when ?? []).includes(w))) return `child_drops_condition:${tool}`;
    if ("quorum" in ps) { const q = quorumWidening(spec.quorum, ps.quorum); if (q) return `${q}:${tool}`; }
    for (const [name, c] of Object.entries(spec.args)) {
      if (!(name in ps.args)) return `child_adds_argument:${tool}.${name}`;
      if (!narrows(c, ps.args[name])) return `child_widens_constraint:${tool}.${name}`;
    }
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
  const issuers: string[] = [], digests: string[] = [];
  let result = "ok", prev: J = null;
  for (let depth = 0; depth < chain.length; depth++) {
    const body = isObj(chain[depth]) ? chain[depth].body : null;
    if (!isObj(body)) { result = `grant_shape:${depth}`; break; }
    let issuer: string;
    try { issuer = keyId(rawKey(Buffer.from(body.issuerKey, "base64"))); } catch (e) { result = `grant_invalid:${depth}:${(e as Error).message}`; break; }
    if (!sigOk(body.issuerKey, GRANT_DOMAIN, body, chain[depth].sig)) { result = `grant_signature_unverified:${depth}`; break; }
    if (prev === null) { if (body.parent !== null || !roots.has(issuer)) { result = "grant_root_untrusted"; break; } }
    else {
      if (body.parent !== digests[digests.length - 1]) { result = `grant_parent_mismatch:${depth}`; break; }
      const problem = narrowingProblem(body, prev);
      if (problem) { result = `${problem}:${depth}`; break; }
    }
    issuers.push(issuer); digests.push(digestOf(body)); prev = body;
  }
  const when = ts(at);
  for (let depth = 0; depth < issuers.length; depth++) {
    const body = chain[depth].body;
    if (!(ts(body.notBefore) <= when && when <= ts(body.expiresAt))) return [null, `grant_outside_window:${depth}`];
  }
  return result !== "ok" ? [null, result] : [chain[chain.length - 1].body, "ok"];
}

function checkCall(leaf: J, tool: string, args: J, ctx: J): string {
  for (const [k, c] of Object.entries(leaf.context ?? {})) if (!(k in ctx) || !check(c, ctx[k], isFloat(ctx, k, ctx[k]))) return `context_violation:${k}`;
  const spec = leaf.tools[tool];
  if (spec === undefined) return "tool_not_granted";
  if (!isObj(args)) return "arguments_not_an_object";
  const extra = Object.keys(args).filter((k) => !(k in spec.args)).sort();
  if (extra.length) return `argument_not_granted:${extra[0]}`;
  for (const [name, c] of Object.entries(spec.args)) if (!check(c, args[name] ?? null, isFloat(args, name, args[name]))) return `constraint_violation:${name}`;
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
const OPTIONAL = ["tenant", "act"];
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
  if (!pinned.includes(thumb)) return "principal_key_not_pinned";
  if ("act" in p && actSubjects(p.act) === null) return "principal_act_malformed";
  return null;
}
const ROLES = ["user", "agent", "sponsor", "approver"];
export function checkPrincipals(block: J, at: string, pins: Record<string, string[]>, approvers: Set<string> | null): [string[], string | null] {
  if (!isObj(block) || !Object.keys(block).length || Object.keys(block).some((k) => !ROLES.includes(k))) return [["principals_malformed"], null];
  const problems: string[] = [];
  for (const r of ROLES) if (r in block) { const p = checkPrincipal(block[r], at, pins); if (p) problems.push(`principal_${r}:${p}`); }
  if (!("user" in block) || !("agent" in block)) problems.push("principals_need_user_and_agent");
  if (problems.length) return [problems, null];
  const chain = "act" in block.user ? actSubjects(block.user.act) ?? [] : [];
  if (chain.length && ![block.agent.subject, block.agent.clientId].includes(chain[0])) return [["principal_act_names_another_agent"], null];
  if ("approver" in block && approvers !== null && !approvers.has(block.approver.subject)) return [["principal_approver_not_an_approval_signer"], null];
  return [[], chain.length && ROLES.every((r) => r in block) ? "strict" : "basic"];
}

// ---------- journal ----------

export interface TrustDoc { grantRootKeyIds?: string[]; quorumPolicies?: Record<string, J>; identityIssuers?: Record<string, string[]>; identityProfile?: string }

function checkAuthority(pred: J, trust: TrustDoc | null, problems: string[], where: string): boolean {
  const reason = pred.reason;
  if (reason !== "grant" && reason !== "quorum") return false;
  const ev = pred.authority;
  if (!isObj(ev) || ev.kind !== reason) { problems.push(`${where}:${reason}_allow_without_authority_evidence`); return true; }
  if (trust === null) { problems.push(`${where}:${reason}_allow_but_no_trust_pinned`); return true; }
  const at = String(pred.at), pinned = { ...(trust.quorumPolicies ?? {}) };
  const quorumOutcome = (q: J, carried?: J): string => {
    if (carried) pinned[String(carried.policyId)] = carried;
    return verifyQuorumEvidence(q, pinned, requestHash(String(pred.tool), String(pred.argsSha256), String(pred.permitId), q.proposer, q.historyDigest), at);
  };
  if (reason === "quorum") { const o = quorumOutcome(ev); if (o !== "ok") problems.push(`${where}:${o}`); return true; }
  const raw = Buffer.from(ev.argsB64 ?? "", "base64");
  if (sha256Hex(raw) !== pred.argsSha256) problems.push(`${where}:authority_args_are_not_the_call_arguments`);
  const args = raw.length ? parsePy(raw.toString("utf8")) : null;
  const v = verifyGrantAllow(ev.chain ?? [], String(pred.tool), args, at, new Set(trust.grantRootKeyIds ?? []), ev.ctx ?? {});
  if (v.decision === "needs_approval" && isObj(ev.quorum)) {
    const o = quorumOutcome(ev.quorum, ev.chain[ev.chain.length - 1].body.tools[String(pred.tool)].quorum);
    if (o !== "ok") problems.push(`${where}:grant_approval_${o}`);
  } else if (v.decision !== "allow") problems.push(`${where}:grant_${v.decision}:${v.reason}`);
  if (v.grantDigest && v.grantDigest !== pred.grantDigest) problems.push(`${where}:grant_digest_differs_from_record`);
  return true;
}

function approvalSigners(pred: J): Set<string> | null {
  const names = new Set<string>();
  for (const b of pred.approvalBindings ?? []) names.add(String(b?.record?.approval?.approver));
  const a = pred.authority ?? {}, q = a.quorum ?? a;
  for (const v of q.votes ?? []) if (isObj(v)) names.add(String(v.body?.onBehalfOf ?? v.body?.approver));
  return names.size ? names : null;
}

// ---------- approval-binding/v1 reader ----------

const APPROVAL_BINDING_CONTRACT = "https://probityai.github.io/agent-evidence-vectors/contract/approval-binding/v1";
const APPROVAL_CHECKS = ["contract_id_missing", "contract_id_unknown", "approval_not_cited", "approval_id_ambiguous",
  "approval_replayed", "approval_superseded", "renewal_transition_missing", "renewal_binding_invalid", "key_not_bound",
  "principal_mismatch", "event_phase_mismatch", "payload_mismatch", "approval_outside_validity", "effect_already_closed",
  "comparison_unavailable", "release_not_served_at_decision"] as const;
const BOUND_FIELDS = ["event", "payloadSha256", "phase", "principal", "target", "tool"];
const CLOSED_EFFECT_STATES = ["CONSUMED", "UNCERTAIN_CLOSE"];

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

function approvalAmbiguous(record: J): boolean {
  const approval = req(record, "approval");
  return getOr(record, "presentedApprovals", []).some((o: J) => pyEq(req(o, "approvalId"), req(approval, "approvalId")) && !pyEq(o, approval));
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
  const approval = req(record, "approval"), use = req(record, "use");
  const failures: Record<string, () => boolean> = {
    contract_id_missing: () => !("contractId" in record),
    contract_id_unknown: () => !pyEq(getOr(record, "contractId", APPROVAL_BINDING_CONTRACT), APPROVAL_BINDING_CONTRACT),
    approval_not_cited: () => !pyEq(getOr(use, "approvalId", null), req(approval, "approvalId")),
    approval_id_ambiguous: () => approvalAmbiguous(record),
    approval_replayed: () => getOr(record, "consumedApprovalIds", []).some((x: J) => pyEq(x, req(approval, "approvalId"))),
    approval_superseded: () => approvalSuperseded(record),
    renewal_transition_missing: () => renewed(record) && acceptedInto(record).length === 0,
    renewal_binding_invalid: () => renewalInvalid(record),
    key_not_bound: () => !pyEq(getOr(req(record, "trustedKeys"), String(req(approval, "approver")), null), req(approval, "keyId")),
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

const EFFECT_CONTRACT = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/uncertain-effect";
const UNKNOWN_REPLIES = ["timeout", "connection_lost"];
const REPLIES = ["confirmed", "no_effect", ...UNKNOWN_REPLIES];
const ANSWERS = ["present", "absent"];
const OUTCOMES = ["committed", "not_run", "unknown"];
const STOP_REPORTS = ["quiescent", "effect_after_stop", "not_established"];
const AUTHORITY_ANSWERS = ["accepted", "refused"];
const EFFECT_CHECKS = ["contract_id_missing", "contract_id_unknown", "operation_identity_missing", "idempotency_key_args_changed",
  "dispatch_beyond_lease", "retry_after_unknown", "duplicate_effect", "unknown_released", "outcome_settled_without_authority",
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
    contract_id_unknown: () => !pyEq(getOr(record, "contractId", EFFECT_CONTRACT), EFFECT_CONTRACT),
    operation_identity_missing: () => [req(record, "operation"), ...req(record, "attempts")].some((item: J) =>
      ["idempotencyKey", "argsDigest"].some((k) => !truthy(getOr(item, k, null)))),
    idempotency_key_args_changed: () => { const op = req(record, "operation");
      return req(record, "attempts").some((a: J) => pyEq(getOr(a, "idempotencyKey", null), getOr(op, "idempotencyKey", null)) &&
        !pyEq(getOr(a, "argsDigest", null), getOr(op, "argsDigest", null))); },
    dispatch_beyond_lease: () => { const leases = getOr(record, "leases", null) ?? []; return leases.length > 0 && req(record, "attempts").some((a: J) => outsideLease(a, leases)); },
    retry_after_unknown: () => unprotectedRetry(record),
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
  for (const a of domainObjects(record, "attempts")) domainWord(a, "reply", REPLIES);
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

function checkApproval(pred: J, problems: string[], where: string, trust: TrustDoc | null): void {
  if (pred.decision === "allow" && checkAuthority(pred, trust, problems, where)) return;
  const bindings: J[] = pred.approvalBindings ?? [];
  if (!bindings.length) {
    if (pred.decision === "allow" && ![NO_APPROVAL_REQUIRED, RECONCILED_RETRY].includes(pred.reason)) problems.push(`${where}:allow_without_approval_binding`);
    return;
  }
  const readerAllowed = new Set<string>();
  bindings.forEach((embedded, n) => {
    const payload = unb64(embedded.payloadB64);
    if (sha256Hex(payload) !== pred.argsSha256) problems.push(`${where}:binding_${n}:approval_payload_is_not_the_call_arguments`);
    const verdict = judgeApprovalBinding(embedded.record, payload);
    if (verdict.decision === "allow") readerAllowed.add(String(embedded.record?.approval?.approver));
    else if (pred.decision === "deny" && verdict.reason !== pred.reason && bindings.length === 1)
      problems.push(`${where}:deny_reason_${pred.reason}_but_reader_says_${verdict.reason}`);
  });
  if (pred.decision !== "allow") return;
  if (trust === null) { problems.push(`${where}:approval_allow_but_no_trust_pinned`); return; }
  const policy = (trust.quorumPolicies ?? {})[String(pred.approvalPolicyId)];
  if (policy === undefined) { problems.push(`${where}:approval_policy_not_pinned`); return; }
  if (!pyEq(pred.threshold, policy.threshold)) problems.push(`${where}:threshold_${pyRepr(pred.threshold, isFloat(pred, "threshold", pred.threshold))}_is_not_the_pinned_${pyRepr(policy.threshold, isFloat(policy, "threshold", policy.threshold))}`);
  const { counted: signed, problems: sigProblems } = countBindings(policy, bindings);
  problems.push(...sigProblems.map((p) => `${where}:${p}`));
  const counted = [...signed].filter((a) => readerAllowed.has(a));
  if (counted.length < policy.threshold) problems.push(`${where}:recorded_allow_but_${counted.length}_of_${policy.threshold}_approvals_hold`);
}

function checkEffect(pred: J, problems: string[], where: string): void {
  const record = pred.uncertainEffect;
  if (!truthy(record)) { problems.push(`${where}:effect_without_uncertain_effect_record`); return; }
  const verdict = judgeUncertainEffect(record);
  if (verdict.decision !== "supported") problems.push(`${where}:uncertain_effect_${verdict.decision}:${verdict.reason}`);
  if (!pyEq(getOr(getOr(record, "operation", {}), "argsDigest", null), "sha256:" + String(pred.argsSha256))) problems.push(`${where}:effect_args_differ_from_call`);
  if (!pyEq(pred.outcome ?? null, verdict.reported_outcome)) problems.push(`${where}:outcome_field_differs_from_record`);
}

/** Python's str() of a parsed JSON scalar, for the failure text. */
function pyRepr(v: J, asFloat = false): string {
  if (v === null || v === undefined) return "None";
  if (typeof v === "boolean") return v ? "True" : "False";
  return asFloat && Number.isInteger(v) ? `${v}.0` : String(v);
}

function checkLine(i: number, line: string, keys: KeyObject[], prev: string, trust: TrustDoc | null): [J | null, string[]] {
  const where = `line_${i}`, problems: string[] = [];
  let body: J;
  try { const [payload] = openEnvelope(JSON.parse(line), keys); body = parsePy(payload.toString("utf8")); }
  catch (e) { return [null, [`${where}:${(e as Error).message}`]]; }
  const pred = body.predicate ?? {};
  if (pred.seq !== i) problems.push(`${where}:seq_${pred.seq ?? "None"}_not_${i}`);
  if (pred.prev !== prev) problems.push(`${where}:chain_broken`);
  if (body.predicateType === TOOL_CALL_RECORD && pred.principals !== undefined && pred.principals !== null) {
    if (trust === null) problems.push(`${where}:principals_but_no_trust_pinned`);
    else {
      const [found, grade] = checkPrincipals(pred.principals, String(pred.at), trust.identityIssuers ?? {}, approvalSigners(pred));
      problems.push(...found.map((p) => `${where}:${p}`));
      if (grade !== null && trust.identityProfile === "strict" && grade !== "strict")
        problems.push(`${where}:principals_below_strict:${"act" in (pred.principals.user ?? {}) ? "act-chain" : "act-absent"}`);
    }
  }
  if (body.predicateType === TOOL_CALL_RECORD) {
    if (pred.phase === "authorize") checkApproval(pred, problems, where, trust);
    else if (pred.phase === "effect") checkEffect(pred, problems, where);
  } else if (body.predicateType !== TOOL_CALL_RECORD && pred.phase === undefined && body.predicateType?.endsWith("/governance-step"))
    problems.push(`${where}:governance_step_not_ported`);
  return [body, problems];
}

function spendOf(budget: J, args: J): number {
  if (!budget || !("spend" in budget) || !isObj(args)) return 0;
  const v = args[budget.spend.arg] ?? 0;
  return typeof v === "number" ? v : Infinity;
}

function crossChecks(bodies: [number, J][]): string[] {
  const problems: string[] = [];
  const uses = new Map<string, number>(), spent = new Map<string, number>(), charged = new Set<J>();
  for (const [i, body] of bodies) {
    const pred = body.predicate ?? {};
    if (body.predicateType !== TOOL_CALL_RECORD || pred.phase !== "authorize" || pred.decision !== "allow" || charged.has(pred.permitId)) continue;
    const ev = pred.authority;
    if (!isObj(ev) || ev.kind !== "grant") continue;
    let charges: [string, J, J][];
    try {
      const args = ev.argsB64 ? parsePy(Buffer.from(ev.argsB64, "base64").toString("utf8")) : null;
      charges = (ev.chain ?? []).map((g: J) => [digestOf(g.body), g.body.budget, args]);
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
  const grantOf = new Map<J, J>(), allowed = new Set<J>(), effects = new Map<J, number>(), intents = new Map<J, number>();
  for (const [i, body] of bodies) {
    if (body.predicateType !== TOOL_CALL_RECORD) continue;
    const pred = body.predicate, pid = pred.permitId ?? null, phase = pred.phase;
    if (phase === "authorize" && pred.decision === "allow") {
      if (pred.reason === "reconciled_absent_retry" && !allowed.has(pid)) problems.push(`line_${i}:reconciled_retry_without_earlier_permit`);
      allowed.add(pid);
      if (!grantOf.has(pid)) grantOf.set(pid, pred.grantDigest ?? null);
    } else if ((phase === "intent" || phase === "effect") && grantOf.has(pid) && (pred.grantDigest ?? null) !== grantOf.get(pid))
      problems.push(`line_${i}:${phase}_grant_differs_from_permit`);
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

export function verifyJournal(lines: string[], publicPems: string[], checkpointEnv: J | null, trust: TrustDoc | null): Report {
  const keys = publicPems.map((p) => createPublicKey(p));
  if (!keys.length) throw new Error("verify_journal needs at least one trusted public key");
  let prev = GENESIS, verified = 0;
  const failures: string[] = [], bodies: [number, J][] = [];
  lines = lines.filter((l) => l.trim());
  lines.forEach((line, n) => {
    const i = n + 1;
    const [body, problems] = checkLine(i, line, keys, prev, trust);
    prev = sha256Hex(Buffer.from(line, "utf8"));
    failures.push(...problems);
    if (body === null) return;
    bodies.push([i, body]);
    if (!problems.length) verified++;
  });
  failures.push(...crossChecks(bodies));
  let checkpoint = "not_supplied";
  if (checkpointEnv !== null) {
    try {
      const cp = JSON.parse(openEnvelope(checkpointEnv, keys)[0].toString("utf8")).predicate;
      if (cp.count !== lines.length) { failures.push(`checkpoint_count_${cp.count}_journal_has_${lines.length}`); checkpoint = "mismatch"; }
      else if (cp.head !== prev) { failures.push("checkpoint_head_mismatch"); checkpoint = "mismatch"; }
      else checkpoint = "matches";
    } catch (e) { failures.push(`checkpoint:${(e as Error).message}`); checkpoint = "invalid"; }
  }
  const verdict = failures.length ? "FAIL" : checkpoint !== "matches" ? "NOT_ESTABLISHED" : "PASS";
  return { verdict, records: lines.length, verified, failures, checkpoint };
}

// web_bot_auth/v1: was this HTTP request signed, under Web Bot Auth, by the agent the consumer pinned? The TypeScript
// twin of agent_evidence_verify.adapters.web_bot_auth. It reads the same probity-case/v1 case and probity-policy/v1
// policy, runs the same checks in the same order and returns the same decision and reason, and for a supported request
// the same scope.record, on every vector in packages/agent-evidence-verify/vectors-web-bot-auth. Spec:
// packages/agent-evidence-verify/docs/web-bot-auth.md. The verifying key comes only from the pinned directory: the
// request's keyid selects among its keys and nothing the request names is fetched or trusted.
import { createHash, createPublicKey, verify as edVerify } from "node:crypto";
import { lstatSync, readFileSync } from "node:fs";
import { isIP } from "node:net";
import { join } from "node:path";
import { type BareItem, type InnerList, type Member, Decimal, SFError, Token, parseDictionary, reserialize, serializeInnerList, serializeItem, serializeMember } from "./sf.ts";
import { isFloat, parseReceived, strictB64url } from "./verify.ts";

type J = any; // eslint-disable-line @typescript-eslint/no-explicit-any

export const CLAIM_TYPE = "web_bot_auth/v1";
const TAG = "web-bot-auth";
/** RFC 9421 Appendix B.1.4's published Ed25519 key, which the Web Bot Auth drafts' test vectors also use. */
const KNOWN_TEST_KEYS_X = new Set(["JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"]);
const MAX_SKEW_SECONDS = 60;
const DEFAULT_MAX_VALIDITY_SECONDS = 24 * 60 * 60;
const MAX_HEADERS = 256;
const MAX_FIELD_BYTES = 16 * 1024;
const MAX_ARTIFACT_BYTES = 16 * 1024 * 1024;
const MAX_SAFE = 2 ** 53 - 1;
const HEX64 = /^[0-9a-f]{64}$/;
const TCHAR = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const FORM_SAFE = /[A-Za-z0-9*\-._]/;
const DIGESTS: [string, (body: Buffer) => Buffer][] = [
  ["sha-256", (b) => createHash("sha256").update(b).digest()],
  ["sha-512", (b) => createHash("sha512").update(b).digest()],
];
export const LIMIT = "Checks that the pinned directory's key signed the components the signature covers (scope.record lists " +
  "them and the request parts left uncovered), for the authority the consumer serves, inside the signature's validity and " +
  "over the body that arrived. It keeps no state, so it does not establish that the request was not replayed inside that " +
  "window, who holds the key, or that the directory is the signer's own.";
const REQUIRED = ["request", "directory", "directory_sha256", "signature_agent", "authority", "at"];
const OPTIONAL = ["body", "label", "required_components", "pinned_fields", "max_age_seconds", "max_validity_seconds",
  "allow_test_keys"];

/** The case or the consumer policy is malformed: no verdict (the CLI exits 2). */
export class CaseError extends Error {}

class Fail extends Error {
  readonly verdict: string; readonly reason: string;
  constructor(verdict: string, reason: string, detail: string) { super(detail); this.verdict = verdict; this.reason = reason; }
}
const contradicted = (reason: string, detail: string): Fail => new Fail("contradicted", reason, detail);

const isObj = (v: J): boolean => v !== null && typeof v === "object" && !Array.isArray(v);
const isInt = (v: J): boolean => typeof v === "number" && Number.isInteger(v);
const isStr = (v: BareItem | undefined): v is string => typeof v === "string";
/** Python's str() of a bare item: a Token reads as its text, as Python's str subclass does. */
const pyStr = (v: BareItem): string => (v instanceof Token ? v.value : typeof v === "boolean" ? (v ? "True" : "False")
  : v instanceof Decimal ? v.text : Buffer.isBuffer(v) ? `b'${v.toString("latin1")}'` : String(v));
/** Python's == between a bare item and a str: a Token equals its text. */
const pyEq = (v: BareItem | undefined, text: string): boolean => (typeof v === "string" ? v === text : v instanceof Token && v.value === text);
const nonEmpty = (v: J, label: string): string => { if (typeof v !== "string" || !v) throw new CaseError(`${label}: expected nonempty string`); return v; };
const sha256Hex = (data: Buffer): string => createHash("sha256").update(data).digest("hex");

// --- strict JSON: I-JSON with integers only (agent_evidence_verify.ijson.parse_ijson(integers_only=True)) --------

function strictJson(raw: Buffer, label: string): J {
  let value: J;
  try { value = parseReceived(raw); } catch { throw new CaseError(`${label}: not strict UTF-8 JSON`); }
  const walk = (holder: J, key: string | number, v: J, depth: number): void => {
    if (depth > 128) throw new CaseError(`${label}: not strict UTF-8 JSON`);
    if (typeof v === "number" && (isFloat(holder, key, v) || Math.abs(v) > MAX_SAFE)) throw new CaseError(`${label}: not strict UTF-8 JSON`);
    if (Array.isArray(v)) v.forEach((x, i) => walk(v, i, x, depth + 1));
    else if (isObj(v)) for (const k of Object.keys(v)) walk(v, k, v[k], depth + 1);
  };
  walk(null, "", value, 1);
  return value;
}

// --- Python's urllib.parse.urlsplit, for the parts this check reads ------------------------------------------------

interface Split { scheme: string; netloc: string; path: string; query: string; fragment: string }
const SCHEME_CHARS = /^[A-Za-z0-9+\-.]$/;

function urlsplit(input: string): Split {
  let url = input.replace(/^[\x00-\x20]+/, "").replace(/[\t\r\n]/g, "");
  let scheme = "", netloc = "", query = "", fragment = "";
  const i = url.indexOf(":");
  if (i > 0 && /^[A-Za-z]$/.test(url[0]) && [...url.slice(0, i)].every((c) => SCHEME_CHARS.test(c))) {
    scheme = url.slice(0, i).toLowerCase(); url = url.slice(i + 1);
  }
  if (url.startsWith("//")) {
    let delim = url.length;
    for (const c of "/?#") { const w = url.indexOf(c, 2); if (w >= 0) delim = Math.min(delim, w); }
    netloc = url.slice(2, delim); url = url.slice(delim);
    if (netloc.includes("[") !== netloc.includes("]")) throw new RangeError("Invalid IPv6 URL");
    if (netloc.includes("[")) {
      const host = netloc.split("[").slice(1).join("[").split("]")[0];
      if (host.startsWith("v") ? !/^v[a-fA-F0-9]+\..+$/.test(host) : isIP(host) !== 6) throw new RangeError("Invalid IPv6 URL");
    }
  }
  const hash = url.indexOf("#");
  if (hash >= 0) { fragment = url.slice(hash + 1); url = url.slice(0, hash); }
  const q = url.indexOf("?");
  if (q >= 0) { query = url.slice(q + 1); url = url.slice(0, q); }
  if (netloc && /[^\x00-\x7f]/.test(netloc)) {
    const n = netloc.replace(/[@:#?]/g, "");
    const normal = n.normalize("NFKC");
    if (n !== normal && /[/?#@:]/.test(normal)) throw new RangeError("netloc contains invalid characters under NFKC normalization");
  }
  return { scheme, netloc, path: url, query, fragment };
}

function hostinfo(netloc: string): [string, string | null] {
  const info = netloc.slice(netloc.lastIndexOf("@") + 1);
  const open = info.indexOf("[");
  let host: string, port: string;
  if (open >= 0) {
    const bracketed = info.slice(open + 1);
    const close = bracketed.indexOf("]");
    host = close >= 0 ? bracketed.slice(0, close) : bracketed;
    const rest = close >= 0 ? bracketed.slice(close + 1) : "";
    const colon = rest.indexOf(":");
    port = colon >= 0 ? rest.slice(colon + 1) : "";
  } else {
    const colon = info.indexOf(":");
    host = colon >= 0 ? info.slice(0, colon) : info;
    port = colon >= 0 ? info.slice(colon + 1) : "";
  }
  return [host, port || null];
}

function hostname(s: Split): string | null {
  const [host] = hostinfo(s.netloc);
  if (!host) return null;
  const pct = host.indexOf("%");
  return pct >= 0 ? host.slice(0, pct).toLowerCase() + host.slice(pct) : host.toLowerCase();
}

function port(s: Split): number | null {
  const [, text] = hostinfo(s.netloc);
  if (text === null) return null;
  if (!/^[0-9]+$/.test(text)) throw new RangeError(`Port could not be cast to integer value as '${text}'`);
  const value = Number(text);
  if (value > 65535) throw new RangeError("Port out of range 0-65535");
  return value;
}

const username = (s: Split): string | null => (s.netloc.includes("@") ? s.netloc.slice(0, s.netloc.lastIndexOf("@")).split(":")[0] : null);

function authorityOf(url: string): string {
  const s = urlsplit(url);
  let host = (hostname(s) ?? "").toLowerCase();
  if (host.includes(":")) host = `[${host}]`;
  const p = port(s);
  const fallback = s.scheme === "http" ? 80 : 443;
  return p !== null && p !== fallback ? `${host}:${p}` : host;
}

// Python's unquote(errors="replace") and parse_qsl(keep_blank_values=True), then the WHATWG form encoding of RFC 9421
// section 2.2.8 step 2.
function unquote(text: string): string {
  if (!text.includes("%")) return text;
  return text.replace(/[\x00-\x7f]+/g, (run) => {
    const pieces = run.split("%");
    const bytes: number[] = [...Buffer.from(pieces[0], "latin1")];
    for (const piece of pieces.slice(1)) {
      if (/^[0-9a-fA-F]{2}/.test(piece)) { bytes.push(parseInt(piece.slice(0, 2), 16)); bytes.push(...Buffer.from(piece.slice(2), "latin1")); }
      else bytes.push(0x25, ...Buffer.from(piece, "latin1"));
    }
    return new TextDecoder("utf-8").decode(Buffer.from(bytes));
  });
}

function parseQsl(query: string): [string, string][] {
  const out: [string, string][] = [];
  for (const pair of query ? query.split("&") : []) {
    if (!pair) continue;
    const eq = pair.indexOf("=");
    const [name, value] = eq >= 0 ? [pair.slice(0, eq), pair.slice(eq + 1)] : [pair, ""];
    out.push([unquote(name.replace(/\+/g, " ")), unquote(value.replace(/\+/g, " "))]);
  }
  return out;
}

const formEncode = (text: string): string => [...Buffer.from(text, "utf8")]
  .map((b) => (FORM_SAFE.test(String.fromCharCode(b)) ? String.fromCharCode(b) : `%${b.toString(16).toUpperCase().padStart(2, "0")}`)).join("");

// --- the captured request -----------------------------------------------------------------------------------------

export interface Request { method: string; url: string; headers: [string, string][] }

/** RFC 9421 section 2.1: every line of the field, trimmed, joined with a comma and a space. */
function fieldValue(request: Request, name: string): string | null {
  const values = request.headers.filter(([n]) => n.toLowerCase() === name.toLowerCase()).map(([, v]) => v.replace(/^[ \t]+|[ \t]+$/g, ""));
  return values.length ? values.join(", ") : null;
}

function fieldName(v: J, label: string): string {
  if (typeof v !== "string" || !TCHAR.test(v)) throw new CaseError(`${label}: expected an HTTP field name`);
  return v;
}

function fieldText(v: J, label: string): string {
  if (typeof v !== "string" || Buffer.byteLength(v, "utf8") > MAX_FIELD_BYTES) throw new CaseError(`${label}: expected a field value of at most ${MAX_FIELD_BYTES} bytes`);
  if (/[\r\n\0]/.test(v)) throw new CaseError(`${label}: a field value holds a line break or NUL`);
  return v;
}

function readRequest(raw: Buffer): Request {
  const obj = strictJson(raw, "request");
  if (!isObj(obj) || Object.keys(obj).sort().join(",") !== "headers,method,url") throw new CaseError("request: expected exactly method, url and headers");
  const method = fieldName(obj.method, "request.method");
  const url = nonEmpty(obj.url, "request.url");
  let s: Split;
  try { s = urlsplit(url); port(s); } catch { throw new CaseError("request.url: not a URL"); }
  if ((s.scheme !== "http" && s.scheme !== "https") || !hostname(s) || s.fragment || username(s) !== null) {
    throw new CaseError("request.url: expected an absolute http or https target URI without a fragment or credentials");
  }
  if (!Array.isArray(obj.headers) || obj.headers.length > MAX_HEADERS) throw new CaseError(`request.headers: expected a list of at most ${MAX_HEADERS} [name, value] pairs`);
  const headers = obj.headers.map((pair: J, i: number): [string, string] => {
    if (!Array.isArray(pair) || pair.length !== 2) throw new CaseError(`request.headers[${i}]: expected a [name, value] pair`);
    return [fieldName(pair[0], `request.headers[${i}][0]`), fieldText(pair[1], `request.headers[${i}][1]`)];
  });
  return { method, url, headers };
}

// --- the pinned key directory ---------------------------------------------------------------------------------------

/** RFC 7638 thumbprint of an OKP key (RFC 8037 Appendix A.3), base64url without padding. */
export function jwkThumbprint(key: J): string {
  return createHash("sha256").update(JSON.stringify({ crv: key.crv, kty: key.kty, x: key.x })).digest("base64url");
}

function readDirectory(raw: Buffer): Map<string, J> {
  const obj = strictJson(raw, "directory");
  if (!isObj(obj) || !Array.isArray(obj.keys)) throw new CaseError("directory: expected a JWK set, an object with a keys list");
  const keys = new Map<string, J>();
  obj.keys.forEach((key: J, i: number) => {
    const label = `directory.keys[${i}]`;
    if (!isObj(key)) throw new CaseError(`${label}: expected an object`);
    if (key.kty !== "OKP" || key.crv !== "Ed25519") return;
    const x = nonEmpty(key.x, `${label}.x`), kid = nonEmpty(key.kid, `${label}.kid`);
    let raw32: Buffer;
    try { raw32 = strictB64url(x); } catch { throw new CaseError(`${label}.x: not a canonical base64url Ed25519 key`); }
    if (raw32.length !== 32) throw new CaseError(`${label}.x: not a canonical base64url Ed25519 key`);
    if (jwkThumbprint(key) !== kid) throw new CaseError(`${label}.kid: is not the key's RFC 7638 thumbprint`);
    for (const bound of ["nbf", "exp"]) if (bound in key && !isInt(key[bound])) throw new CaseError(`${label}.${bound}: expected an integer NumericDate`);
    if ("use" in key && typeof key.use !== "string") throw new CaseError(`${label}.use: expected a string`);
    if ("key_ops" in key && (!Array.isArray(key.key_ops) || !key.key_ops.every((op: J) => typeof op === "string"))) throw new CaseError(`${label}.key_ops: expected a list of strings`);
    if (keys.has(kid)) throw new CaseError(`${label}.kid: repeated`);
    keys.set(kid, key);
  });
  return keys;
}

// --- RFC 9421 section 2: the signature base -------------------------------------------------------------------------

function derived(request: Request, name: string, params: Map<string, BareItem>): string {
  const s = urlsplit(request.url);
  if (name === "@query-param") {
    const wanted = params.get("name");
    if (!(isStr(wanted) || wanted instanceof Token) || params.size !== 1) throw contradicted("signature_base_invalid", "@query-param needs exactly one parameter, name");
    const text = pyStr(wanted);
    const found = parseQsl(s.query).filter(([k]) => formEncode(k) === text).map(([, v]) => formEncode(v));
    if (found.length !== 1) throw contradicted("signature_base_invalid", `@query-param occurs ${found.length} times`);
    return found[0];
  }
  const values: Record<string, () => string> = {
    "@method": () => request.method,
    "@target-uri": () => request.url,
    "@authority": () => authorityOf(request.url),
    "@scheme": () => s.scheme.toLowerCase(),
    "@request-target": () => (s.path || "/") + (s.query ? `?${s.query}` : ""),
    "@path": () => s.path || "/",
    "@query": () => `?${s.query}`,
  };
  if (!(name in values)) throw contradicted("signature_base_invalid", `derived component ${name} is not supported`);
  if (params.size) throw contradicted("signature_base_invalid", `${name} takes no parameters`);
  return values[name]();
}

function field(request: Request, name: string, params: Map<string, BareItem>): string {
  if (name !== name.toLowerCase()) throw contradicted("signature_base_invalid", `field name ${name} must be lowercase`);
  if ([...params.keys()].some((k) => k !== "key" && k !== "sf")) throw contradicted("signature_base_invalid", "field parameters are not supported");
  const value = fieldValue(request, name);
  if (value === null) throw contradicted("component_not_covered", `the request has no ${name} field`);
  try {
    if (params.has("key")) {
      const key = params.get("key");
      if (!isStr(key)) throw new SFError("the key parameter must be a String");
      const members = parseDictionary(value);
      const member = members.get(key);
      if (member === undefined) throw new SFError(`no member ${key}`);
      return serializeMember(member);
    }
    if (params.has("sf")) return reserialize(value);
  } catch (e) {
    if (e instanceof SFError) throw contradicted("signature_base_invalid", `${name} is not the Structured Field its parameter says`);
    throw e;
  }
  return value;
}

/** The signature base for one Signature-Input member over `request` (RFC 9421 section 2.5). */
export function signatureBase(request: Request, inner: InnerList): string {
  const lines: string[] = [];
  const seen = new Set<string>();
  for (const item of inner.items) {
    const identifier = serializeItem(item);
    if (seen.has(identifier)) throw contradicted("signature_base_invalid", `component ${identifier} is covered twice`);
    seen.add(identifier);
    if (!isStr(item.value)) throw contradicted("signature_base_invalid", `component identifier ${identifier} is not a String`);
    const value = item.value.startsWith("@") ? derived(request, item.value, item.params) : field(request, item.value, item.params);
    lines.push(`${identifier}: ${value}`);
  }
  lines.push(`"@signature-params": ${serializeInnerList(inner)}`);
  const base = lines.join("\n");
  if (/[^\x00-\x7f]/.test(base)) throw contradicted("signature_base_invalid", "the signature base is not ASCII");
  return base;
}

// --- the signature headers ------------------------------------------------------------------------------------------

interface Signature {
  label: string; inner: InnerList; signature: Buffer; created: number; expires: number; keyid: string;
  agentMember: string; components: string[];
}

function dictionary(request: Request, name: string, absent = "signature_absent"): Map<string, Member> {
  const raw = fieldValue(request, name);
  if (raw === null) throw contradicted(absent, `the request carries no ${name} header`);
  try { return parseDictionary(raw); } catch (e) {
    if (e instanceof SFError) throw contradicted("signature_headers_malformed", `${name}: ${e.message}`);
    throw e;
  }
}

function candidates(request: Request, label: string | undefined): [string, InnerList][] {
  const inputs = dictionary(request, "signature-input");
  if (label) {
    const member = inputs.get(label);
    if (member === undefined) throw contradicted("signature_absent", `no Signature-Input for label ${label}`);
    if (member.kind !== "inner") throw contradicted("signature_headers_malformed", `Signature-Input ${label} is not an Inner List`);
    return [[label, member]];
  }
  const found = [...inputs].filter((e): e is [string, InnerList] => e[1].kind === "inner" && isStr(e[1].params.get("tag")) && e[1].params.get("tag") === TAG);
  if (!found.length) throw contradicted("signature_absent", `no signature carries tag="${TAG}"`);
  return found;
}

function parameters(inner: InnerList): [number, number, string] {
  const p = inner.params;
  for (const required of ["created", "expires", "keyid"]) if (!p.has(required)) throw contradicted("signature_parameters_invalid", `the signature parameters lack ${required}`);
  const created = p.get("created"), expires = p.get("expires"), keyid = p.get("keyid");
  if (typeof created !== "number" || typeof expires !== "number" || !isStr(keyid)) throw contradicted("signature_parameters_invalid", "created and expires must be Integers and keyid a String");
  if (p.get("tag") !== TAG) throw contradicted("signature_parameters_invalid", `tag is not ${TAG}`);
  const alg = p.get("alg");
  if (alg !== undefined && alg !== "ed25519") throw contradicted("signature_parameters_invalid", "only ed25519 is supported");
  if (expires <= created) throw contradicted("signature_parameters_invalid", "expires is not after created");
  return [created, expires, keyid];
}

function agentMember(inner: InnerList): string {
  const members = inner.items.filter((i) => pyEq(i.value, "signature-agent") && i.params.has("key")).map((i) => pyStr(i.params.get("key") as BareItem));
  if (members.length !== 1) throw contradicted("component_not_covered", "the signature must cover exactly one Signature-Agent Dictionary member (the key parameter)");
  return members[0];
}

function readSignature(request: Request, chosen: string, inner: InnerList): Signature {
  const [created, expires, keyid] = parameters(inner);
  const value = dictionary(request, "signature").get(chosen);
  if (value === undefined || value.kind !== "item" || !Buffer.isBuffer(value.value)) throw contradicted("signature_headers_malformed", `no Signature byte sequence for label ${chosen}`);
  return { label: chosen, inner, signature: value.value, created, expires, keyid, agentMember: agentMember(inner), components: inner.items.map((i) => pyStr(i.value)) };
}

// --- the checks -----------------------------------------------------------------------------------------------------

function checkComponents(sig: Signature, required: string[]): void {
  const covered = new Set(sig.components);
  if (!covered.has("@authority") && !covered.has("@target-uri")) throw contradicted("component_not_covered", "the signature covers neither @authority nor @target-uri");
  for (const name of required) if (!covered.has(name)) throw contradicted("component_not_covered", `the signature does not cover ${name}, which the consumer requires`);
}

function checkAgent(request: Request, sig: Signature, pinned: string): string {
  const member = dictionary(request, "signature-agent", "signature_agent_mismatch").get(sig.agentMember);
  if (member === undefined || member.kind !== "item" || !isStr(member.value) || member.params.size) throw contradicted("signature_agent_mismatch", `Signature-Agent has no plain String member ${sig.agentMember}`);
  if (member.value !== pinned) throw contradicted("signature_agent_mismatch", "the signature names another signer than the pinned one");
  return member.value;
}

function checkAuthority(request: Request, pinned: string): string {
  const observed = authorityOf(request.url);
  if (observed !== pinned) throw contradicted("authority_mismatch", `the request was for ${observed}, not ${pinned}`);
  return observed;
}

function checkPinnedFields(request: Request, sig: Signature, pinned: Record<string, string>): string[] {
  const whole = new Set(sig.inner.items.filter((i) => !i.params.size).map((i) => pyStr(i.value)));
  for (const [name, expected] of Object.entries(pinned)) {
    if (!whole.has(name)) throw contradicted("component_not_covered", `the signature does not cover the pinned field ${name}`);
    if (fieldValue(request, name) !== expected) throw contradicted("pinned_field_mismatch", `${name} is not the value the consumer pinned`);
  }
  return Object.keys(pinned).sort();
}

const iso = (seconds: number): string => new Date(seconds * 1000).toISOString().replace(/\.000Z$/, "Z");

function checkTime(sig: Signature, at: number, a: J): void {
  if (sig.expires <= at) throw contradicted("signature_expired", `expired at ${iso(sig.expires)}, before ${iso(at)}`);
  if (sig.created > at + MAX_SKEW_SECONDS) throw contradicted("signature_created_in_future", `created ${iso(sig.created)}, after ${iso(at)}`);
  const age = a.max_age_seconds;
  if (age !== undefined && at - sig.created > age) throw contradicted("signature_too_old", `created ${at - sig.created} s before ${iso(at)}, over the ${age} s limit`);
  const window = a.max_validity_seconds ?? DEFAULT_MAX_VALIDITY_SECONDS;
  if (sig.expires - sig.created > window) throw contradicted("validity_window_too_long", `valid for ${sig.expires - sig.created} s, over the ${window} s limit`);
}

function declaresBody(request: Request): boolean {
  const length = fieldValue(request, "content-length");
  return fieldValue(request, "transfer-encoding") !== null || (length !== null && length.trim() !== "0");
}

function checkBody(request: Request, sig: Signature, bound: Buffer | null): J {
  const covered = sig.components.includes("content-digest");
  if (bound === null) {
    if (covered || declaresBody(request)) throw new Fail("not_established", "body_unavailable", "the request declares or covers a body and the case binds none");
    bound = Buffer.alloc(0);
  }
  if (bound.length && !covered) throw contradicted("body_not_covered", "the request has a body and the signature does not cover content-digest");
  if (!covered) return { id: "body", status: "met", covered: false, length: 0 };
  const raw = fieldValue(request, "content-digest");
  if (raw === null) throw contradicted("content_digest_mismatch", "content-digest is covered but the request has no such field");
  let members: Map<string, Member>;
  try { members = parseDictionary(raw); } catch (e) {
    if (e instanceof SFError) throw contradicted("content_digest_mismatch", `content-digest: ${e.message}`);
    throw e;
  }
  const items = sig.inner.items.filter((i) => pyEq(i.value, "content-digest"));
  const signed = items.some((i) => !i.params.has("key")) ? null : new Set(items.map((i) => pyStr(i.params.get("key") as BareItem)));
  const verified: string[] = [];
  for (const [algorithm, compute] of DIGESTS) {
    const member = members.get(algorithm);
    if (member === undefined || (signed !== null && !signed.has(algorithm))) continue;
    if (member.kind !== "item" || !Buffer.isBuffer(member.value) || !member.value.equals(compute(bound))) throw contradicted("content_digest_mismatch", `${algorithm} is not the digest of the received body`);
    verified.push(algorithm);
  }
  if (!verified.length) throw contradicted("content_digest_unsupported", "content-digest carries no covered sha-256 or sha-512 member");
  return { id: "body", status: "met", covered: true, length: bound.length, algorithms: verified };
}

function checkSignature(sig: Signature, request: Request, keys: Map<string, J>, allowTest: boolean, at: number): J {
  const key = keys.get(sig.keyid);
  if (key === undefined) throw new Fail("not_established", "key_not_in_directory", `keyid ${sig.keyid.slice(0, 12)}... is not in the pinned directory`);
  if ("d" in key) throw contradicted("key_private_published", "the pinned directory publishes this key's private part");
  if ((key.use ?? "sig") !== "sig" || ("key_ops" in key && !key.key_ops.includes("verify"))) throw contradicted("key_not_for_signing", "the pinned directory does not mark this key for signatures");
  if ("nbf" in key && (at < key.nbf || sig.created < key.nbf)) throw contradicted("key_not_yet_valid", `the key is valid from ${iso(key.nbf)}`);
  if ("exp" in key && (at >= key.exp || sig.created >= key.exp)) throw contradicted("key_expired", `the key expired at ${iso(key.exp)}`);
  if (KNOWN_TEST_KEYS_X.has(key.x) && !allowTest) throw contradicted("test_key_refused", "the signing key is a published test key (RFC 9421 Appendix B.1.4)");
  const base = signatureBase(request, sig.inner);
  const publicKey = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: key.x }, format: "jwk" });
  let ok = false;
  try { ok = edVerify(null, Buffer.from(base, "ascii"), publicKey, sig.signature); } catch { ok = false; }
  if (!ok) throw contradicted("signature_invalid", "the signature does not verify over the covered components");
  return { id: "signature", status: "met", algorithm: "ed25519", keyid: sig.keyid, signature_base_sha256: sha256Hex(Buffer.from(base, "ascii")) };
}

// --- the case, the policy and the claim -----------------------------------------------------------------------------

function object(value: J, label: string, required: string[], optional: string[] = []): J {
  if (!isObj(value) || required.some((k) => !(k in value)) || Object.keys(value).some((k) => !required.includes(k) && !optional.includes(k))) {
    throw new CaseError(`${label}: expected fields ${[...required].sort()}, optional ${[...optional].sort()}`);
  }
  return value;
}

function instant(value: J, label: string): number {
  const m = typeof value === "string" ? /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z$/.exec(value) : null;
  if (m === null) throw new CaseError(`${label}: expected UTC RFC 3339 seconds (ending Z)`);
  const [y, mo, d, h, mi, s] = m.slice(1).map(Number);
  const ms = Date.UTC(y, mo - 1, d, h, mi, s);
  const back = new Date(ms);
  if (y < 1 || back.getUTCFullYear() !== y || back.getUTCMonth() !== mo - 1 || back.getUTCDate() !== d || h > 23 || mi > 59 || s > 59) {
    throw new CaseError(`${label}: invalid UTC instant`);
  }
  return Math.floor(ms / 1000);
}

function policyAt(a: J): number {
  if (typeof a.directory_sha256 !== "string" || !HEX64.test(a.directory_sha256)) throw new CaseError("assessment.directory_sha256: expected lowercase SHA-256");
  const agent = nonEmpty(a.signature_agent, "assessment.signature_agent");
  const s = urlsplit(agent);
  if (s.scheme !== "https" || !hostname(s) || s.fragment || username(s) !== null) throw new CaseError("assessment.signature_agent: expected an https URL without a fragment or credentials");
  const authority = nonEmpty(a.authority, "assessment.authority");
  if (authority !== authority.toLowerCase() || /[/?#@ ]/.test(authority)) throw new CaseError("assessment.authority: expected a lowercase host[:port]");
  const at = instant(a.at, "assessment.at");
  const required = a.required_components ?? [];
  if (!Array.isArray(required) || !required.every((r: J) => typeof r === "string" && r)
      || JSON.stringify(required) !== JSON.stringify([...new Set(required)].sort())) {
    throw new CaseError("assessment.required_components: expected a sorted list of distinct component names");
  }
  for (const name of ["max_age_seconds", "max_validity_seconds"]) {
    const v = a[name];
    if (name in a && (!isInt(v) || v <= 0)) throw new CaseError(`assessment.${name}: expected a positive integer`);
  }
  if (typeof (a.allow_test_keys ?? false) !== "boolean") throw new CaseError("assessment.allow_test_keys: expected a boolean");
  if ("label" in a) nonEmpty(a.label, "assessment.label");
  const pinned = a.pinned_fields ?? {};
  if (!isObj(pinned) || ("pinned_fields" in a && !Object.keys(pinned).length)
      || !Object.keys(pinned).every((n) => TCHAR.test(n) && n === n.toLowerCase())
      || !Object.values(pinned).every((v) => typeof v === "string")) {
    throw new CaseError("assessment.pinned_fields: expected a non-empty object of lowercase field names to values");
  }
  for (const [name, value] of Object.entries(pinned)) fieldText(value, `assessment.pinned_fields.${name}`);
  return at;
}

/** The bytes of one case artifact and its binding record; null bytes when the file is absent. */
function bound(artifacts: J, root: string, name: J, label: string): [Buffer | null, J] {
  const key = nonEmpty(name, label);
  if (!Object.hasOwn(artifacts, key)) throw new CaseError(`${label}: names no case artifact`);
  const meta = object(artifacts[key], `artifacts.${key}`, ["path", "sha256", "length"]);
  const path = nonEmpty(meta.path, `artifacts.${key}.path`);
  if (path.includes("\0") || path.startsWith("/") || path.split("/").some((p: string) => p === "." || p === ".." || p === "")) throw new CaseError(`artifacts.${key}.path: must be a normalized relative path`);
  if (typeof meta.sha256 !== "string" || !HEX64.test(meta.sha256)) throw new CaseError(`artifacts.${key}.sha256: expected lowercase SHA-256`);
  if (!isInt(meta.length) || meta.length < 0 || meta.length > MAX_ARTIFACT_BYTES) throw new CaseError(`artifacts.${key}.length: expected integer from 0 to ${MAX_ARTIFACT_BYTES}`);
  let data: Buffer;
  try {
    let at = root;
    for (const part of path.split("/")) { at = join(at, part); if (lstatSync(at).isSymbolicLink()) throw new CaseError(`artifacts.${key}.path: symlink traversal refused`); }
    data = readFileSync(at);
  } catch (e) {
    if (e instanceof CaseError) throw e;
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return [null, { status: "unavailable", path }];
    throw new CaseError(`artifacts.${key}: unsafe or unreadable artifact`);
  }
  if (data.length !== meta.length || sha256Hex(data) !== meta.sha256) throw new CaseError(`artifacts.${key}: artifact binding_mismatch (length or SHA-256)`);
  return [data, { status: "bound", path, sha256: meta.sha256, length: meta.length }];
}

function uncovered(sig: Signature): string[] {
  const covered = new Set(sig.components);
  const whole = covered.has("@target-uri") || covered.has("@request-target");
  return (["method", "path", "query"] as const).filter((part) => !(covered.has(`@${part}`) || whole));
}

/** Judge one bound request under the consumer's pinned signer, directory and clock. CaseError for invalid input. */
export function adjudicate(caseDoc: J, policy: J, root: string): J {
  const c = object(caseDoc, "case", ["schema_version", "case_id", "artifacts"]);
  const p = object(policy, "policy", ["schema_version", "assessments"], ["witnesses"]);
  if (c.schema_version !== "probity-case/v1" || p.schema_version !== "probity-policy/v1") throw new CaseError("unsupported schema_version");
  const caseId = nonEmpty(c.case_id, "case_id");
  if (!isObj(c.artifacts) || !isObj(p.assessments)) throw new CaseError("artifacts and assessments: expected objects");
  const a = object(Object.hasOwn(p.assessments, caseId) ? p.assessments[caseId] : undefined, "assessment", [...REQUIRED, "claim_type"], OPTIONAL);
  if (a.claim_type !== CLAIM_TYPE) throw new CaseError("unsupported claim_type");
  const at = policyAt(a);
  const scope: J = { signature_agent: a.signature_agent, authority: a.authority, at: a.at, directory_sha256: a.directory_sha256, limit: LIMIT };
  const decision = (verdict: string, reason: string, checks: J[] = []): J => ({ schema_version: "probity-decision/v1", case_id: caseId, claim_type: CLAIM_TYPE, decision: verdict, reason, scope, checks });
  const [raw, requestBinding] = bound(c.artifacts, root, a.request, "assessment.request");
  scope.request = requestBinding;
  if (raw === null) return decision("not_established", "request_unavailable");
  const request = readRequest(raw);
  const [directoryRaw, directoryBinding] = bound(c.artifacts, root, a.directory, "assessment.directory");
  scope.directory = directoryBinding;
  if (directoryRaw === null) return decision("not_established", "directory_unavailable");
  const pinned = { id: "directory_pinned", status: directoryBinding.sha256 === a.directory_sha256 ? "met" : "failed", expected: a.directory_sha256, observed: directoryBinding.sha256 };
  if (pinned.status !== "met") return decision("not_established", "directory_not_pinned", [pinned]);
  const keys = readDirectory(directoryRaw);
  let body: Buffer | null = null;
  if ("body" in a) {
    const [bodyRaw, bodyBinding] = bound(c.artifacts, root, a.body, "assessment.body");
    scope.body = bodyBinding;
    if (bodyRaw === null) return decision("not_established", "body_unavailable", [pinned]);
    body = bodyRaw;
  }
  let chosen: [string, InnerList][];
  try { chosen = candidates(request, a.label); } catch (e) {
    if (!(e instanceof Fail)) throw e;
    return decision(e.verdict, e.reason, [pinned, { id: e.reason, status: "failed", detail: e.message }]);
  }
  const failures: [Fail, J[], boolean][] = [];
  for (const [label, inner] of chosen) {
    const outcome = judgeOne(request, label, inner, keys, body, at, a);
    if (!(outcome[0] instanceof Fail)) {
      const [sig, checks] = outcome as [Signature, J[]];
      scope.record = { label: sig.label, keyid: sig.keyid, created: sig.created, expires: sig.expires, covered: sig.components, uncovered: uncovered(sig) };
      if (chosen.length > 1) checks.push({ id: "signatures", status: "met", judged: chosen.map(([l]) => l), supported_by: sig.label });
      return decision("supported", "request_signed_by_pinned_agent", [pinned, ...checks]);
    }
    failures.push(outcome as [Fail, J[], boolean]);
  }
  const [failure, checks] = failures.find((f) => f[2]) ?? failures[0];
  if (chosen.length > 1) checks.push({ id: "signatures", status: "failed", judged: chosen.map(([l]) => l), reasons: failures.map((f) => f[0].reason) });
  return decision(failure.verdict, failure.reason, [pinned, ...checks]);
}

function judgeOne(request: Request, label: string, inner: InnerList, keys: Map<string, J>, body: Buffer | null, at: number, a: J): [Signature, J[]] | [Fail, J[], boolean] {
  const checks: J[] = [];
  let namesPinned = false;
  try {
    const sig = readSignature(request, label, inner);
    checks.push({ id: "signature_headers", status: "met", label: sig.label, created: sig.created, expires: sig.expires, keyid: sig.keyid });
    checkComponents(sig, a.required_components ?? []);
    checks.push({ id: "components", status: "met", covered: sig.components });
    const agent = checkAgent(request, sig, a.signature_agent);
    namesPinned = true;
    checks.push({ id: "signature_agent", status: "met", observed: agent });
    checks.push({ id: "authority", status: "met", observed: checkAuthority(request, a.authority) });
    if ("pinned_fields" in a) checks.push({ id: "pinned_fields", status: "met", fields: checkPinnedFields(request, sig, a.pinned_fields) });
    checkTime(sig, at, a);
    checks.push({ id: "validity", status: "met", created: iso(sig.created), expires: iso(sig.expires) });
    checks.push(checkBody(request, sig, body));
    checks.push(checkSignature(sig, request, keys, a.allow_test_keys === true, at));
    return [sig, checks];
  } catch (e) {
    if (!(e instanceof Fail)) throw e;
    checks.push({ id: e.reason, status: "failed", detail: e.message });
    return [e, checks, namesPinned];
  }
}

/** The CLI contract of agent-evidence-verify for this claim: CASE --policy POLICY --json. 0 with a decision, 2 for
 *  invalid input. */
export function main(argv: string[]): number {
  const caseAt = argv.findIndex((x) => !x.startsWith("--"));
  const policyAt_ = argv.indexOf("--policy");
  if (caseAt < 0 || policyAt_ < 0 || !argv[policyAt_ + 1] || caseAt === policyAt_ + 1) {
    console.error("usage: probity-records-verify web-bot-auth CASE.json --policy POLICY.json [--json]");
    return 2;
  }
  try {
    const casePath = argv[caseAt];
    const caseDoc = strictJson(readFileSync(casePath), "case");
    const policy = strictJson(readFileSync(argv[policyAt_ + 1]), "policy");
    const root = casePath.includes("/") ? casePath.slice(0, casePath.lastIndexOf("/")) || "/" : ".";
    console.log(JSON.stringify(adjudicate(caseDoc, policy, root), null, 2));
    return 0;
  } catch (e) {
    if (e instanceof CaseError || (e as NodeJS.ErrnoException).code !== undefined) { console.error(`invalid input: ${(e as Error).message}`); return 2; }
    throw e;
  }
}


// The verified identities of one request, and the agent stamp verifier: the TypeScript twin of
// probity_records.verified_identities and probity_records.stamp. It returns the same identities, or the same
// refusal code, as the Python package on every vector in packages/probity-records/vectors/shared/verified_identities.json.
// The verifying key never comes from the presented data: the trust bundle pins each issuer's keys by RFC 7638
// thumbprint, scoped to roles and tenants. Spec: packages/probity-records/docs/verified-identities.md.
import { createHash, createPublicKey, timingSafeEqual, verify as cryptoVerify, X509Certificate, type KeyObject } from "node:crypto";
import { CanonicalIdentity, IdentityStringError, Ref } from "./identity.ts";
import { type InnerList, type Item, type Member, SFError, parseDictionary, serializeInnerList } from "./sf.ts";
import { IdentityDigestError, actChainDigest, cnfProblem, isFloat, jwkThumbprint, parsePy, ts } from "./verify.ts";

type J = any; // eslint-disable-line @typescript-eslint/no-explicit-any

export const PRINCIPALS_HEADER = "probity-principals";
export const STAMP_HEADERS = [PRINCIPALS_HEADER, "content-digest", "signature-input", "signature"];
export const COVERED = ["@method", "@target-uri", "@authority", "content-digest", PRINCIPALS_HEADER];
const STAMP_PARAMS = ["alg", "created", "expires", "keyid", "nonce", "tag"];
export const MAX_TTL_SECONDS = 300;
const MAX_NONCE_BYTES = 128;
const TOKEN_ROLES = ["user", "agent", "sponsor"] as const;
const PIN_ROLES = [...TOKEN_ROLES, "stamp"];
const ROLE_TYPES: Record<string, (string | null)[]> = { user: ["at+jwt", "oauth-id-jag+jwt"], agent: ["at+jwt"], sponsor: [null, "jwt"] };
const KEY_REFERENCES = ["jku", "jwk", "x5u", "x5c"];
const BUNDLE_MEMBERS = ["audience", "environment", "issuers", "profile", "tenant", "version"];
const PRIVATE_JWK = ["d", "p", "q", "dp", "dq", "qi", "k", "oth"];
const MIN_RSA_BITS = 2048;
const DIGEST = /^sha256:[0-9a-f]{64}$/;

/** A request whose identities cannot be established; `code` is the registered reason. */
export class VerifiedIdentitiesRefused extends Error {
  readonly code: string;
  constructor(code: string, detail = "") { super(detail ? `${code}: ${detail}` : code); this.code = code; }
}
const refuse = (code: string, detail = ""): never => { throw new VerifiedIdentitiesRefused(code, detail); };

const isObj = (v: J): boolean => v !== null && typeof v === "object" && !Array.isArray(v);
const sameKeys = (v: J, keys: string[]): boolean => isObj(v) && Object.keys(v).sort().join("\0") === [...keys].sort().join("\0");
const b64u = (data: Buffer): string => data.toString("base64url");
const sha256Hex = (data: Buffer | string): string => createHash("sha256").update(data).digest("hex");
const isInt = (holder: J, key: string): boolean => typeof holder[key] === "number" && Number.isInteger(holder[key]) && !isFloat(holder, key, holder[key]);
const utf8Len = (s: string): number => Buffer.byteLength(s, "utf8");

// --- strict JSON segments: a repeated member is refused, as Python's object_pairs_hook refuses it ----------------

class Duplicate extends Error {}

function noDuplicates(text: string): void {
  const stack: { obj: boolean; keys: Set<string>; expectKey: boolean }[] = [];
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch === '"') {
      let j = i + 1;
      while (j < text.length && text[j] !== '"') j += text[j] === "\\" ? 2 : 1;
      const top = stack[stack.length - 1];
      if (top?.obj && top.expectKey) {
        const key = JSON.parse(text.slice(i, j + 1)) as string;
        if (top.keys.has(key)) throw new Duplicate("duplicate");
        top.keys.add(key);
        top.expectKey = false;
      }
      i = j;
    } else if (ch === "{" || ch === "[") stack.push({ obj: ch === "{", keys: new Set(), expectKey: ch === "{" });
    else if (ch === "}" || ch === "]") stack.pop();
    else if (ch === ",") { const top = stack[stack.length - 1]; if (top?.obj) top.expectKey = true; }
  }
}

function segmentJson(segment: string): J {
  const text = Buffer.from(segment, "base64url").toString("utf8");
  noDuplicates(text);
  return parsePy(text);
}

// --- the trust bundle -------------------------------------------------------------------------------------------

interface PinnedKey { jwk: J; thumbprint: string; roles: Set<string>; tenants: Set<string> }
export interface TrustBundle { environment: string; tenant: string; audience: string; profile: string; issuers: Map<string, PinnedKey[]> }

const isStampKey = (jwk: J): boolean => jwk.kty === "OKP" && jwk.crv === "Ed25519" && typeof jwk.x === "string";
const stampKeyId = (raw: Buffer): string => sha256Hex(raw);
const rawOf = (jwk: J): Buffer => Buffer.from(String(jwk.x), "base64url");
const distinctNames = (v: J): boolean => Array.isArray(v) && v.length > 0 && v.every((t) => typeof t === "string" && t !== "") && new Set(v).size === v.length;

export function parseBundle(doc: J): TrustBundle {
  const bad = (detail: string): never => refuse("trust_bundle_malformed", detail);
  if (!sameKeys(doc, BUNDLE_MEMBERS)) bad("a bundle has exactly its six members");
  if (doc.version !== 1) bad("version is 1");
  try { new Ref("service", doc.environment, "bundle", "probe"); } catch { bad("environment is an identity environment"); }
  for (const name of ["tenant", "audience"]) if (typeof doc[name] !== "string" || doc[name] === "") bad(`${name} is a non-empty string`);
  if (doc.profile !== "basic" && doc.profile !== "strict") bad("profile is basic or strict");
  if (!isObj(doc.issuers) || Object.keys(doc.issuers).length === 0) bad("issuers is a non-empty object");
  const issuers = new Map<string, PinnedKey[]>();
  for (const [url, entry] of Object.entries(doc.issuers as Record<string, J>)) issuers.set(url, parseIssuer(url, entry));
  return { environment: doc.environment, tenant: doc.tenant, audience: doc.audience, profile: doc.profile, issuers };
}

function parseIssuer(url: string, entry: J): PinnedKey[] {
  const bad = (detail: string): never => refuse("trust_bundle_malformed", `issuer ${url}: ${detail}`);
  if (url === "" || !/^[\x00-\x7f]*$/.test(url)) bad("an issuer is a non-empty ASCII string");
  if (!sameKeys(entry, ["keys", "pins"])) bad("exactly keys and pins");
  if (!Array.isArray(entry.keys) || !entry.keys.length || !Array.isArray(entry.pins) || !entry.pins.length) bad("keys and pins are non-empty lists");
  const byThumb = new Map<string, J>();
  for (const jwk of entry.keys) {
    if (!isObj(jwk) || Object.keys(jwk).some((k) => PRIVATE_JWK.includes(k))) bad("a key is a public JWK");
    let thumb = "";
    try { thumb = jwkThumbprint(jwk); } catch { bad("a key has no RFC 7638 thumbprint"); }
    if (jwk.kty === "RSA") {
      const n = Buffer.from(String(jwk.n), "base64url");
      let start = 0; while (start < n.length && n[start] === 0) start++;
      if ((n.length - start) * 8 < MIN_RSA_BITS) bad(`an RSA key shorter than ${MIN_RSA_BITS} bits`);
    }
    if (byThumb.has(thumb)) bad("a key is listed twice");
    byThumb.set(thumb, jwk);
  }
  const pinned: PinnedKey[] = [];
  for (const pin of entry.pins) {
    if (!sameKeys(pin, ["roles", "tenants", "thumbprint"])) bad("a pin has exactly thumbprint, roles, tenants");
    const jwk = typeof pin.thumbprint === "string" ? byThumb.get(pin.thumbprint) : undefined;
    if (jwk === undefined || pinned.some((p) => p.thumbprint === pin.thumbprint)) bad("a pin names no listed key, or one pinned twice");
    if (!distinctNames(pin.roles) || !pin.roles.every((r: string) => PIN_ROLES.includes(r)) || !distinctNames(pin.tenants)) {
      bad("roles and tenants are lists of distinct names");
    }
    if (pin.roles.includes("stamp") && (pin.roles.length !== 1 || !isStampKey(jwk))) bad("a stamp key is an Ed25519 key pinned for stamp only");
    if (!pin.roles.includes("stamp") && (!url.startsWith("https://") || typeof jwk.kid !== "string")) bad("a token issuer is https and its keys carry kid");
    pinned.push({ jwk, thumbprint: pin.thumbprint, roles: new Set(pin.roles), tenants: new Set(pin.tenants) });
  }
  return pinned;
}

function admit(bundle: TrustBundle, key: PinnedKey, role: string): PinnedKey {
  if (!key.roles.has(role) || !key.tenants.has(bundle.tenant)) return refuse("principal_key_not_pinned", `${role} in ${bundle.tenant}`);
  return key;
}

function pinnedKey(bundle: TrustBundle, issuer: J, role: string, kid: J): PinnedKey {
  const keys = typeof issuer === "string" ? bundle.issuers.get(issuer) : undefined;
  if (keys === undefined) return refuse("principal_issuer_untrusted", String(issuer).slice(0, 80));
  const matches = keys.filter((k) => typeof kid === "string" && k.jwk.kid === kid);
  if (matches.length !== 1) return refuse("token_kid_unknown");
  return admit(bundle, matches[0], role);
}

/** TrustBundle.stamp_key: the one listed Ed25519 key whose stamp key id is `keyid`, pinned for stamps here. */
function stampKey(bundle: TrustBundle, keyid: string): PinnedKey {
  const matches = [...bundle.issuers.values()].flat().filter((k) => isStampKey(k.jwk) && stampKeyId(rawOf(k.jwk)) === keyid);
  if (matches.length !== 1) return refuse("stamp_key_mismatch");
  return admit(bundle, matches[0], "stamp");
}

// --- signatures ---------------------------------------------------------------------------------------------------

function publicKey(jwk: J): KeyObject {
  const members = jwk.kty === "RSA" ? ["kty", "n", "e"] : jwk.kty === "EC" ? ["kty", "crv", "x", "y"] : ["kty", "crv", "x"];
  const key: J = {}; for (const m of members) key[m] = jwk[m];
  return createPublicKey({ key, format: "jwk" });
}

/** probity_records.identity._verify_jws: the algorithm the pinned key's type takes, never the one a token asks for alone. */
function verifyJws(alg: string, jwk: J, data: Buffer, sig: Buffer): boolean {
  try {
    if (alg === "EdDSA" && jwk.kty === "OKP" && jwk.crv === "Ed25519") return cryptoVerify(null, data, publicKey(jwk), sig);
    if (alg === "ES256" && jwk.kty === "EC" && jwk.crv === "P-256") {
      return sig.length === 64 && cryptoVerify("sha256", data, { key: publicKey(jwk), dsaEncoding: "ieee-p1363" }, sig);
    }
    if (alg === "RS256" && jwk.kty === "RSA") return cryptoVerify("sha256", data, publicKey(jwk), sig);
  } catch { return false; }
  return false;
}

// --- one identity-provider token ----------------------------------------------------------------------------------

interface Token { role: string; raw: string; issuer: string; subject: string; client: string; claims: J }

function seconds(claims: J, name: string): number {
  if (!isInt(claims, name)) refuse("token_malformed", `${name} is not an integer`);
  return claims[name];
}

function verifyToken(role: string, token: J, bundle: TrustBundle, when: number): Token {
  const parts = typeof token === "string" && /^[\x00-\x7f]*$/.test(token) ? token.split(".") : [];
  if (parts.length !== 3 || parts.some((p) => p === "")) refuse("token_malformed", `the ${role} credential is not a compact JWS`);
  let header: J, claims: J;
  try { header = segmentJson(parts[0]); claims = segmentJson(parts[1]); } catch { return refuse("token_malformed"); }
  if (!isObj(header) || !isObj(claims)) refuse("token_malformed");
  if (KEY_REFERENCES.some((k) => k in header)) refuse("token_header_names_a_key");
  if ("crit" in header) refuse("token_critical_unsupported");
  if (typeof claims.iss !== "string" || !bundle.issuers.has(claims.iss)) refuse("principal_issuer_untrusted");
  const key = pinnedKey(bundle, claims.iss, role, header.kid);
  let typ: J = "typ" in header ? header.typ : null;
  if (typeof typ === "string") { typ = typ.toLowerCase(); if (typ.startsWith("application/")) typ = typ.slice(12); }
  if (!ROLE_TYPES[role].includes(typ)) refuse("token_type_mismatch");
  if (!verifyJws(String(header.alg), key.jwk, Buffer.from(`${parts[0]}.${parts[1]}`, "ascii"), Buffer.from(parts[2], "base64url"))) {
    refuse("token_signature_unverified");
  }
  const client = role !== "sponsor" ? claims.client_id : ("azp" in claims ? claims.azp : claims.client_id);
  if (typeof claims.sub !== "string" || claims.sub === "" || typeof client !== "string" || client === "") refuse("token_malformed");
  const iat = seconds(claims, "iat"), exp = seconds(claims, "exp");
  const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!audiences.includes(bundle.audience)) refuse("token_wrong_audience");
  if (exp <= iat) refuse("token_malformed", "exp is not after iat");
  if (when < iat) refuse("principal_not_yet_valid");
  if ("nbf" in claims && seconds(claims, "nbf") > when) refuse("token_not_yet_valid");
  if (when >= exp) refuse("principal_expired");
  return { role, raw: token, issuer: claims.iss, subject: claims.sub, client, claims };
}

function actors(act: J): J[] {
  const out: J[] = [];
  while (act !== null && act !== undefined) {
    if (!isObj(act) || typeof act.sub !== "string" || act.sub === "") refuse("principal_act_malformed");
    if ("iss" in act && (typeof act.iss !== "string" || act.iss === "")) refuse("principal_act_malformed");
    out.push(act);
    act = act.act;
  }
  return out;
}

function identityFromTokens(found: Record<string, Token>, bundle: TrustBundle): CanonicalIdentity {
  const env = bundle.environment;
  const { user, agent, sponsor } = found;
  const sponsorRef = sponsor ? new Ref("sponsor", env, sponsor.issuer, sponsor.subject) : undefined;
  if (sponsor && !agent) refuse("principals_need_agent");
  if (!user) return new CanonicalIdentity({ kind: "agent", chain: [new Ref("agent", env, agent.issuer, agent.subject)], sponsor: sponsorRef });
  const userRef = new Ref("user", env, user.issuer, user.subject);
  const chainActors = "act" in user.claims ? actors(user.claims.act) : [];
  if (!agent) {
    if (chainActors.length) refuse("principal_credential_missing");
    return new CanonicalIdentity({ kind: "unknown", user: userRef });
  }
  if (chainActors.length && chainActors[0].sub !== agent.subject && chainActors[0].sub !== agent.client) refuse("principal_act_names_another_agent");
  if (user.client !== agent.client) refuse("principal_user_token_not_issued_to_agent");
  const parents = chainActors.slice(1).map((a) => new Ref("agent", env, String(a.iss ?? user.issuer), a.sub));
  let act: string | undefined;
  if ("act" in user.claims) {
    try { act = actChainDigest(user.claims.act, user.claims, "act"); } catch (e) {
      if (e instanceof IdentityDigestError) refuse(e.code); throw e;
    }
  }
  return new CanonicalIdentity({ kind: "agent", user: userRef, chain: [...parents.reverse(), new Ref("agent", env, agent.issuer, agent.subject)], sponsor: sponsorRef, act });
}

// --- possession: probity_records.possession.check_possession ------------------------------------------------------

const DPOP_TYP = "dpop+jwt";
const DPOP_HEADER = ["alg", "jwk", "typ", "x5c"];
const DPOP_JWK: Record<string, string[]> = { ES256: ["crv", "kty", "x", "y"], EdDSA: ["crv", "kty", "x"] };
const DPOP_CURVE: Record<string, [string, string]> = { ES256: ["EC", "P-256"], EdDSA: ["OKP", "Ed25519"] };
const MAX_PROOF_BYTES = 8 << 10, MAX_JTI_BYTES = 128, DEFAULT_SKEW = 120;

export interface RequestFacts { method: string; url: string; content: Buffer | null; dpop: string | null; clientCertificate: Buffer | null; headers: [string, string][] }

function eq(a: string, b: string): boolean {
  const x = Buffer.from(a), y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

/** possession.normalize_htu, with Python's urlsplit split rules. */
export function normalizeHtu(url: string): string {
  const m = /^([A-Za-z][A-Za-z0-9+.-]*):\/\/([^/?#]*)([^?#]*)/.exec(url);
  const scheme = m ? m[1].toLowerCase() : "";
  let netloc = m ? m[2] : "";
  netloc = netloc.slice(netloc.lastIndexOf("@") + 1);
  let host = netloc, portText = "";
  const bracket = /^\[([^\]]*)\](?::(.*))?$/.exec(netloc);
  if (bracket) { host = bracket[1]; portText = bracket[2] ?? ""; }
  else if (netloc.includes(":")) { host = netloc.slice(0, netloc.indexOf(":")); portText = netloc.slice(netloc.indexOf(":") + 1); }
  host = host.toLowerCase();
  if ((scheme !== "https" && scheme !== "http") || !host) throw new Error("htu_not_absolute");
  let port: number | null = null;
  if (portText !== "") {
    if (!/^\d+$/.test(portText) || +portText > 65535) throw new Error("port");
    port = +portText;
  }
  const authority = port === null || (scheme === "https" && port === 443) || (scheme === "http" && port === 80) ? host : `${host}:${port}`;
  return `${scheme}://${authority}${m![3] || "/"}`;
}

function dpopHeader(segment: string, expectedJkt: string): [string, KeyObject | null, string | null] {
  let h: J;
  try {
    const raw = Buffer.from(segment, "base64url");
    if (b64u(raw) !== segment) return ["", null, "dpop_malformed"];
    h = segmentJson(segment);
  } catch (e) { return ["", null, e instanceof Duplicate ? "dpop_duplicate_member" : "dpop_malformed"]; }
  if (!isObj(h)) return ["", null, "dpop_malformed"];
  if (Object.keys(h).some((k) => !DPOP_HEADER.includes(k))) return ["", null, "dpop_header_member_unknown"];
  if (h.typ !== DPOP_TYP) return ["", null, "dpop_typ_invalid"];
  const alg = h.alg;
  if (alg !== "ES256" && alg !== "EdDSA") return ["", null, "dpop_alg_not_allowed"];
  const jwk = h.jwk;
  if (!isObj(jwk)) return ["", null, "dpop_jwk_invalid"];
  if (["d", "p", "q", "dp", "dq", "qi", "k"].some((m) => m in jwk)) return ["", null, "dpop_jwk_private"];
  const [kty, crv] = DPOP_CURVE[alg];
  if (!sameKeys(jwk, DPOP_JWK[alg]) || jwk.kty !== kty || jwk.crv !== crv) return ["", null, "dpop_jwk_invalid"];
  let key: KeyObject;
  try {
    const x = Buffer.from(String(jwk.x), "base64url");
    if (x.length !== 32 || (alg === "ES256" && Buffer.from(String(jwk.y), "base64url").length !== 32)) throw new Error("length");
    key = publicKey(jwk);
  } catch { return ["", null, "dpop_jwk_invalid"]; }
  if ("x5c" in h) {
    const x5c = h.x5c;
    if (!Array.isArray(x5c) || x5c.length !== 1 || typeof x5c[0] !== "string") return ["", null, "dpop_x5c_invalid"];
    let presented: J;
    try {
      if (!/^[A-Za-z0-9+/]*={0,2}$/.test(x5c[0])) throw new Error("base64");
      presented = new X509Certificate(Buffer.from(x5c[0], "base64")).publicKey.export({ format: "jwk" });
    } catch { return ["", null, "dpop_x5c_invalid"]; }
    const members = presented.kty === "OKP" && presented.crv === "Ed25519" ? DPOP_JWK.EdDSA
      : presented.kty === "EC" && presented.crv === "P-256" ? DPOP_JWK.ES256 : null;
    if (members === null) return ["", null, "dpop_x5c_invalid"];
    if (!sameKeys(jwk, members) || members.some((m) => presented[m] !== jwk[m])) return ["", null, "dpop_x5c_key_mismatch"];
  }
  if (!eq(jwkThumbprint(jwk), expectedJkt)) return ["", null, "dpop_key_not_confirmed"];
  return [alg, key, null];
}

function dpopClaims(p: J, method: string, url: string, now: number, skew: number, accessToken: string | null, content: Buffer): string | null {
  if (!isObj(p)) return "dpop_malformed";
  if (p.htm !== method) return "dpop_htm_mismatch";
  try { if (typeof p.htu !== "string" || normalizeHtu(p.htu) !== normalizeHtu(url)) return "dpop_htu_mismatch"; }
  catch { return "dpop_htu_mismatch"; }
  if (accessToken === null) { if ("ath" in p) return "dpop_ath_unexpected"; }
  else if (!("ath" in p)) return "dpop_ath_missing";
  else if (typeof p.ath !== "string" || !eq(p.ath, b64u(createHash("sha256").update(accessToken, "ascii").digest()))) return "dpop_ath_mismatch";
  if (!isInt(p, "iat")) return "dpop_malformed";
  if (p.iat < now - skew) return "dpop_iat_stale";
  if (p.iat > now + skew) return "dpop_iat_future";
  if (typeof p.jti !== "string" || p.jti === "" || utf8Len(p.jti) > MAX_JTI_BYTES) return "dpop_jti_invalid";
  const digest = p.ans_content_digest;
  if (digest === undefined || digest === null) return "dpop_content_unbound";
  if (typeof digest !== "string" || !eq(digest, b64u(createHash("sha256").update(content).digest()))) return "dpop_content_mismatch";
  return null;
}

/** possession.check_dpop: the proof's method on success, or the refusal code. */
export function checkDpop(proof: J, method: string, url: string, at: string, expectedJkt: string, accessToken: string | null, content: Buffer): string {
  if (typeof proof !== "string") return "dpop_malformed";
  if (proof.length > MAX_PROOF_BYTES) return "dpop_too_large";
  const parts = proof.split(".");
  if (parts.length !== 3 || parts.some((p) => p === "")) return "dpop_malformed";
  const [alg, key, problem] = dpopHeader(parts[0], expectedJkt);
  if (problem) return problem;
  const sig = Buffer.from(parts[2], "base64url");
  const data = Buffer.from(`${parts[0]}.${parts[1]}`, "ascii");
  const ok = alg === "EdDSA" ? cryptoVerify(null, data, key!, sig)
    : sig.length === 64 && cryptoVerify("sha256", data, { key: key!, dsaEncoding: "ieee-p1363" }, sig);
  if (!ok) return "dpop_signature_unverified";
  let claims: J;
  try {
    if (b64u(Buffer.from(parts[1], "base64url")) !== parts[1]) return "dpop_malformed";
    claims = segmentJson(parts[1]);
  } catch (e) { return e instanceof Duplicate ? "dpop_duplicate_member" : "dpop_malformed"; }
  return dpopClaims(claims, method, url, Math.floor(ts(at) / 1e6), DEFAULT_SKEW, accessToken, content) ?? "ok";
}

/** possession.check_client_certificate. */
export function checkClientCertificate(der: Buffer | null, expected: string, at: string): string {
  if (der === null) return "mtls_certificate_missing";
  if (!eq(b64u(createHash("sha256").update(der).digest()), expected)) return "mtls_certificate_not_confirmed";
  let cert: X509Certificate;
  try { cert = new X509Certificate(der); } catch { return "mtls_certificate_invalid"; }
  const when = ts(at) / 1000;
  if (when < Date.parse(cert.validFrom)) return "mtls_certificate_not_yet_valid";
  if (when > Date.parse(cert.validTo)) return "mtls_certificate_expired";
  return "ok";
}

function possession(tokens: Token[], request: RequestFacts | null, at: string): string | null {
  const bound = tokens.filter((t) => "cnf" in t.claims);
  if (!bound.length) return null;
  const cnf = bound[0].claims.cnf;
  const same = (a: J, b: J): boolean => isObj(a) && isObj(b) && sameKeys(a, Object.keys(b)) && Object.keys(b).every((k) => a[k] === b[k]);
  if (!isObj(cnf) || bound.some((t) => !same(t.claims.cnf, cnf))) {
    refuse("possession_not_the_grant_key");
  }
  const facts = request ?? { method: "", url: "", content: null, dpop: null, clientCertificate: null };
  const presented = [...bound].sort((a, b) => ["agent", "user", "sponsor"].indexOf(a.role) - ["agent", "user", "sponsor"].indexOf(b.role))[0];
  const problem = cnfProblem(cnf);
  if (problem) refuse(problem);
  let reason: string;
  if ("jkt" in cnf) {
    reason = facts.dpop === null ? "dpop_proof_missing"
      : checkDpop(facts.dpop, facts.method, facts.url, at, cnf.jkt, presented.raw, facts.content ?? Buffer.alloc(0));
    if (reason === "ok") return "dpop";
  } else {
    reason = checkClientCertificate(facts.clientCertificate, cnf["x5t#S256"], at);
    if (reason === "ok") return "mtls";
  }
  return refuse(reason);
}

// --- the stamp: probity_records.stamp -------------------------------------------------------------------------------

export interface VerifiedStamp { identity: CanonicalIdentity; nonce: string; expires: number }

class StampRefused extends VerifiedIdentitiesRefused {}
const stampRefuse = (code: string, detail = ""): never => { throw new StampRefused(code, detail); };
const isString = (v: unknown): v is string => typeof v === "string";
const isInteger = (v: unknown): v is number => typeof v === "number";
const DEFAULT_PORTS: Record<string, string> = { "http:": "80", "https:": "443" };

function dictionary(value: string): Map<string, Member> {
  try { return parseDictionary(value); } catch (e) { if (e instanceof SFError) return stampRefuse("stamp_malformed"); throw e; }
}

/** stamp.stamp_fields: the stamp fields of a request's header lines, null when it carries no stamp at all. */
export function stampFields(headers: [string, string][]): Map<string, string> | null {
  const found = new Map<string, string[]>();
  for (const [name, value] of headers) {
    const lower = name.toLowerCase();
    if (STAMP_HEADERS.includes(lower)) found.set(lower, [...(found.get(lower) ?? []), value]);
  }
  if ([...found.values()].some((v) => v.length > 1)) stampRefuse("stamp_repeated");
  const fields = new Map([...found].map(([n, v]) => [n, v[0]]));
  const labelled = ["signature-input", "signature"].filter((n) => fields.has(n) && dictionary(fields.get(n) as string).has("probity"));
  if (!fields.has(PRINCIPALS_HEADER) && labelled.length === 0) return null;
  if (STAMP_HEADERS.some((n) => !fields.has(n) || ((n === "signature-input" || n === "signature") && !labelled.includes(n)))) stampRefuse("stamp_malformed");
  return fields;
}

function stampParams(member: Member | undefined): { created: number; expires: number; nonce: string; keyid: string; inner: InnerList } {
  if (member === undefined || member.kind !== "inner") return stampRefuse("stamp_header_invalid");
  const covered = member.items.map((i) => i.value);
  if (covered.length !== COVERED.length || covered.some((c, k) => c !== COVERED[k]) || member.items.some((i) => i.params.size > 0)) stampRefuse("stamp_header_invalid");
  const p = member.params;
  if ([...p.keys()].sort().join("\0") !== STAMP_PARAMS.join("\0")) stampRefuse("stamp_header_invalid");
  if (p.get("alg") !== "ed25519" || p.get("tag") !== "probity-principals/v1") stampRefuse("stamp_header_invalid");
  const created = p.get("created"), expires = p.get("expires"), nonce = p.get("nonce"), keyid = p.get("keyid");
  if (!isInteger(created) || !isInteger(expires)) return stampRefuse("stamp_header_invalid");
  if (!isString(nonce) || nonce === "" || !isString(keyid) || keyid === "") return stampRefuse("stamp_header_invalid");
  if (Buffer.byteLength(nonce, "ascii") > MAX_NONCE_BYTES) stampRefuse("stamp_header_invalid");
  return { created, expires, nonce, keyid, inner: member };
}

/** stamp.authority: the host in lower case, the port only when it is not the scheme's default. */
function authority(target: string): string {
  const u = new URL(target);
  if (!(u.protocol in DEFAULT_PORTS) || u.username !== "" || u.password !== "" || u.hash !== "") throw new TypeError("a stamped target is an absolute http(s) URI");
  return u.port === "" || u.port === DEFAULT_PORTS[u.protocol] ? u.hostname.toLowerCase() : `${u.hostname.toLowerCase()}:${u.port}`;
}

function signatureBase(method: string, target: string, digestValue: string, principalsValue: string, inner: InnerList): Buffer {
  const base = [`"@method": ${method}`, `"@target-uri": ${target}`, `"@authority": ${authority(target)}`,
    `"content-digest": ${digestValue.trim()}`, `"${PRINCIPALS_HEADER}": ${principalsValue.trim()}`,
    `"@signature-params": ${serializeInnerList(inner)}`].join("\n");
  if (!/^[\x00-\x7f]*$/.test(base) || base.includes("\r") || base.includes("\0")) stampRefuse("stamp_malformed");
  return Buffer.from(base, "ascii");
}

const stringItem = (m: Member | undefined): string | null => (m !== undefined && m.kind === "item" && m.params.size === 0 && isString(m.value) ? m.value : null);

/** Stamp.from_field and Stamp.of: the identity a `Probity-Principals` value states. */
function principalsIdentity(value: string): CanonicalIdentity {
  const members = dictionary(value);
  if ([...members.keys()].join("\0") !== "id\0client\0principals") stampRefuse("stamp_malformed");
  const [ident, client, principals] = ["id", "client", "principals"].map((n) => stringItem(members.get(n)));
  if (ident === null || client === null || principals === null) return stampRefuse("stamp_malformed");
  if (client === "" || !DIGEST.test(principals)) stampRefuse("stamp_malformed");
  let found: CanonicalIdentity;
  try { found = CanonicalIdentity.parse(ident); } catch { return stampRefuse("stamp_identity_mismatch"); }
  const agent = found.chain[found.chain.length - 1];
  if (found.kind !== "agent" || agent === undefined) return stampRefuse("stamp_downgraded");
  if (!found.user) return stampRefuse("stamp_no_user");
  if (agent.domain === found.user.domain && agent.subject === found.user.subject) stampRefuse("stamp_downgraded");
  return found;
}

function presentedKeyId(fields: Map<string, string>): string {
  return stampParams(dictionary(fields.get("signature-input") as string).get("probity")).keyid;
}

/** stamp.verify_stamp: every stateless check of the stamp a request's header lines carry, under the pinned key. */
export function verifyStamp(headers: [string, string][], method: string, target: string, body: Buffer | null, publicRaw: Buffer, nowNs: bigint): VerifiedStamp {
  const fields = stampFields(headers);
  if (fields === null) return stampRefuse("stamp_dropped");
  const inputs = dictionary(fields.get("signature-input") as string), signatures = dictionary(fields.get("signature") as string);
  const digests = dictionary(fields.get("content-digest") as string);
  const { created, expires, nonce, keyid, inner } = stampParams(inputs.get("probity"));
  if (keyid !== stampKeyId(publicRaw)) stampRefuse("stamp_key_mismatch");
  const signature = signatures.get("probity") as Item | InnerList;
  if (signature.kind !== "item" || signature.params.size > 0 || !Buffer.isBuffer(signature.value)) return stampRefuse("stamp_malformed");
  const sha = digests.get("sha-256");
  if (digests.size !== 1 || sha === undefined || sha.kind !== "item" || sha.params.size > 0 || !Buffer.isBuffer(sha.value)) return stampRefuse("stamp_malformed");
  if (!sha.value.equals(createHash("sha256").update(body ?? Buffer.alloc(0)).digest())) stampRefuse("stamp_request_mismatch");
  const base = signatureBase(method, target, fields.get("content-digest") as string, fields.get(PRINCIPALS_HEADER) as string, inner);
  let ok = false;
  try { ok = cryptoVerify(null, base, publicKey({ kty: "OKP", crv: "Ed25519", x: b64u(publicRaw) }), signature.value); } catch { ok = false; }
  if (!ok) stampRefuse("stamp_forged");
  const moment = Number(nowNs) / 1e9;
  if (expires <= created) stampRefuse("stamp_malformed");
  if (expires - created > MAX_TTL_SECONDS) stampRefuse("stamp_lifetime_too_long");
  if (created > moment) stampRefuse("stamp_not_yet_valid");
  if (moment >= expires) stampRefuse("stamp_expired");
  return { identity: principalsIdentity(fields.get(PRINCIPALS_HEADER) as string), nonce, expires };
}

function verifyStampOf(fields: Map<string, string>, bundle: TrustBundle, request: RequestFacts, at: string): VerifiedStamp {
  const key = stampKey(bundle, presentedKeyId(fields));
  return verifyStamp(request.headers, request.method, request.url, request.content, rawOf(key.jwk), BigInt(ts(at)) * 1000n);
}

// --- the request --------------------------------------------------------------------------------------------------

export interface VerifiedRequest { identities: CanonicalIdentity[]; proof: string | null; stamp: { nonce: string; expires: number } | null }

function checkEnvironment(identity: CanonicalIdentity, bundle: TrustBundle): void {
  const refs = [identity.user, ...identity.chain, identity.sponsor, identity.approver, identity.service];
  if (refs.some((r) => r !== undefined && r.environment !== bundle.environment)) refuse("identity_environment_mismatch");
}

/** verified_identities.verify_request: the identities of one request and what it presented to spend once. */
export function verifyRequest(tokens: Record<string, J>, bundleDoc: J, at: string, transport: CanonicalIdentity | null, request: RequestFacts | null): VerifiedRequest {
  const bundle = parseBundle(bundleDoc);
  if (transport !== null && (!(transport instanceof CanonicalIdentity) || transport.kind !== "transport")) throw new TypeError("transport is a CanonicalIdentity of kind transport");
  if (!isObj(tokens)) throw new TypeError("tokens maps a role to a compact JWS");
  if (Object.keys(tokens).some((r) => !(TOKEN_ROLES as readonly string[]).includes(r))) refuse("principal_role_not_configured");
  const fields = request === null ? null : stampFields(request.headers);
  if (Object.keys(tokens).length === 0 && fields === null) refuse("principal_credential_missing");
  const when = ts(at) / 1e6;
  let identity: CanonicalIdentity, proof: string | null = null, stamp: { nonce: string; expires: number } | null = null;
  if (fields !== null && request !== null) {
    if (Object.keys(tokens).length !== 0) refuse("identity_sources_mixed");
    const found = verifyStampOf(fields, bundle, request, at);
    identity = found.identity; stamp = { nonce: found.nonce, expires: found.expires };
  } else {
    const found: Record<string, Token> = {};
    for (const role of TOKEN_ROLES) if (role in tokens) found[role] = verifyToken(role, tokens[role], bundle, when);
    try { identity = identityFromTokens(found, bundle); } catch (e) {
      if (e instanceof IdentityStringError) return refuse(e.code); throw e;
    }
    proof = possession(TOKEN_ROLES.filter((r) => r in found).map((r) => found[r]), request, at);
  }
  checkEnvironment(identity, bundle);
  try { identity.check(bundle.profile); } catch (e) { if (e instanceof IdentityStringError) refuse(e.code); throw e; }
  const identities = [identity];
  if (transport !== null) { checkEnvironment(transport, bundle); identities.push(transport); }
  return { identities, proof, stamp };
}

/** verified_identities.verified_identities. */
export function verifiedIdentities(tokens: Record<string, J>, bundle: J, at: string, transport: CanonicalIdentity | null = null, request: RequestFacts | null = null): CanonicalIdentity[] {
  return verifyRequest(tokens, bundle, at, transport, request).identities;
}

/** One shared vector, judged: the identities and spend values, or the refusal code. */
export function judgeVerified(v: J): J {
  const r = v.request;
  const facts: RequestFacts | null = r === null ? null : {
    method: r.method, url: r.url, content: r.contentB64 === null ? null : Buffer.from(r.contentB64, "base64"),
    dpop: r.dpop, clientCertificate: r.clientCertificateB64 === null ? null : Buffer.from(r.clientCertificateB64, "base64"),
    headers: r.headers,
  };
  const transport = v.transport === null ? null : CanonicalIdentity.parse(v.transport);
  try {
    const found = verifyRequest(v.tokens, v.bundle, v.at, transport, facts);
    return { identities: found.identities.map((i) => i.document()), proof: found.proof, stamp: found.stamp };
  } catch (e) {
    if (e instanceof VerifiedIdentitiesRefused) return { refused: e.code };
    throw e;
  }
}

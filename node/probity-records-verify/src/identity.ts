// The canonical identity string, version 1 (packages/probity-records/docs/canonical-identity.md), in TypeScript.
//
// It parses and renders exactly what the Python reader (probity_records.canonical_identity) parses and renders, and
// refuses with the same code at the same check; test/shared.test.ts holds the two to
// packages/probity-records/vectors/shared/canonical_identity.json.

type J = any; // eslint-disable-line @typescript-eslint/no-explicit-any

export const VERSION = 1;
export const MARKER = "aid1!";
export const KINDS = ["human-attested", "agent", "unknown", "transport"] as const;
export const TYPES = ["user", "agent", "service", "sponsor", "approver"] as const;
export const KEYS = ["user", "chain", "sponsor", "approver", "service", "evidence", "act", "grants"] as const;
export const EVIDENCE_METHODS = ["presence", "approval"] as const;
export const PROFILES = ["basic", "strict"] as const;
const KEY_TYPES: Record<string, string> = { user: "user", chain: "agent", sponsor: "sponsor", approver: "approver",
  service: "service" };
const REQUIRED: Record<string, string[]> = { "human-attested": ["user", "evidence"], agent: ["chain"],
  unknown: ["user"], transport: ["service"] };
const ALLOWED: Record<string, string[]> = {
  "human-attested": ["user", "approver", "evidence", "grants"],
  agent: ["user", "chain", "sponsor", "approver", "act", "grants"],
  unknown: ["user"],
  transport: ["service"],
};
export const MAX_OCTETS = 8192;
export const MAX_CHAIN = 32;
const UNRESERVED = /^[A-Za-z0-9\-._~]$/;
const COMPONENT = /^(?:[A-Za-z0-9\-._~]|%[0-9A-F]{2})+$/;
const ENV = /^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;

/** A string that is not a canonical identity, or parts that have none; `code` is the stable reason. */
export class IdentityStringError extends Error {
  readonly code: string;
  constructor(code: string, detail = "") {
    super(detail ? `${code}: ${detail}` : code);
    this.code = code;
  }
}

const has = (list: readonly string[], value: unknown): boolean => typeof value === "string" && list.includes(value);

function encode(value: string): string {
  if (!value.isWellFormed()) throw new IdentityStringError("identity_value_not_utf8");
  let out = "";
  for (const byte of new TextEncoder().encode(value)) {
    const ch = String.fromCharCode(byte);
    out += byte < 0x80 && UNRESERVED.test(ch) ? ch : `%${byte.toString(16).toUpperCase().padStart(2, "0")}`;
  }
  return out;
}

function decode(text: string): string {
  if (!COMPONENT.test(text)) throw new IdentityStringError("identity_component_not_canonical", text.slice(0, 64));
  const octets: number[] = [];
  for (let i = 0; i < text.length;) {
    if (text[i] === "%") { octets.push(parseInt(text.slice(i + 1, i + 3), 16)); i += 3; } else { octets.push(text.charCodeAt(i)); i += 1; }
  }
  let value: string;
  try { value = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(new Uint8Array(octets)); }
  catch { throw new IdentityStringError("identity_value_not_utf8"); }
  if (encode(value) !== text) throw new IdentityStringError("identity_component_not_canonical", text.slice(0, 64));
  return value;
}

function digest(value: unknown): string {
  if (typeof value !== "string" || !DIGEST.test(value)) throw new IdentityStringError("identity_digest_malformed");
  return value;
}

const isAscii = (text: string): boolean => /^[\x00-\x7f]*$/.test(text);

/** One principal: its type, the environment and pinned trust root it was verified in, and its subject there. */
export class Ref {
  readonly type: string; readonly environment: string; readonly domain: string; readonly subject: string;
  constructor(type: unknown, environment: unknown, domain: unknown, subject: unknown) {
    if (!has(TYPES, type)) throw new IdentityStringError("identity_ref_type_unknown");
    if (typeof environment !== "string" || !ENV.test(environment)) throw new IdentityStringError("identity_environment_malformed");
    for (const value of [domain, subject]) {
      if (typeof value !== "string" || !value) throw new IdentityStringError("identity_ref_malformed");
      encode(value);
    }
    this.type = type as string; this.environment = environment; this.domain = domain as string; this.subject = subject as string;
  }
  render(): string { return `${this.type}:${this.environment}/${encode(this.domain)}/${encode(this.subject)}`; }
  equals(other: Ref): boolean { return this.render() === other.render(); }
  static parse(text: string): Ref {
    if (typeof text !== "string" || !isAscii(text)) throw new IdentityStringError("identity_ref_malformed");
    const colon = text.indexOf(":");
    const parts = colon < 0 ? [] : text.slice(colon + 1).split("/");
    if (colon < 0 || parts.length !== 3) throw new IdentityStringError("identity_ref_malformed", text.slice(0, 64));
    const kind = text.slice(0, colon);
    if (!has(TYPES, kind)) throw new IdentityStringError("identity_ref_type_unknown");
    const domain = decode(parts[1]);
    const subject = decode(parts[2]);
    return new Ref(kind, parts[0], domain, subject);
  }
  document(): J {
    return { id: this.render(), type: this.type, environment: this.environment, domain: this.domain, subject: this.subject };
  }
  static fromDocument(doc: J): Ref {
    const members = ["domain", "environment", "id", "subject", "type"];
    if (!isObject(doc) || Object.keys(doc).sort().join() !== members.join()) {
      throw new IdentityStringError("identity_document_malformed");
    }
    const ref = new Ref(doc.type, doc.environment, doc.domain, doc.subject);
    if (doc.id !== ref.render()) throw new IdentityStringError("identity_document_id_mismatch");
    return ref;
  }
}

const isObject = (v: unknown): v is Record<string, J> => typeof v === "object" && v !== null && !Array.isArray(v);

/** What established that a human acted: a fresh user-presence proof, or an approval bound to the request. */
export class Evidence {
  readonly method: string; readonly digest: string;
  constructor(method: unknown, value: unknown) {
    if (!has(EVIDENCE_METHODS, method)) throw new IdentityStringError("identity_evidence_malformed");
    this.method = method as string; this.digest = digest(value);
  }
  render(): string { return `${this.method}:${this.digest}`; }
  static parse(text: string): Evidence {
    const colon = text.indexOf(":");
    if (colon < 0) throw new IdentityStringError("identity_evidence_malformed");
    return new Evidence(text.slice(0, colon), text.slice(colon + 1));
  }
}

export interface IdentityParts {
  kind: string; user?: Ref; chain?: Ref[]; sponsors?: Ref[]; approver?: Ref; service?: Ref; evidence?: Evidence;
  act?: string; grants?: string;
}

/** The verified identity of one request (or of its transport): kind and typed, scoped principals. `sponsors` lists
 * every sponsor that answers for the agent, sorted by its rendered ref with none twice, empty when none does; a reader
 * checks every entry, so a rule that denies one sponsor fires whichever others are named. */
export class CanonicalIdentity {
  readonly kind: string; readonly user?: Ref; readonly chain: Ref[]; readonly sponsors: Ref[]; readonly approver?: Ref;
  readonly service?: Ref; readonly evidence?: Evidence; readonly act?: string; readonly grants?: string;

  constructor(parts: IdentityParts) {
    if (!has(KINDS, parts.kind)) throw new IdentityStringError("identity_kind_unknown");
    this.kind = parts.kind; this.user = parts.user; this.chain = parts.chain ?? [];
    if (parts.sponsors !== undefined && !Array.isArray(parts.sponsors)) throw new IdentityStringError("identity_sponsor_malformed");
    this.sponsors = parts.sponsors ?? [];
    this.approver = parts.approver; this.service = parts.service; this.evidence = parts.evidence; this.act = parts.act;
    this.grants = parts.grants;
    const present = KEYS.filter((k) => this.present(k));
    for (const key of present) {
      if (!ALLOWED[this.kind].includes(key)) throw new IdentityStringError("identity_attribute_not_allowed", key);
    }
    for (const key of REQUIRED[this.kind]) {
      if (!present.includes(key as typeof KEYS[number])) throw new IdentityStringError("identity_attribute_missing", key);
    }
    for (const [key, want] of Object.entries(KEY_TYPES)) {
      const value = this.value(key);
      const refs: J[] = key === "chain" || key === "sponsor" ? value : value === undefined ? [] : [value];
      for (const ref of refs) {
        if (!(ref instanceof Ref) || ref.type !== want) throw new IdentityStringError("identity_ref_type_mismatch", key);
      }
    }
    if (this.chain.length > MAX_CHAIN) throw new IdentityStringError("identity_chain_too_deep");
    if (new Set(this.chain.map((r) => r.render())).size !== this.chain.length) {
      throw new IdentityStringError("identity_chain_repeats_agent");
    }
    const sponsors = this.sponsors.map((r) => r.render());
    if (new Set(sponsors).size !== sponsors.length) throw new IdentityStringError("identity_sponsor_repeated");
    if (sponsors.some((r, i) => i > 0 && sponsors[i - 1] > r)) throw new IdentityStringError("identity_sponsor_order");
    if (this.evidence?.method === "approval" && this.approver === undefined) {
      throw new IdentityStringError("identity_attribute_missing", "approver");
    }
    if (this.kind === "agent" && this.user === undefined && this.sponsors.length === 0) {
      throw new IdentityStringError("identity_attribute_missing", "sponsor");
    }
    if (this.act !== undefined && this.user === undefined) throw new IdentityStringError("identity_attribute_missing", "user");
    if (this.act !== undefined) digest(this.act);
    if (this.grants !== undefined) digest(this.grants);
    if (this.render().length > MAX_OCTETS) throw new IdentityStringError("identity_too_long");
  }

  /** The attribute a key is held in: the `sponsor` key carries every sponsor. */
  private value(key: string): J {
    return key === "sponsor" ? this.sponsors : (this as J)[key];
  }

  private present(key: string): boolean {
    const value = this.value(key);
    return Array.isArray(value) ? value.length > 0 : value !== undefined;
  }

  private rendered(key: string): string {
    if (key === "chain") return this.chain.map((r) => r.render()).join(">");
    if (key === "sponsor") return this.sponsors.map((r) => r.render()).join("+");
    const value = this.value(key);
    return typeof value === "string" ? value : value.render();
  }

  /** The canonical string: byte-equal for two identities exactly when they are the same identity. */
  render(): string {
    return MARKER + this.kind + KEYS.filter((k) => this.present(k)).map((k) => `;${k}=${this.rendered(k)}`).join("");
  }

  get agent(): Ref | undefined { return this.chain.at(-1); }

  plainUser(): string {
    if (this.kind !== "human-attested" || this.user === undefined) throw new IdentityStringError("identity_not_human_attested");
    return this.user.render();
  }

  aclKey(): string { return this.kind === "human-attested" ? this.plainUser() : this.render(); }

  check(profile: string): void {
    if (!has(PROFILES, profile)) throw new IdentityStringError("identity_profile_unknown");
    if (profile === "strict" && this.kind === "unknown") throw new IdentityStringError("identity_actor_unknown");
  }

  static parse(text: unknown): CanonicalIdentity {
    if (typeof text !== "string") throw new IdentityStringError("identity_string_malformed");
    if (text.length > MAX_OCTETS || !isAscii(text)) {
      throw new IdentityStringError(isAscii(text) ? "identity_too_long" : "identity_string_malformed");
    }
    const bang = text.indexOf("!");
    const head = bang < 0 ? text : text.slice(0, bang);
    if (bang < 0 || !head.startsWith("aid")) throw new IdentityStringError("identity_string_malformed");
    if (head + "!" !== MARKER) throw new IdentityStringError("identity_version_unknown");
    const [kind, ...pairs] = text.slice(MARKER.length).split(";");
    if (!has(KINDS, kind)) throw new IdentityStringError("identity_kind_unknown");
    const parts: J = { kind };
    let position = -1;
    for (const pair of pairs) {
      const equals = pair.indexOf("=");
      const key = equals < 0 ? pair : pair.slice(0, equals);
      const value = equals < 0 ? "" : pair.slice(equals + 1);
      if (equals < 0 || !has(KEYS, key)) throw new IdentityStringError("identity_attribute_unknown", key.slice(0, 32));
      const index = (KEYS as readonly string[]).indexOf(key);
      if (index <= position) throw new IdentityStringError("identity_attribute_order", key);
      position = index;
      if (!value) throw new IdentityStringError("identity_attribute_empty", key);
      if (key === "chain") parts.chain = value.split(">").map((p) => Ref.parse(p));
      else if (key === "sponsor") parts.sponsors = value.split("+").map((p) => Ref.parse(p));
      else if (key === "evidence") parts.evidence = Evidence.parse(value);
      else if (key === "act" || key === "grants") parts[key] = digest(value);
      else parts[key] = Ref.parse(value);
    }
    const identity = new CanonicalIdentity(parts);
    if (identity.render() !== text) throw new IdentityStringError("identity_string_not_canonical");
    return identity;
  }

  /** The structured form: `id` is the canonical string; an absent member is omitted, never null. */
  document(): J {
    const doc: J = { id: this.render(), version: VERSION, kind: this.kind };
    for (const key of KEYS) {
      if (!this.present(key)) continue;
      const value = this.value(key);
      if (key === "chain" || key === "sponsor") doc[key] = value.map((r: Ref) => r.document());
      else if (key === "evidence") doc.evidence = { method: value.method, digest: value.digest };
      else doc[key] = value instanceof Ref ? value.document() : value;
    }
    return doc;
  }

  static fromDocument(doc: J): CanonicalIdentity {
    if (!isObject(doc) || !["id", "version", "kind"].every((k) => k in doc)) {
      throw new IdentityStringError("identity_document_malformed");
    }
    const unknown = Object.keys(doc).filter((k) => !["id", "version", "kind", ...KEYS].includes(k)).sort();
    if (unknown.length) throw new IdentityStringError("identity_attribute_unknown", unknown[0].slice(0, 32));
    if (doc.version !== VERSION) throw new IdentityStringError("identity_version_unknown");
    const parts: J = { kind: doc.kind };
    for (const key of KEYS) {
      if (!(key in doc)) continue;
      const value = doc[key];
      if (key === "chain") {
        if (!Array.isArray(value) || value.length === 0) throw new IdentityStringError("identity_chain_malformed");
        parts.chain = value.map((item) => Ref.fromDocument(item));
      } else if (key === "sponsor") {
        if (!Array.isArray(value) || value.length === 0) throw new IdentityStringError("identity_sponsor_malformed");
        parts.sponsors = value.map((item) => Ref.fromDocument(item));
      } else if (key === "evidence") {
        if (!isObject(value) || Object.keys(value).sort().join() !== "digest,method") {
          throw new IdentityStringError("identity_evidence_malformed");
        }
        parts.evidence = new Evidence(value.method, value.digest);
      } else if (key === "act" || key === "grants") parts[key] = digest(value);
      else parts[key] = Ref.fromDocument(value);
    }
    const identity = new CanonicalIdentity(parts);
    if (doc.id !== identity.render()) throw new IdentityStringError("identity_document_id_mismatch");
    return identity;
  }
}

/** What a reader reports for one shared vector input: the outcome, or the refusal code. */
export function judgeIdentity(direction: string, input: J): J {
  try {
    const identity = direction === "string" ? CanonicalIdentity.parse(input) : CanonicalIdentity.fromDocument(input);
    let strict: string | null = null;
    try { identity.check("strict"); } catch (e) { strict = (e as IdentityStringError).code; }
    return { document: identity.document(), aclKey: identity.aclKey(),
      plainUser: identity.kind === "human-attested" ? identity.plainUser() : null, strict };
  } catch (e) {
    if (e instanceof IdentityStringError) return { refused: e.code };
    throw e;
  }
}

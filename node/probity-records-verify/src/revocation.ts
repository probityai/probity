// Reader of the one signed revocation list, the TypeScript twin of probity_records.revocation.
//
// The format, the order of checks and the ten refusal codes are the Python reader's; the shared vectors
// (packages/probity-records/vectors/shared/revocation.json) hold the two to the same verdict. A refused list
// throws an Error whose message is the code, `<code>` or `<code>:<detail>`, and leaves the state unchanged.
// Each list is a delta: its entries are only the subjects it newly revokes, the state is the union of the chain's
// lists, and a list naming a subject an earlier list revoked is refused (revocation_entry_repeated). Applying a list
// costs what the delta holds, not what the chain has revoked: a state's entries are a read-only view of a store shared
// along one chain, and only the state at the store's tip extends it.
// An identity provider's token-signing key is kind "idp-key", named by its RFC 7638 thumbprint, never kind "key".

import { identifier, sameIdentifier } from "./identifiers.ts";
import { canonicalBytes, edOk, rawKey, sha256Hex, ts } from "./verify.ts";

type J = any; // eslint-disable-line @typescript-eslint/no-explicit-any

const REVOCATION_DOMAIN = Buffer.from("probity-revocation-v1\u0000", "latin1");
export const REVOCATION_LIST = identifier("agent-evidence-vectors/predicate/v2/revocation-list");
/** Every subject kind a list names. A digest kind's id is 64 lowercase hex, an idp-key id an RFC 7638 thumbprint, the rest identifiers. */
export const REVOCATION_KINDS = ["agent", "build", "grant", "idp-key", "key", "permit", "sponsor", "stream"] as const;
/** Every refusal applyRevocationList reports, in the order it checks them. */
export const REFUSAL_CODES = [
  "revocation_list_shape",
  "revocation_list_signer_not_a_root",
  "revocation_list_signature_unverified",
  "revocation_list_other_chain",
  "revocation_list_rollback",
  "revocation_list_gap",
  "revocation_list_previous_mismatch",
  "revocation_list_time_reversed",
  "revocation_entry_from_future",
  "revocation_entry_repeated",
] as const;

const BODY_MEMBERS = ["entries", "issuedAt", "issuerKey", "listId", "previous", "seq", "type"];
const ENTRY_REQUIRED = ["kind", "id", "revokedAt"];
const ENTRY_OPTIONAL = ["reason", "successor"];
const IDENTIFIER = /^[\x21-\x7e]{1,512}$/;
const HEX64 = /^[0-9a-f]{64}$/;
// A SHA-256 thumbprint in base64url without padding: 43 digits, the last carrying two zero bits (one spelling per key).
const THUMBPRINT = /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/;
const ID_FORMS: ReadonlyMap<string, RegExp> = new Map([["grant", HEX64], ["key", HEX64], ["permit", HEX64], ["idp-key", THUMBPRINT]]);
const LIST_DIGEST = /^sha256:[0-9a-f]{64}$/;
const TIME = /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z$/;

const isObj = (v: J): boolean => v !== null && typeof v === "object" && !Array.isArray(v);
const shape = (why: string): Error => new Error(`revocation_list_shape:${why}`);
const sameMembers = (v: J, names: string[]): boolean => {
  const keys = Object.keys(v).sort();
  return keys.length === names.length && keys.every((k, i) => k === names[i]);
};

/** The verifier's side: pinned roots and the list in force (none: seq 0, nothing revoked). Never mutated. */
export interface RevocationState {
  readonly roots: ReadonlySet<string>;
  readonly listId: string | null;
  readonly seq: number;
  readonly head: string | null;
  readonly issuedAt: string | null;
  /** Every entry the chain published up to seq, keyed `kind` NUL `id`. */
  readonly entries: ReadonlyMap<string, J>;
}

/** The entries of one chain, each key with the seq of the list that added it, in the order they were added. */
interface ChainStore {
  added: Map<string, { seq: number; entry: J }>;
  order: string[];
  tip: number;
}

/** A read-only view of a chain store as of one seq: the keys some list at or before seq added. */
class EntriesView {
  store: ChainStore;
  seq: number;
  size: number;

  constructor(store: ChainStore, seq: number, size: number) {
    this.store = store;
    this.seq = seq;
    this.size = size;
  }

  /** A view of a store of its own holding `entries` as of `seq` (a copy). */
  static of(entries: ReadonlyMap<string, J>, seq: number): EntriesView {
    const store: ChainStore = { added: new Map(), order: [], tip: seq };
    for (const [key, entry] of entries) {
      store.added.set(key, { seq, entry });
      store.order.push(key);
    }
    return new EntriesView(store, seq, store.order.length);
  }

  get(key: string): J {
    const held = this.store.added.get(key);
    return held !== undefined && held.seq <= this.seq ? held.entry : undefined;
  }

  has(key: string): boolean {
    const held = this.store.added.get(key);
    return held !== undefined && held.seq <= this.seq;
  }

  keys(): IterableIterator<string> {
    return this.store.order.slice(0, this.size)[Symbol.iterator]();
  }

  values(): IterableIterator<J> {
    return this.store.order.slice(0, this.size).map((key) => this.store.added.get(key)!.entry)[Symbol.iterator]();
  }

  entries(): IterableIterator<[string, J]> {
    return this.store.order.slice(0, this.size).map((key): [string, J] => [key, this.store.added.get(key)!.entry])[Symbol.iterator]();
  }

  [Symbol.iterator](): IterableIterator<[string, J]> {
    return this.entries();
  }

  forEach(fn: (value: J, key: string, map: ReadonlyMap<string, J>) => void, thisArg?: unknown): void {
    for (const [key, value] of this.entries()) fn.call(thisArg, value, key, this as unknown as ReadonlyMap<string, J>);
  }

  /** The view as of `seq` holding this view's keys and `delta`'s: in place at the store's tip, else on a copy. */
  extended(seq: number, delta: Map<string, J>): EntriesView {
    if (this.store.tip === this.seq) {
      for (const [key, entry] of delta) {
        this.store.added.set(key, { seq, entry });
        this.store.order.push(key);
      }
      this.store.tip = seq;
      return new EntriesView(this.store, seq, this.store.order.length);
    }
    const branch = EntriesView.of(this as unknown as ReadonlyMap<string, J>, this.seq);
    return branch.extended(seq, delta);
  }
}

const asMap = (view: EntriesView): ReadonlyMap<string, J> => view as unknown as ReadonlyMap<string, J>;

/** The state's entries as a view this reader can extend (a plain map is copied once). */
const viewOf = (state: RevocationState): EntriesView =>
  state.entries instanceof EntriesView && state.entries.seq === state.seq ? state.entries : EntriesView.of(state.entries, state.seq);

export function newRevocationState(rootKeyIds: Iterable<string>): RevocationState {
  return { roots: new Set(rootKeyIds), listId: null, seq: 0, head: null, issuedAt: null, entries: asMap(EntriesView.of(new Map(), 0)) };
}

/** The digest a list's successor names as `previous` and a permit names as the list it was minted under. */
export function listDigest(body: J): string {
  return "sha256:" + sha256Hex(canonicalBytes(body));
}

function checkTime(value: J, what: string): string {
  const m = typeof value === "string" ? TIME.exec(value) : null;
  if (!m) throw shape(`${what}_not_a_utc_second`);
  const [year, month, day, hour, minute, second] = m.slice(1).map(Number);
  const at = new Date(0);
  at.setUTCFullYear(year, month - 1, day);
  at.setUTCHours(hour, minute, second, 0);
  const real = year >= 1 && at.getUTCFullYear() === year && at.getUTCMonth() === month - 1 && at.getUTCDate() === day
    && at.getUTCHours() === hour && at.getUTCMinutes() === minute && at.getUTCSeconds() === second;
  if (!real) throw shape(`${what}_not_a_calendar_instant`);
  return value;
}

/** The 32 raw bytes of a padded canonical base64 Ed25519 key, or a shape refusal. */
function rawKeyBytes(value: J, what: string): Buffer {
  if (typeof value !== "string") throw shape(`${what}_not_base64`);
  const raw = Buffer.from(value, "base64");
  if (raw.length !== 32) throw shape(`${what}_not_an_ed25519_key`);
  if (raw.toString("base64") !== value) throw shape(`${what}_not_canonical_base64`);
  return raw;
}

function checkEntry(entry: J): [string, string] {
  if (!isObj(entry)) throw shape("entry_not_an_object");
  const members = Object.keys(entry);
  if (!ENTRY_REQUIRED.every((k) => members.includes(k)) || !members.every((k) => ENTRY_REQUIRED.includes(k) || ENTRY_OPTIONAL.includes(k))) {
    throw shape("entry_members");
  }
  const { kind, id } = entry;
  if (!(REVOCATION_KINDS as readonly string[]).includes(kind)) throw shape("entry_kind_unknown");
  const pattern = ID_FORMS.get(kind) ?? IDENTIFIER;
  if (typeof id !== "string" || !pattern.test(id)) throw shape(`entry_id_form:${kind}`);
  checkTime(entry.revokedAt, "revokedAt");
  if ("reason" in entry && typeof entry.reason !== "string") throw shape("entry_reason_not_text");
  if ("successor" in entry) {
    if (kind !== "key") throw shape("successor_on_non_key_entry");
    rawKeyBytes(entry.successor, "successor");
  }
  return [kind, id];
}

/** Throw revocation_list_shape unless body is exactly the format (signature and order against a chain not checked). */
function checkBody(body: J): void {
  if (!isObj(body) || !sameMembers(body, BODY_MEMBERS)) throw shape("body_members");
  if (!sameIdentifier(body.type, REVOCATION_LIST)) throw shape("type");
  if (typeof body.listId !== "string" || !IDENTIFIER.test(body.listId)) throw shape("list_id_form");
  const { seq, previous } = body;
  if (typeof seq !== "number" || !Number.isSafeInteger(seq) || seq < 1) throw shape("seq_not_a_positive_exact_integer");
  if ((seq === 1) !== (previous === null) || (previous !== null && !(typeof previous === "string" && LIST_DIGEST.test(previous)))) {
    throw shape("previous_form");
  }
  checkTime(body.issuedAt, "issuedAt");
  rawKeyBytes(body.issuerKey, "issuerKey");
  if (!Array.isArray(body.entries)) throw shape("entries_not_a_list");
  const order = body.entries.map(checkEntry);
  for (let i = 1; i < order.length; i++) {
    const [ak, ai] = order[i - 1];
    const [bk, bi] = order[i];
    if (ak > bk || (ak === bk && ai >= bi)) throw shape("entries_not_strictly_ascending");
  }
}

function signatureHolds(issuerKey: Buffer, sig: J, body: J): boolean {
  try {
    if (typeof sig !== "string") return false;
    const raw = Buffer.from(sig, "base64");
    if (raw.length !== 64 || raw.toString("base64") !== sig) return false;
    return edOk(rawKey(issuerKey), Buffer.concat([REVOCATION_DOMAIN, canonicalBytes(body)]), raw);
  } catch {
    return false;
  }
}

/** The state with `signed` as the list in force, or an Error whose message is the refusal code (state unchanged). */
export function applyRevocationList(state: RevocationState, signed: J): RevocationState {
  if (!isObj(signed) || !sameMembers(signed, ["body", "sig"])) throw shape("signed_list_members");
  const body = signed.body;
  checkBody(body);
  const issuerKey = rawKeyBytes(body.issuerKey, "issuerKey");
  if (!state.roots.has(sha256Hex(issuerKey))) throw new Error("revocation_list_signer_not_a_root");
  if (!signatureHolds(issuerKey, signed.sig, body)) throw new Error("revocation_list_signature_unverified");
  const seq: number = body.seq;
  if (state.listId !== null && body.listId !== state.listId) throw new Error("revocation_list_other_chain");
  if (seq <= state.seq) throw new Error(`revocation_list_rollback:${seq}<=${state.seq}`);
  if (seq > state.seq + 1) throw new Error(`revocation_list_gap:${seq}>${state.seq + 1}`);
  if (body.previous !== state.head) throw new Error("revocation_list_previous_mismatch");
  if (state.issuedAt !== null && body.issuedAt < state.issuedAt) throw new Error("revocation_list_time_reversed");
  const delta = new Map<string, J>(body.entries.map((e: J): [string, J] => [`${e.kind}\u0000${e.id}`, e]));
  for (const e of delta.values()) if (e.revokedAt > body.issuedAt) throw new Error("revocation_entry_from_future");
  const held = state.entries;
  for (const e of delta.values()) {
    if (held.has(`${e.kind}\u0000${e.id}`)) throw new Error(`revocation_entry_repeated:${e.kind}:${e.id.slice(0, 12)}`);
  }
  // A revoked key is never a root, whatever the order of the entries and whichever list revoked it: the successors of
  // the roots this list revokes join unless an earlier list revoked them, then every key id this list revokes leaves,
  // so a successor the same list revokes does not stay either.
  const roots = new Set(state.roots);
  for (const e of delta.values()) {
    if (e.kind !== "key" || !state.roots.has(e.id) || !("successor" in e)) continue;
    const successor = sha256Hex(Buffer.from(e.successor, "base64"));
    if (!held.has(`key\u0000${successor}`)) roots.add(successor);
  }
  for (const e of delta.values()) if (e.kind === "key") roots.delete(e.id);
  return { roots, listId: body.listId, seq, head: listDigest(body), issuedAt: body.issuedAt,
    entries: asMap(viewOf(state).extended(seq, delta)) };
}

/** Whether the list in force names `id` under `kind` (in force from install). */
export function revoked(state: RevocationState, kind: string, id: string): boolean {
  if (!(REVOCATION_KINDS as readonly string[]).includes(kind)) throw new Error(`unknown_revocation_kind:${kind}`);
  return state.entries.has(`${kind}\u0000${id}`);
}

/** Whether `id` was revoked at or before `at`: anything it signs or authorises from then on is refused. */
export function revokedAt(state: RevocationState, kind: string, id: string, at: string): boolean {
  if (!revoked(state, kind, id)) return false;
  return ts(state.entries.get(`${kind}\u0000${id}`).revokedAt) <= ts(at);
}

/** Whether the identity provider key with RFC 7638 `thumbprint` was revoked at or before `at`. */
export function idpKeyRevoked(state: RevocationState, thumbprint: string, at: string): boolean {
  return revokedAt(state, "idp-key", thumbprint, at);
}

/** The state as the shared vectors state it. */
export function revocationSummary(state: RevocationState): J {
  const revokedByKind: Record<string, string[]> = {};
  for (const kind of REVOCATION_KINDS) revokedByKind[kind] = [];
  for (const e of state.entries.values()) revokedByKind[e.kind].push(e.id);
  for (const kind of REVOCATION_KINDS) revokedByKind[kind].sort();
  return { head: state.head, issuedAt: state.issuedAt, listId: state.listId, revoked: revokedByKind,
    roots: [...state.roots].sort(), seq: state.seq };
}

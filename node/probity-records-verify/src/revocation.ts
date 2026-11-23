// Reader of the one signed revocation list, the TypeScript twin of probity_records.revocation.
//
// The format, the order of checks and the ten refusal codes are the Python reader's; the shared vectors
// (packages/probity-records/vectors/shared/revocation.json) hold the two to the same verdict. A refused list
// throws an Error whose message is the code, `<code>` or `<code>:<detail>`, and leaves the state unchanged.

import { canonicalBytes, edOk, rawKey, sha256Hex } from "./verify.ts";

type J = any; // eslint-disable-line @typescript-eslint/no-explicit-any

const REVOCATION_DOMAIN = Buffer.from("probity-revocation-v1\u0000", "latin1");
export const REVOCATION_LIST = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/revocation-list";
/** Every subject kind a list names. A digest kind's id is 64 lowercase hex; the rest are identifiers. */
export const REVOCATION_KINDS = ["agent", "build", "grant", "key", "permit", "sponsor", "stream"] as const;
const DIGEST_KINDS = new Set(["grant", "key", "permit"]);
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
  "revocation_list_drops_entry",
] as const;

const BODY_MEMBERS = ["entries", "issuedAt", "issuerKey", "listId", "previous", "seq", "type"];
const ENTRY_REQUIRED = ["kind", "id", "revokedAt"];
const ENTRY_OPTIONAL = ["reason", "successor"];
const IDENTIFIER = /^[\x21-\x7e]{1,512}$/;
const HEX64 = /^[0-9a-f]{64}$/;
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
  /** The list's entries, keyed `kind` NUL `id`. */
  readonly entries: ReadonlyMap<string, J>;
}

export function newRevocationState(rootKeyIds: Iterable<string>): RevocationState {
  return { roots: new Set(rootKeyIds), listId: null, seq: 0, head: null, issuedAt: null, entries: new Map() };
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
  const pattern = DIGEST_KINDS.has(kind) ? HEX64 : IDENTIFIER;
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
  if (body.type !== REVOCATION_LIST) throw shape("type");
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
  const entries = new Map<string, J>(body.entries.map((e: J): [string, J] => [`${e.kind}\u0000${e.id}`, e]));
  for (const e of entries.values()) if (e.revokedAt > body.issuedAt) throw new Error("revocation_entry_from_future");
  for (const [key, held] of state.entries) {
    const now = entries.get(key);
    if (now === undefined || !canonicalBytes(now).equals(canonicalBytes(held))) {
      const [kind, id] = key.split("\u0000");
      throw new Error(`revocation_list_drops_entry:${kind}:${id.slice(0, 12)}`);
    }
  }
  // A revoked key is never a root, whatever the order of the entries: the successors of the roots this list revokes
  // join, then every key id it revokes leaves, so a successor the same list revokes does not stay.
  const roots = new Set(state.roots);
  for (const e of entries.values()) {
    if (e.kind === "key" && state.roots.has(e.id) && "successor" in e) roots.add(sha256Hex(Buffer.from(e.successor, "base64")));
  }
  for (const e of entries.values()) if (e.kind === "key") roots.delete(e.id);
  return { roots, listId: body.listId, seq, head: listDigest(body), issuedAt: body.issuedAt, entries };
}

/** Whether the list in force names `id` under `kind` (in force from install). */
export function revoked(state: RevocationState, kind: string, id: string): boolean {
  if (!(REVOCATION_KINDS as readonly string[]).includes(kind)) throw new Error(`unknown_revocation_kind:${kind}`);
  return state.entries.has(`${kind}\u0000${id}`);
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

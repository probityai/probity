// Test support: rewrite a shared vector from the probityai.github.io spelling to another spelling of our identifiers
// and re-sign it with the deterministic test keys the vectors were made with (the Python generator derives each key
// from sha256("probity-shared-vectors/<name>")), so a verdict can be compared across spellings on signed records.
import { createHash, createPrivateKey, createPublicKey, sign as edSign, verify as edVerify, type KeyObject } from "node:crypto";
import { canonical, canonicalBytes, parseReceived } from "../src/verify.ts";
import { listDigest } from "../src/revocation.ts";

export const OLD = "https://probityai.github.io/";
export const NEW = "https://probityai.org/";
export const HTTP = "http://probityai.org/";
export const OTHER = "https://example.invalid/";

type J = any; // eslint-disable-line @typescript-eslint/no-explicit-any

const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const IN_TOTO = "application/vnd.in-toto+json";
const REVOCATION_DOMAIN = Buffer.from("probity-revocation-v1\u0000", "latin1");

export interface TestKey { name: string; priv: KeyObject; pub: KeyObject; raw: Buffer }

export function testKey(name: string): TestKey {
  const seed = createHash("sha256").update(`probity-shared-vectors/${name}`).digest();
  const priv = createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, seed]), format: "der", type: "pkcs8" });
  const pub = createPublicKey(priv);
  const raw = Buffer.from(pub.export({ format: "der", type: "spki" })).subarray(-32);
  return { name, priv, pub, raw };
}

export const JOURNAL_KEYS = ["gate", "root", "agent", "sub"].map(testKey);
export const REVOCATION_KEYS = ["revocation-root", "revocation-successor", "revocation-outsider", "revocation-successor-1"].map(testKey);

/** Every string in `value` that starts with `from` now starts with `to`; the rest is unchanged. */
export function rehost(value: J, from: string, to: string): J {
  if (typeof value === "string") return value.startsWith(from) ? to + value.slice(from.length) : value;
  if (Array.isArray(value)) return value.map((x) => rehost(x, from, to));
  if (value !== null && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, rehost(v, from, to)]));
  return value;
}

const sha256Hex = (b: Buffer | string) => createHash("sha256").update(b).digest("hex");
const pae = (type: string, payload: Buffer) =>
  Buffer.concat([Buffer.from(`DSSEv1 ${Buffer.byteLength(type)} ${type} ${payload.length} `), payload]);

function envelopeKey(env: J, keys: TestKey[]): TestKey | null {
  try {
    const payload = Buffer.from(env.payload, "base64");
    const sig = Buffer.from(env.signatures[0].sig, "base64");
    return keys.find((k) => edVerify(null, pae(env.payloadType, payload), k.pub, sig)) ?? null;
  } catch { return null; }
}

/** Sign `body` as a DSSE envelope line: the shape the journal's own writer gives (sorted keys, compact). */
function envelopeLine(body: J, key: TestKey): string {
  const payload = Buffer.from(canonical(body), "utf8");
  const sig = edSign(null, pae(IN_TOTO, payload), key.priv);
  const keyid = sha256Hex(key.raw);
  return JSON.stringify({ payload: payload.toString("base64"), payloadType: IN_TOTO, signatures: [{ keyid, sig: sig.toString("base64") }] });
}

export interface Rehosted { lines: string[]; checkpoint: J | null; rewritten: number }

/**
 * The journal with every identifier moved from `from` to `to` and every line signed by a test key re-signed, the hash
 * chain recomputed where the original chain held. A line no test key signed is kept as it was, so its verdict is the
 * original's. `rewritten` counts the lines whose bytes changed.
 */
export function rehostJournal(lines: string[], checkpoint: J | null, from: string, to: string): Rehosted {
  const out: string[] = [];
  let oldPrev = "0".repeat(64), newPrev = "0".repeat(64), rewritten = 0;
  for (const line of lines) {
    let next = line;
    const env = JSON.parse(line);
    const key = envelopeKey(env, JOURNAL_KEYS);
    if (key !== null) {
      try {
        const body = parseReceived(Buffer.from(env.payload, "base64"));
        const moved = rehost(body, from, to);
        if (moved.predicate && moved.predicate.prev === oldPrev) moved.predicate.prev = newPrev;
        next = envelopeLine(moved, key);
        if (next !== line) rewritten++;
      } catch { next = line; } // bytes the readers refuse to parse have no rewritten twin
    }
    oldPrev = sha256Hex(Buffer.from(line, "utf8"));
    newPrev = sha256Hex(Buffer.from(next, "utf8"));
    out.push(next);
  }
  let cp = checkpoint;
  if (checkpoint !== null) {
    const key = envelopeKey(checkpoint, JOURNAL_KEYS);
    if (key !== null) {
      const body = parseReceived(Buffer.from(checkpoint.payload, "base64"));
      const moved = rehost(body, from, to);
      if (moved.predicate && moved.predicate.head === oldPrev) moved.predicate.head = newPrev;
      cp = JSON.parse(envelopeLine(moved, key));
    }
  }
  return { lines: out, checkpoint: cp, rewritten };
}

/** The revocation lists with `type` moved and each list signed by a test key re-signed and re-linked. */
export function rehostRevocations(lists: J[], from: string, to: string): { lists: J[]; rewritten: number } {
  const out: J[] = [];
  let oldPrev: string | null = null, newPrev: string | null = null, rewritten = 0;
  for (const signed of lists) {
    let next = signed;
    try {
      const body = signed.body;
      const issuer = Buffer.from(body.issuerKey, "base64");
      const key = REVOCATION_KEYS.find((k) => k.raw.equals(issuer));
      const sig = Buffer.from(signed.sig, "base64");
      if (key && edVerify(null, Buffer.concat([REVOCATION_DOMAIN, canonicalBytes(body)]), key.pub, sig)) {
        const moved = rehost(body, from, to);
        if (moved.previous === oldPrev) moved.previous = newPrev;
        const resigned = edSign(null, Buffer.concat([REVOCATION_DOMAIN, canonicalBytes(moved)]), key.priv);
        next = { body: moved, sig: resigned.toString("base64") };
        if (JSON.stringify(next) !== JSON.stringify(signed)) rewritten++;
      }
    } catch { next = signed; }
    try { oldPrev = listDigest(signed.body); newPrev = listDigest(next.body); } catch { oldPrev = newPrev = null; }
    out.push(next);
  }
  return { lists: out, rewritten };
}

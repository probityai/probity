// The outline of an X.509 certificate, read from its DER bytes by the grammar in
// packages/probity-records/grammar/x509.json: the TypeScript twin of probity_records.certificate. The readers take two
// facts from a certificate, its validity period and its subject public key, and both come from this walk. No platform
// certificate parser stands behind it: Node's X509Certificate also reads PEM text and stops at the end of the first DER
// value, and each platform's parser accepts its own set of non-canonical encodings, so two readers would see two
// certificates. A certificate's signature is not checked here; who vouches for it is the caller's question (the TLS
// endpoint for a client certificate, the confirmed key for a DPoP x5c).
import { MICROS, civilSeconds, decimal } from "./verify.ts";

/** Bytes that are not one DER certificate of the outline the grammar gives. */
export class CertificateRefused extends Error {}
const bad = (why: string): CertificateRefused => new CertificateRefused(`certificate_not_der:${why}`);

interface Tlv { tag: number; start: number; body: number; end: number }

/** One DER tag-length-value at `at`, inside [at, limit): a one-byte tag, a definite length in its shortest form. */
function tlv(der: Buffer, at: number, limit: number): Tlv {
  if (at + 2 > limit) throw bad("truncated");
  const tag = der[at];
  if ((tag & 0x1f) === 0x1f) throw bad("tag");
  let length = der[at + 1], body = at + 2;
  if (length >= 0x80) {
    const count = length & 0x7f;
    if (count === 0 || count > 4 || body + count > limit) throw bad("length");
    length = 0;
    for (let i = 0; i < count; i += 1) length = length * 256 + der[body + i];
    if (der[body] === 0 || length < 0x80) throw bad("length_not_minimal");
    body += count;
  }
  if (body + length > limit) throw bad("truncated");
  return { tag, start: at, body, end: body + length };
}

/** The elements that fill `parent` exactly. */
function children(der: Buffer, parent: Tlv): Tlv[] {
  const out: Tlv[] = [];
  let at = parent.body;
  while (at < parent.end) { const child = tlv(der, at, parent.end); out.push(child); at = child.end; }
  return out;
}

const UTC_TIME = /^[0-9]{12}Z$/, GENERALIZED_TIME = /^[0-9]{14}Z$/;

/** A Time (RFC 5280 section 4.1.2.5) as microseconds since the epoch: UTCTime YYMMDDHHMMSSZ (YY 50 to 99 is 19YY, 00 to
 *  49 is 20YY) or GeneralizedTime YYYYMMDDHHMMSSZ, seconds present, no fraction, no offset. */
function time(der: Buffer, at: Tlv): bigint {
  const text = der.subarray(at.body, at.end).toString("latin1");
  let year: number, rest: string;
  if (at.tag === 0x17 && UTC_TIME.test(text)) { const yy = decimal(text.slice(0, 2)); year = yy >= 50 ? 1900 + yy : 2000 + yy; rest = text.slice(2); }
  else if (at.tag === 0x18 && GENERALIZED_TIME.test(text)) { year = decimal(text.slice(0, 4)); rest = text.slice(4); }
  else throw bad("time");
  const [mo, d, h, mi, sec] = [0, 2, 4, 6, 8].map((i) => decimal(rest.slice(i, i + 2)));
  const seconds = civilSeconds(year, mo, d, h, mi, sec);
  if (seconds === null) throw bad("time");
  return BigInt(seconds) * MICROS;
}

/** What the readers take from a certificate: its validity in microseconds, and its SubjectPublicKeyInfo bytes. */
export interface CertificateFacts { notBefore: bigint; notAfter: bigint; spki: Buffer }

/** The facts of `der` when it is exactly one DER certificate of the grammar's outline; CertificateRefused otherwise. */
export function certificateFacts(der: Buffer): CertificateFacts {
  if (!Buffer.isBuffer(der)) throw bad("bytes");
  const cert = tlv(der, 0, der.length);
  if (cert.tag !== 0x30 || cert.end !== der.length) throw bad("certificate");
  const top = children(der, cert);
  if (top.length !== 3 || top[0].tag !== 0x30 || top[1].tag !== 0x30 || top[2].tag !== 0x03) throw bad("certificate");
  const tbs = children(der, top[0]);
  let i = 0;
  if (tbs.length > 0 && tbs[0].tag === 0xa0) {  // [0] EXPLICIT Version: v2 (1) or v3 (2); DER never writes the default v1
    const version = children(der, tbs[0]);
    if (version.length !== 1 || version[0].tag !== 0x02 || version[0].end - version[0].body !== 1 || (der[version[0].body] !== 1 && der[version[0].body] !== 2)) throw bad("version");
    i = 1;
  }
  // serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo
  const outline = [0x02, 0x30, 0x30, 0x30, 0x30, 0x30];
  if (tbs.length < i + outline.length || outline.some((tag, k) => tbs[i + k].tag !== tag)) throw bad("tbs");
  const validity = children(der, tbs[i + 3]);
  if (validity.length !== 2) throw bad("validity");
  // then, each at most once and in this order: issuerUniqueID [1], subjectUniqueID [2], extensions [3]
  let allowed = [0x81, 0x82, 0xa3];
  for (const extra of tbs.slice(i + outline.length)) {
    const k = allowed.indexOf(extra.tag);
    if (k < 0) throw bad("tbs");
    allowed = allowed.slice(k + 1);
  }
  const spki = tbs[i + 5];
  return { notBefore: time(der, validity[0]), notAfter: time(der, validity[1]), spki: Buffer.from(der.subarray(spki.start, spki.end)) };
}

// The SubjectPublicKeyInfo of the two key types a DPoP proof may use, as the bytes before the key (RFC 8410 section 4
// for Ed25519; RFC 5480 section 2 for P-256, a named curve and an uncompressed point).
const SPKI_ED25519 = Buffer.from("302a300506032b6570032100", "hex");
const SPKI_P256 = Buffer.from("3059301306072a8648ce3d020106082a8648ce3d03010703420004", "hex");

/** The public key a SubjectPublicKeyInfo holds, as the JWK members' bytes: {kty, crv, x} or {kty, crv, x, y}; null
 *  for any other key type or encoding. */
export function spkiKey(spki: Buffer): { kty: string; crv: string; x: Buffer; y?: Buffer } | null {
  if (spki.length === SPKI_ED25519.length + 32 && spki.subarray(0, SPKI_ED25519.length).equals(SPKI_ED25519)) {
    return { kty: "OKP", crv: "Ed25519", x: Buffer.from(spki.subarray(SPKI_ED25519.length)) };
  }
  if (spki.length === SPKI_P256.length + 64 && spki.subarray(0, SPKI_P256.length).equals(SPKI_P256)) {
    const at = SPKI_P256.length;
    return { kty: "EC", crv: "P-256", x: Buffer.from(spki.subarray(at, at + 32)), y: Buffer.from(spki.subarray(at + 32)) };
  }
  return null;
}

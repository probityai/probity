// Reader of the session-key certificate probity-key-delegation/v2, the TypeScript twin of
// probity_records.signing.verify_delegation and Delegation.covers.
//
// The format, the order of checks and the sixteen refusal codes are the Python reader's
// (packages/probity-records/docs/key-delegation.md); the shared vectors
// (packages/probity-records/vectors/shared/delegation.json) hold the two to the same verdict. A refused
// certificate throws an Error whose message is the code.

import type { KeyObject } from "node:crypto";
import { canonicalBytes, edOk, isFloat, keyId, rawKey, ts, unb64 } from "./verify.ts";

type J = any; // eslint-disable-line @typescript-eslint/no-explicit-any

const DELEGATION_DOMAIN = Buffer.from("probity-key-delegation-v2\u0000", "latin1");
export const DELEGATION_FORMAT = "probity-key-delegation/v2";
/** Formats this reader refuses by name: a v1 certificate states no scope, and its readers counted notAfter inside. */
export const RETIRED_DELEGATION_FORMATS = ["probity-key-delegation/v1"];
export const HIERARCHIES = ["authority", "identity", "record"];
export const CUSTODIES = ["custodian", "customer", "ours"];
const MEMBERS = ["custody", "format", "hierarchy", "notAfter", "notBefore", "rootKeyId", "rootProvenance", "sessionKey", "tenant", "windowS"];
const TENANT = /^[\x21-\x7e]{1,256}$/;
const WINDOW_MAX_S = 2 ** 53 - 1;
/** Every refusal verifyDelegation reports, in the order it checks them. */
export const DELEGATION_CODES = [
  "delegation_shape", "delegation_format_retired", "delegation_format_unknown", "delegation_members_invalid",
  "delegation_hierarchy_invalid", "delegation_custody_invalid", "delegation_record_root_customer_custody",
  "delegation_tenant_invalid", "delegation_window_invalid", "delegation_time_invalid", "delegation_window_empty",
  "delegation_window_exceeds_declared", "delegation_root_provenance_invalid", "delegation_session_key_invalid",
  "delegation_unverified", "delegation_root_key_id_mismatch",
] as const;

export interface Delegation {
  session: KeyObject;
  sessionKeyId: string;
  rootKeyId: string;
  hierarchy: string;
  custody: string;
  tenant: string;
  windowS: number;
  notBefore: string;
  notAfter: string;
}

const isObj = (v: J): boolean => v !== null && typeof v === "object" && !Array.isArray(v);

/** The refusal code for a scope a root may not certify, or null (signing.scope_problem). */
export function scopeProblem(hierarchy: J, custody: J, tenant: J, windowS: J, holder: J = null): string | null {
  if (typeof hierarchy !== "string" || !HIERARCHIES.includes(hierarchy)) return "delegation_hierarchy_invalid";
  if (typeof custody !== "string" || !CUSTODIES.includes(custody)) return "delegation_custody_invalid";
  if (hierarchy === "record" && custody === "customer") return "delegation_record_root_customer_custody";
  if (typeof tenant !== "string" || !TENANT.test(tenant)) return "delegation_tenant_invalid";
  if (typeof windowS !== "number" || !Number.isInteger(windowS) || isFloat(holder, "windowS", windowS)
      || windowS < 1 || windowS > WINDOW_MAX_S) return "delegation_window_invalid";
  return null;
}

function utc(text: J): number {
  if (typeof text !== "string" || !text.endsWith("Z")) throw new Error("delegation_time_invalid");
  try { return ts(text); } catch { throw new Error("delegation_time_invalid"); }
}

function bodyProblem(body: J): string | null {
  const keys = Object.keys(body).sort();
  if (keys.length !== MEMBERS.length || keys.some((k, i) => k !== MEMBERS[i])) return "delegation_members_invalid";
  const scope = scopeProblem(body.hierarchy, body.custody, body.tenant, body.windowS, body);
  if (scope) return scope;
  let start: number, end: number;
  try { start = utc(body.notBefore); end = utc(body.notAfter); } catch (e) { return (e as Error).message; }
  if (end <= start) return "delegation_window_empty";
  if (end - start > body.windowS * 1_000_000) return "delegation_window_exceeds_declared";
  if (!isObj(body.rootProvenance)) return "delegation_root_provenance_invalid";
  try { if (unb64(body.sessionKey).length !== 32) return "delegation_session_key_invalid"; }
  catch { return "delegation_session_key_invalid"; }
  if (typeof body.rootKeyId !== "string") return "delegation_root_key_id_mismatch";
  return null;
}

/** The delegation when one pinned root (raw 32-byte Ed25519 keys) signed a well-formed v2 certificate; throws the
 * first refusal code otherwise. Nothing in the certificate selects its root: every pinned root is tried. */
export function verifyDelegation(certificate: J, roots: Buffer[]): Delegation {
  if (!isObj(certificate) || !isObj(certificate.body) || Object.keys(certificate).sort().join(",") !== "body,sig")
    throw new Error("delegation_shape");
  const body = certificate.body;
  if (RETIRED_DELEGATION_FORMATS.includes(body.format)) throw new Error("delegation_format_retired");
  if (body.format !== DELEGATION_FORMAT) throw new Error("delegation_format_unknown");
  const problem = bodyProblem(body);
  if (problem) throw new Error(problem);
  let sig: Buffer;
  try { sig = unb64(certificate.sig); } catch { throw new Error("delegation_shape"); }
  const message = Buffer.concat([DELEGATION_DOMAIN, canonicalBytes(body)]);
  for (const raw of roots) {
    const root = rawKey(raw);
    if (!edOk(root, message, sig)) continue;
    if (keyId(root) !== body.rootKeyId) throw new Error("delegation_root_key_id_mismatch");
    const session = rawKey(unb64(body.sessionKey));
    return { session, sessionKeyId: keyId(session), rootKeyId: body.rootKeyId, hierarchy: body.hierarchy,
      custody: body.custody, tenant: body.tenant, windowS: body.windowS, notBefore: body.notBefore, notAfter: body.notAfter };
  }
  throw new Error("delegation_unverified");
}

/** Whether an instant `at` (RFC 3339 with an offset) falls in the half-open window [notBefore, notAfter). */
export function covers(d: Delegation, at: J): boolean {
  let moment: number;
  try { moment = ts(at); } catch { return false; }
  return ts(d.notBefore) <= moment && moment < ts(d.notAfter);
}

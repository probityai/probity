#!/usr/bin/env node
// Native APS inputs for one connected refund case (contract review-2026-10-23, section 3).
//
// Builds the action-intent receipt, the policy-decision receipt, ActionReferenceInputV2, the exact payload, the
// four decision components and the consumption trust selection with the APS SDK 8.0.1 functions themselves
// (createActionReferenceInputV2, computePayloadRefV1, computeActionRefV2, createReceiptV1, buildDecisionRefV1,
// normalizeCoreDecisionOutputV1). The SDK is loaded through the Horizon Shield aps-receipt adapter's pinnedSdk(),
// which refuses any installed package whose file tree differs from its PINS.json.
//
// Keys are public test keys derived from fixed labels. These inputs stand in for the native J01 artifacts APS
// offered to produce; they carry no merchant authority.
//
//   node aps_inputs.mjs --adapter <horizon aps_receipt dir> --out <case dir> --seed-label <label>
//     --decision-id <id> --payment-id <id> --amount-minor <n> --currency EUR
//     --intent-issued-at <utc ms> --approval-issued-at <utc ms> --valid-until <utc ms> --nonce <32 hex>
import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync, existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const argv = process.argv.slice(2);
const arg = (n) => {
  const i = argv.indexOf(n);
  if (i < 0 || i + 1 >= argv.length) { console.error("aps_inputs: missing " + n); process.exit(2); }
  return argv[i + 1];
};
const A = await import(pathToFileURL(join(resolve(arg("--adapter")), "adapter_aps_receipt.mjs")).href);
const { sdk, tree, version } = await A.pinnedSdk();

const sha = (b) => createHash("sha256").update(b).digest("hex");
const label = arg("--seed-label");
const seedOf = (role) => sha(Buffer.from("refund-j01-connected/" + label + "/" + role, "utf8"));
const W = A.REFUND.worker, B = A.REFUND.approval_boundary;
const out = resolve(arg("--out"));
const payload = { payment_id: arg("--payment-id"), amount_minor: Number.parseInt(arg("--amount-minor"), 10), currency: arg("--currency") };
const decisionId = arg("--decision-id");
const intentAt = arg("--intent-issued-at"), approvalAt = arg("--approval-issued-at"), validUntil = arg("--valid-until");

const action = sdk.createActionReferenceInputV2({
  agent_id: W, action_type: A.REFUND.action_type, target: A.REFUND.target_prefix + payload.payment_id + A.REFUND.target_suffix,
  payload_ref: sdk.computePayloadRefV1(payload), scope_required: A.REFUND.scope_required, issued_at: intentAt, nonce: arg("--nonce"),
});
const actionRef = sdk.computeActionRefV2(action);
const delegation = "sha256:" + sha(Buffer.from("refund-j01-connected/delegation/" + label, "utf8"));
const intent = sdk.createReceiptV1({
  profile: "aps-receipt-v1", receipt_type: "aps:action-intent:v1", issuer: W, subject_agent: W, action_ref: actionRef,
  delegation_ref: delegation, issued_at: intentAt, evidence_refs: [], result: { profile: "aps-action-intent-result-v1", status: "declared" },
}, [{ signer: W, key_id: "wrk-1", private_key: seedOf("worker") }]);
const output = sdk.normalizeCoreDecisionOutputV1({
  profile: "aps-core-decision-output-v1", verdict: "permit",
  effective_authority_ref: sha(Buffer.from("refund-j01-connected/authority/" + label, "utf8")), constraints: [], valid_until: validUntil,
});
const decision = {
  authority_state: { grant: "refund-j01-connected" },
  policy_input: { merchant_decision: { decision_id: decisionId, merchant_id: "merchant-test" } },
  decision_context: { channel: "sandbox" },
  decision_output: output,
};
const built = sdk.buildDecisionRefV1({ action_ref: actionRef, ...decision });
const approval = sdk.createReceiptV1({
  profile: "aps-receipt-v1", receipt_type: "aps:policy-decision:v1", issuer: B, subject_agent: W, action_ref: actionRef,
  delegation_ref: delegation, decision_ref: built.decision_ref, issued_at: approvalAt, evidence_refs: [], result: output,
  prev: intent.receipt_id,
}, [{ signer: B, key_id: "bnd-1", private_key: seedOf("boundary") }]);
const trust = {
  schema: A.TRUST_SCHEMA, profile: "aps-receipt-v1", scope: A.REFUND.scope_required, keys: [
    { signer: W, key_id: "wrk-1", role: "worker", public_key: sdk.publicKeyFromPrivate(seedOf("worker")), not_before: "2026-10-01T00:00:00.000Z", not_after: null, revoked_at: null },
    { signer: B, key_id: "bnd-1", role: "approval-boundary", public_key: sdk.publicKeyFromPrivate(seedOf("boundary")), not_before: "2026-10-01T00:00:00.000Z", not_after: null, revoked_at: null },
  ],
};

const files = {
  "inputs/aps-approval.json": approval, "inputs/aps-intent.json": intent, "inputs/aps-action.json": action,
  "inputs/aps-payload.json": payload, "inputs/decision-evidence.json": decision, "trust/aps-consumption.json": trust,
};
for (const [rel, obj] of Object.entries(files)) {
  const path = join(out, rel);
  if (existsSync(path)) { console.error("aps_inputs: refusing to overwrite " + path); process.exit(2); }
  mkdirSync(join(path, ".."), { recursive: true });
  writeFileSync(path, JSON.stringify(obj, null, 2) + "\n", { encoding: "utf8", flag: "wx" });
}
console.log(JSON.stringify({
  aps_sdk_version: version, aps_package_tree_sha256: tree, receipt_id: approval.receipt_id, intent_receipt_id: intent.receipt_id,
  decision_id: decisionId, action_ref: actionRef, approval_issued_at: approvalAt, valid_until: validUntil,
}));

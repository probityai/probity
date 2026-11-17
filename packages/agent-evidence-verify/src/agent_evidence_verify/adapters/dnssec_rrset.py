"""``dnssec_rrset/v1``: does a DNSSEC chain validate one RRset from the consumer's trust anchor?

A DNS answer held offline (an SVCB discovery record, a TXT key record) is evidence of what the zone
owner published only when its DNSSEC chain validates: RRSIG over the RRset, DNSKEY of the zone, DS
in the parent, up to a trust anchor the consumer holds. The assessment names the chain (a case
artifact: records in DNS wire format, uncompressed), the owner name and type, the trust anchor
(``{"zone": ".", "ds": ["20326 8 2 E06D..."]}``) and the instant at which the signatures must be
valid. The rules are those of :mod:`agent_evidence_verify.dnssec`.

Decisions: ``supported`` / ``rrset_validated`` when the chain validates the RRset, with the
SHA-256 of each validated record's RDATA in the check; ``contradicted`` when the chain is present
and a check fails (``signature_invalid``, ``rrsig_expired``, ``rrsig_not_yet_valid``,
``ds_mismatch``, ``chain_malformed``, ...); ``not_established`` when a record the chain needs is
missing (``rrset_missing``, ``rrsig_missing``, ``ds_missing``, ``dnskey_missing``), an algorithm is
not read, or the answer was expanded from a wildcard. A missing chain is never validated.
"""

from __future__ import annotations

from .. import dnssec
from ..common import CaseError

CLAIM_TYPE = "dnssec_rrset/v1"
_DECISION = {dnssec.SECURE: "supported", dnssec.BOGUS: "contradicted",
             dnssec.INDETERMINATE: "not_established"}


def adjudicate(case, policy, artifact_root):
    """Validate the named RRset of the bound chain at the consumer's instant."""
    from ..key_authority import dnssec_anchor, parse_instant, posix_seconds
    from .bound_records import assessment_for, bound, decision
    case_id, artifacts, assessment = assessment_for(
        case, policy, CLAIM_TYPE, {"chain", "name", "type", "trust_anchor", "at"})
    zone, ds = dnssec_anchor(assessment, "assessment")
    try:
        dnssec.name_labels(assessment["name"], "assessment.name")
        rtype = dnssec.rrtype(assessment["type"], "assessment.type")
    except ValueError as exc:
        raise CaseError(str(exc)) from exc
    now = posix_seconds(parse_instant(assessment["at"], "assessment.at"))
    chain, binding = bound(artifacts, artifact_root, assessment["chain"], "assessment.chain")
    scope = {"chain": binding, "name": assessment["name"], "type": assessment["type"],
             "at": assessment["at"], "trust_anchor": {"zone": zone, "ds": ds}}
    if chain is None:
        return decision(case_id, CLAIM_TYPE, scope, "not_established", "chain_unavailable")
    result = dnssec.validate(chain, assessment["name"], rtype, zone, ds, now)
    return decision(case_id, CLAIM_TYPE, scope, _DECISION[result.outcome], result.reason,
                    [result.check(assessment["name"], rtype)])

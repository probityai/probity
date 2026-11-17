# DNS-AID discovery: the signed binding, the DNSSEC chain, and where the calls went

Three claim types check what a DNS-AID discovery record (an SVCB record under `_agents.<zone>`)
proves and whether an agent's calls followed it. None of them contacts DNS or the network: every
byte is a case artifact the consumer binds by length and SHA-256.

| Claim type | Question | Inputs |
|---|---|---|
| `dns_aid_sig/v1` | Does the record's `sig` bind it to a key the zone owner may sign with? | the record as served, the JWKS fetched, the instant, the consumer's `key_authority` |
| `dnssec_rrset/v1` | Does a DNSSEC chain validate this RRset from my trust anchor? | the chain in DNS wire format, owner name, type, trust anchor, instant |
| `declared_versus_acted/v1` | Did every call go to an endpoint a verified record declared? | an observer trajectory and its witnessed head, the JWKS and chain bytes it names |

## `dns_aid_sig/v1`

The record artifact is one JSON object: `fqdn`, `target`, `port`, `alpn`, optional `proto`, `zone`,
`params` (the DNS-AID parameters `cap`, `cap-sha256`, `bap`, `policy`, `realm`, `connect-class`,
`connect-meta`, `enroll-uri`, `well-known`, each a string or `null`), `sig` (the compact JWS), and
optional `jwks_url`. The assessment names the record, the JWKS and the instant `at` (RFC 3339), and
may name a `key_authority` (see [key-authority.md](key-authority.md)).

The rules form the profile `https://probityai.github.io/agent-evidence-vectors/profile/dns-aid-sig-binding/v1`:

- The JWS is three strict, canonical base64url parts; a part with non-zero trailing bits is refused,
  because a lenient decoder reads the same bytes and the signature would still verify.
- Header and payload are I-JSON: a repeated member name is refused, so a first-wins and a last-wins
  reader cannot bind two different `fqdn` values to one signature.
- `crit` in the header is refused (RFC 7515 section 4.1.11), and `alg` is `ES256`.
- `port`, `iat` and `exp` are JSON integers (`443.0` is refused).
- The record is expired when `exp` is at or before the instant, and not yet valid when `iat` is more
  than 300 seconds after it.
- The signed `alpn` is compared with the record's `proto` when it has one (draft-dawn-dnsaid-00
  Table 1: `alpn` names the transport, `proto` the agent protocol), and with its `alpn` otherwise.
- The `svcb` digest is `svcb1:` followed by the RFC 8785 form of the present parameters; an empty
  value is a value, so a parameter the publisher never set cannot be injected as `""`.
- A `jwks_url` on another host than `dns-aid.<zone>` or the zone apex is refused.
- The signature verifying is not enough: `supported` needs the key authorised for the zone under the
  consumer's `key_authority`. With none, the verdict stops at `not_established`
  (`no_key_authority_in_policy`). For `did-web` the subject is `did:web:<zone>`; for every other kind
  it is the zone.

| Decision | Reasons |
|---|---|
| `supported` | `binding_verified` |
| `contradicted` | `record_malformed`, `record_not_ijson`, `jws_malformed`, `jws_header_not_ijson`, `jws_header_not_object`, `jws_crit_unsupported`, `jws_alg_not_es256`, `jws_signature_malformed`, `signature_invalid`, `payload_not_ijson`, `payload_not_object`, `payload_member_not_integer`, `binding_expired`, `endpoint_not_bound`, `params_not_bound`, `jwks_host_not_zone`, and every `unauthorized` reason of the key authority |
| `not_established` | `record_unavailable`, `jwks_unavailable`, `jwks_malformed`, `jwks_no_usable_key`, `zone_does_not_contain_record`, `binding_not_yet_valid`, `endpoint_only`, and every `unknown` reason of the key authority |

Every decision's scope states `dns_aid_status` (the publisher's own status vocabulary: `full`,
`endpoint_only`, `unbound`, `expired`, `invalid`, `no_key`, `not_yet_valid`), `signature_coverage`
(vocabulary term `signature_coverage`: `full`, `endpoint_only`, `none`) and `jwks_key_set_sha256`,
the SHA-256 over the sorted raw-key digests of the JWKS signing keys read, one per line. Every
malformed input a record, a signature or a JWKS can carry gets a verdict; only the consumer's own
policy is refused with exit 2.

The tests run the twelve original binding cases and eight counter-examples signed by dns-aid-core's
own signer (825ccea), plus a non-canonical signature case (`tests/data/dns-aid-sig`).

## `dnssec_rrset/v1`

The chain is a series of resource records in DNS wire format, uncompressed (RFC 9102 section 3): the
form `agent-evidence-observer` records at call time. The trust anchor is
`{"zone": ".", "ds": ["20326 8 2 E06D44B8..."]}`; IANA publishes the root's at
https://data.iana.org/root-anchors/root-anchors.xml. The validator
(`agent_evidence_verify.dnssec`) is written from RFC 4034 and RFC 4035 and imports no DNS library;
it reads RSA/SHA-256 and SHA-512, ECDSA P-256 and P-384, Ed25519 and Ed448, and DS digests SHA-256
and SHA-384.

`supported` (`rrset_validated`) names the signer and the SHA-256 of each validated RDATA.
`contradicted` means the chain is present and a check fails (`signature_invalid`, `rrsig_expired`,
`rrsig_not_yet_valid`, `ds_mismatch`, `ds_malformed`, `signer_not_authoritative`,
`chain_malformed`). `not_established` means a record the chain needs is missing (`rrset_missing`,
`rrsig_missing`, `ds_missing`, `dnskey_missing`, `chain_unavailable`), an algorithm is not read, or
the answer was expanded from a wildcard, which needs a denial-of-existence proof this reader does
not read. A missing chain never validates. The tests run chains a second implementation (dnspython)
signed, with mutations, and the HTTPS RRset of cloudflare.com with its chain from the IANA root.

## `declared_versus_acted/v1`

The trajectory is the JSONL file `probity_observer.resolution.ResolutionObserver` writes, closed by
a head signed by a witness key the consumer pins (`witness_key`, raw Ed25519 as hex) for the
trajectory id the consumer expects. The adapter verifies the hash links and the head itself, then
joins each `call` event to the SVCB records of the resolution it names (or of every earlier
resolution when it names none), judging each declaring record's `sig` with the `dns_aid_sig/v1`
rules at the call's own instant. `evidence` lists the case artifacts (JWKS bytes, DNSSEC chains); a
resolution picks them by the SHA-256 it recorded. A `dnssec-chain` authority with no `chain` member
reads each resolution's own recorded chain.

| Decision | When |
|---|---|
| `supported` (`every_call_declared_and_bound`) | every call went to a host and port a record declared, and that record's binding is `supported` at the call's instant |
| `contradicted` | a call went to an endpoint no record declared (`call_not_declared`), after `exp`, or under a key the authority refuses; or the trajectory fails (`trajectory_tail_missing`, `trajectory_link_broken`, `trajectory_head_other_key`, ...) |
| `not_established` | the best binding is endpoint-only, unsigned or has no key authority, its bytes were not supplied, or no call was recorded (`no_calls_recorded`) |

The scope carries the denominator: events, resolutions, calls, and calls bound, contradicted and
unestablished. A call the observer did not record is missing, never clean: the witnessed head fixes
the count. The tests run ten trajectories written by the observer's own recorder, among them a
planted call to an undeclared host and a trajectory whose last call was dropped.

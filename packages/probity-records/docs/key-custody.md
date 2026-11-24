# Key custody and the customer-held witness key

The signing key does not have to live next to the agent. `VaultTransitKey`, `AwsKmsKey` and `GcpKmsKey` sign
through HashiCorp Vault transit, AWS KMS or Cloud KMS Ed25519, so the private key never leaves the service.
Each pins its public key at construction and refuses a service that answers with another one. `delegate`
issues a short-lived session key signed by a root key for one scope, and `verify_delegation` re-checks the
certificate offline ([probity-key-delegation/v2](key-delegation.md)). The key's provenance travels in every permit and checkpoint it signs.

The witness key belongs to the customer. The journal publishes a C2SP tlog checkpoint feed. A witness the
customer runs, with a key we never hold, cosigns each checkpoint over an RFC 9162 consistency proof and refuses a
split view with HTTP 422. `Witness` and `serve_witness` are the server, `Feed` the client. The auditor pins a
`c2sp.org/tlog-policy` naming that witness, and `verify_journal` then fails with `witness_quorum_not_met`
unless the journal carries the cosignature. An independent witness built only from `golang.org/x/mod`,
`transparency-dev/formats` and `transparency-dev/merkle` completes the same handshake
(`interop/go-witness/interop.py`).

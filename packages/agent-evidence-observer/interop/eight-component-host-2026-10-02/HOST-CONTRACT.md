# Eight-component host contract

This page records the contract of the retained run under [retained](retained).
The producing host chain is run by the operator's runtime. This directory keeps
the run it wrote and the public replay in `verify_retained.py`; it does not
fetch any source snapshot, build any wheel or launch any component.

## Source selection, as recorded

The run selected the original `SOURCE-SELECTION.json`, SHA-256
`1107cb0621b8b9227d5e7e8615c24bd1a2cee0ecb4cb1e7a15a1e3dd839540d6`, byte-identical
to partial feature `c104d8b7db835f1ed3f88a9ab927067136481079`. Its retained copy is
`retained/fresh-completed/selected-reference/SOURCE-SELECTION.json`, and the
retained `public-installation.json` binds that digest as `sourceSelectionSha256`.
The selection pins files of historical commits of other repositories; it is a
record of what the run consumed, never re-pinned to this tree.

| Component | Recorded frozen source | Executed consumption |
| --- | --- | --- |
| Vocabulary | `8c80579ae613d7ae07982321e13a6091c402b2a8` | Actual closed basis/method/result and PEER terms |
| Vectors | `bbdef583c9241138e5c2b5d872bc77f7f539e9ac` | Installed `ReferenceVerifier(pinned_pubs).verify(stmt, raw)` |
| JCS | `40ce923843167629f0ed044590d1319e6a711015` | Real registry `jcs-admit=0.1.1` byte admission |
| DSSE | `f6f6df4bef5544af76dc3f5b05909a2f24a8e51f` | Real registry `dsse=0.1.1` sign and returned verified payload |
| Verify | `e835ce2bd6a960e7a1cc2fa6522f16d55dce728a` | Installed `source_text_coverage/v1`, selected `text_utf8/v1` witness |
| Admission | `20d8924d904a2597276209529ab8f60ceb1aaba9` | Actual pinned `data.sigstore.isCompliant` with external anchors |
| Observer | `c774e0711e4a30c31cdfb184c1e4495a249fbdd0` | Installed native grant, HTTP target, readback and SQLite recovery |
| Atlas | `58c89e18033a3c5fdd10d1a9b65497e25093dcc8` | Actual full register validator and stable original authority record |

These heads are facts of the run, carried in `retained/fresh-completed.json` and
the retained installation record. The replay reads no repository at any of them.

DSSE's registry release matched its selected source. JCS's released VCS source is
`33603fc8caf6f8469ea790f41ab74ae64d4f1658`, which differs from selected current
`40ce923...`; the chain used the released crate APIs, without asserting that the
release came from current main. OPA 1.18.0's official Linux/amd64 static asset
was selected by SHA-256
`65d700b14b99b354982b61031b40bdc8e316ea93dadd61818f066d1d9a69dcce`; its version
reports build commit `cc2c5c60a4c486f15a5e8de457e96ed0fefaf5fe-dirty`, an exact
binary selection rather than a pristine source-build claim. The source-wheel
versions were Observer 0.0.1, Vectors 0.15.0 and Verify 0.1.0; nothing was
published.

## What the producing host checked

The operator selected the complete installation manifest SHA-256 (retained as
`retained/host-selection-sha256.txt`) before candidate execution; the candidate
could not choose that hash, manifest, policy, key, source revision, binary,
installed reader or authority identity. Before the first child the host checked
the source-selection digest, all eight declared heads and every selected source
byte; the complete installed site-packages closure; the selected interpreter,
wheels, Rust binary and OPA; and the external policy, seed files, public keys and
distinct roles. The envelope, issuer and target-service keys were fresh random
seeds held by the same operator: distinct roles, neither identity proof nor
independent custody. Private seed bytes were never retained.

Component children ran with `-I -B` and a finite environment allowlist. The host
launcher, interpreter standard library, operating system, protected filesystem,
native clock and SQLite durability were trusted infrastructure. Hash checking is
not process isolation, and the run makes no general sandbox claim.

## Executed gates, as retained

Raw candidate AEE is retained unchanged. The installed Rust CLI admitted it with
JCS, signed the admitted canonical bytes, and DSSE verified under the externally
selected host public key and returned the verified payload; later gates received
only those returned bytes. Installed Vectors checked structure and crypto under
the published test public key
`496cbe15e391eccd3a0864f2709df0eeb4f5b6c1bad750c95cc80ee49bceae62`; the healthy
candidate is the unchanged signed fixture `vectors/statements/vcc938c6038536dcb.json`,
an exposed deterministic conformance fixture, not a production execution or blind
test. OPA admitted the returned payload under the pinned Rego source and the
selected corpus, substrate, catch-policy, network posture, demanded `XA` scope and
pass-only threshold. The vocabulary check read actual closed terms. Atlas's
`validate_register` authenticated the selected register, and the selected
`authority-recovery-2026-10-02` provenance authenticated its whole 110-member
original archive. Installed Verify selected literal nonclaims in that provenance
under `source_text_coverage/v1`; only a supported outcome admits.

After those gates passed, installed Observer created the request, policy and grant.
The action's content digest is the accepted returned payload's SHA-256; tenant,
principal, tool, target and invocation identity came from host policy. Two
separately launched target processes served the native ticket store over HTTP:
one exact POST committed a native intent and one ticket revision, and a fresh
process reopened the same SQLite file under a retained signed prior head,
recovered, and supplied a separate GET readback. The grant clock began at
`2026-10-02T12:00:00Z`, expired after 60 seconds, and the effect ran at +10 seconds.

The retained run is the completed scenario. Every child's stdout and stderr,
process receipts, HTTP request and response bytes, target startup, exit and
recovery records, native SQLite state, signed heads, the public host policy and
the selected reference vocabulary, Rego, Atlas register, provenance, original ZIP
and report are kept under `retained/fresh-completed/`.

## What the public replay checks

`verify_retained.py` uses only the published observer package and makes two checks:

1. Every retained `*.stdout` and `*.stderr` matches the byte length and SHA-256
   its `*.process.json` record carries.
2. The native effect is re-verified from the retained signed receipt, the separate
   HTTP readback and the host grant with `probity_observer.ticket_state`, at the
   retained host clock and under the host-selected service key. The resulting
   report must equal `verify-effect.stdout` byte for byte.

`tests/test_retained.py` adds refusal controls: a changed stream byte, a changed
readback revision or content, the wrong service key and an expired clock each
refuse. The Rust, Vectors, OPA, vocabulary, Atlas and Verify gates are not
re-executed; their recorded outputs are checked only against their process records.

## Limits

The run used author-operated keys, store and clock. It establishes a finite
installed integration and bounded native effects. Acceptance, outside recurring
adoption, production issuer identity, independent effect custody, general
containment, power-loss recovery and distributed exactly-once semantics remain
unestablished, as the retained run's own `doesNotAssert` list states. No
component release or vocabulary promotion was performed.

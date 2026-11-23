# Identity digests, version 1

A record, a permit, a stamp on an upstream request and a canonical identity string each name who acted for whom by
digest. This page defines those digests once. Every implementation computes them the same way, and the shared vectors
in [`vectors/shared/identity_digests.json`](../vectors/shared/identity_digests.json) hold each one to it. The Python
reference is `probity_records.digests`; the TypeScript twin is `node/probity-records-verify` (`principalsDigest`,
`actChainDigest`, `grantChainDigest`, `grantChainDigestOf`, `stampDigest`, `stampDigestOf`).

## The form

Every identity digest is the text `sha256:` followed by 64 lowercase hexadecimal digits: the SHA-256 of the RFC 8785
(JCS) bytes of a JSON value, after that value has passed the identity domain check below. A digest in any other form
(upper case, no prefix, another length) is refused where a digest is expected (`identity_digest_malformed`).

## The four digests

| function | input | digest of |
|---|---|---|
| `principals_digest(block)` | the verified principals block of one request | the block as recorded: an object whose members are among `user`, `agent`, `sponsor`, `approver`, each an object (the principal member of the tool-call record) |
| `act_chain_digest(act)` | the RFC 8693 `act` claim of the user's credential | the claim as its identity provider signed it: an object naming the current actor in a non-empty string `sub`, its `act` member the prior actor, at most 32 actors |
| `grant_chain_digest(links)` | the capability grant links a request runs under, root first | the JSON array of the links' grant digests, root first, each the 64-digit hex `grant_digest` of the link's body |
| `stamp_digest(principals, act, grants)` | three digests, `act` and `grants` optional | the object `{"act": act, "grants": grants, "principals": principals}`, with null for an absent act claim or grant chain |

`grant_chain_digest_of(digests)` computes the grant chain digest from the grant digests alone, and
`stamp_digest_of(block, links)` computes the stamp digest from a block (its act chain is the `user` member's `act`)
and the links, or null for none.

Why the grant chain digest is over the grant digests and not over the links: a grant digest is already the public
name of a grant (a revocation list names it, and `verify_grant_allow` reports the chain as a list of them), so anyone
who holds those names computes the chain digest without the bodies. A link's signature proves the link; `verify_chain`
checks it, and the digest names the chain it proved.

Why an absent act claim is null and has no digest of its own: a credential without `act` is graded `act-absent` and is
accepted, and absence must never look like a chain. `act_chain_digest` refuses a missing claim
(`identity_act_missing`); the stamp carries null.

## The identity domain

Before anything is hashed, the value must lie in the identity domain:

- null, `true`, `false`;
- strings of Unicode scalar values (astral characters included; a lone surrogate is refused);
- integers from -(2^53 - 1) to 2^53 - 1;
- arrays;
- objects whose member names are printable ASCII (U+0020 to U+007E);
- at most 64 nested arrays and objects.

A value outside it is refused with the one code `identity_out_of_domain` and one reason:

| reason | the value holds |
|---|---|
| `unsupported_type` | something that is not JSON |
| `float` | a number written with a fraction or an exponent, integral ones such as `7.0` and `7e0` included |
| `integer_out_of_range` | an integer beyond 2^53 - 1 in magnitude |
| `member_name_not_ascii` | a member name outside printable ASCII |
| `lone_surrogate` | a string with an unpaired surrogate |
| `too_deep` | more than 64 nested containers |
| `no_canonical_form` | anything else RFC 8785 cannot print |

The reasons for these limits: JavaScript cannot tell `7.0` from `7`, and a Go reader would need an ECMAScript number
printer, so a float would be hashed one way by one reader and refused or hashed another way by the next; two integers
beyond 2^53 share their JCS bytes, so a digest over one would hold for the other; RFC 8785 sorts member names by UTF-16
code unit, which differs from code point order outside ASCII. A reader that parses JSON text must keep a number written
as a float apart from an integer (Python `json`, the TypeScript twin's `parsePy`, Go `json.Number`).

Grant bodies are outside the rule. A body may carry a float (a spend limit, a range bound); its grant digest is
`probity_records.core.canonical`'s, and the chain digest is over those digests, which are in the domain.

## The order of the checks

So that every implementation refuses a value with the same code and reason:

1. A missing act claim (`act_chain_digest` of null) is refused first, as `identity_act_missing`.
2. The identity domain, walked depth first: at an array, its depth, then its items in order; at an object, its depth,
   then every member name, then its member values in sorted member order.
3. The shape of the input: `identity_principals_malformed`, `identity_act_malformed`, `identity_grant_chain_empty`,
   `identity_grant_chain_malformed`, `identity_digest_malformed`.

`stamp_digest` takes digests only: an argument that is not a digest (or null where null is allowed) is
`identity_digest_malformed`. `grant_chain_digest` checks the links' shape and then each body's grant digest; a body
with no canonical form is `identity_grant_chain_malformed`.

## Where each digest is carried

- A tool-call record's `principals` member: `principals_digest` names it.
- A canonical identity string (`probity_records.canonical_identity`): `act=` is `act_chain_digest`,
  `grants=` is `grant_chain_digest`.
- An agent stamp on an upstream request and a permit at an agent hop: `principals_digest`, `act_chain_digest`,
  `grant_chain_digest`, and `stamp_digest` for what crosses the hop.

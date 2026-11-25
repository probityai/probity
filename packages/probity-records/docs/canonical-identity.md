# The canonical identity string, version 1

One deterministic string for the verified identity of one request, so that every access list and every policy engine
compares the same value. The Python reader is `probity_records.canonical_identity`, the TypeScript reader is
`canonicalIdentity.ts` in `node/probity-records-verify`, and both are held to the shared vectors in
`vectors/shared/canonical_identity.json`.

## Why a request needs one

A credential names a subject. A request made by an agent has several principals at once: the user it acts for, the
agent that acted, the agents that delegated to it, the person accountable for it, and perhaps the person who approved
the call. An access list made before agents existed lists users. If an agent's request is reduced to its user's
subject, the agent inherits every entry of that user. If it is reduced to the agent's subject, the user's own limits
are lost. And when the agent's credential is missing, a reader that treats "no agent" as "the user acted alone" grants
the user's entries to whoever stripped the agent. The string below names every principal, says which kind of actor
acted, and is built so that a reader that does not understand it refuses it instead of matching it.

## Grammar

```
identity    = "aid1!" kind *( ";" attribute )
kind        = "human-attested" / "agent" / "unknown" / "transport"
attribute   = "user=" ref
            / "chain=" ref *( ">" ref )
            / "sponsor=" ref *( "+" ref )
            / "approver=" ref / "service=" ref
            / "evidence=" ( "presence" / "approval" ) ":" digest
            / "act=" digest / "grants=" digest
ref         = type ":" env "/" domain "/" subject
type        = "user" / "agent" / "service" / "sponsor" / "approver"
env         = lowercase letter or digit, then up to 30 of letter, digit or "-", then a letter or digit
domain      = component                            ; the pinned trust root's identifier
subject     = component                            ; the subject within that trust root
component   = 1*( unreserved / pct-encoded )
unreserved  = ALPHA / DIGIT / "-" / "." / "_" / "~"   ; RFC 3986 section 2.3
pct-encoded = "%" UPHEX UPHEX                      ; one UTF-8 octet, uppercase hex
digest      = "sha256:" 64( DIGIT / %x61-66 )      ; lowercase hex
```

## Rules

1. **Critical marker.** Every identity starts with `aid1!`. The `!` makes the version critical: a reader that does not
   implement version 1 refuses the string. No identity is a bare `ref`, so an access-list entry
   `user:prod/<issuer>/alice` never equals, and is never a prefix of, the identity of an agent acting for alice.
2. **The actor kind is explicit.** `agent`: an agent acted, and `chain` names it. `human-attested`: a human acted, and
   `evidence` names what established it, either a fresh user-presence proof (`presence`) or the approval bound to this
   request (`approval`, which needs `approver`). `unknown`: the actor could not be established, which is what a lost
   or stripped agent credential produces. The absence of an agent never means a human acted. `transport`: the identity
   of the channel (a mutual-TLS peer), carried in `service`, beside the request identity.
3. **The plain user form is rendered only for `human-attested`.** That is the bare user `ref`, the value an access list
   made before agents names. Every other kind is looked up by its full string, which no such entry equals.
4. **Strict refuses `unknown`.** The basic profile admits it, so a reader can record it, and a policy still cannot
   match it to a user's entries.
5. **Typed refs.** Each principal is written with its type, and the type must agree with its slot: `user` carries a
   `user` ref, `chain` only `agent` refs, `sponsor` a `sponsor` ref, `approver` an `approver` ref, `service` a `service`
   ref.
6. **Scoped refs.** A subject is unique only within its trust root, and one trust root can serve several
   environments, so a ref names the environment, the identifier of the trust root the verifier pinned (an issuer URL,
   a SPIFFE trust domain) and the subject. The same name under two issuers, or in two environments, is two identities.
7. **The chain is ordered and complete.** It lists the agents of the delegation path, root first, the agent that acted
   last, so a sub-agent's identity always shows its parent. At most 32 agents, none twice.
8. **Every sponsor is named, in one order.** An agent can be answered for by several sponsors, and `sponsor` lists each
   of them, joined by `+`, sorted by the octets of each rendered ref, none twice. A reader refuses an unsorted list
   (`identity_sponsor_order`) and a repeated sponsor (`identity_sponsor_repeated`), so one set of sponsors has one
   written form. A reader checks every entry: a rule that denies one sponsor fires whatever other sponsors the
   identity also names. An identity with one sponsor is written exactly as it was before the list, so its string, and
   every access-list entry naming it, is unchanged.
9. **Digests bind what the string summarises.** `act` is the SHA-256 of the RFC 8785 bytes of the RFC 8693 `act` claim
   in the user's credential, as its identity provider signed it; it requires `user`. `grants` is the SHA-256 of the
   RFC 8785 bytes of the capability grant chain the request ran under, root first.
10. **Which attributes each kind carries.**

    | attribute | human-attested | agent | unknown | transport |
    |---|---|---|---|---|
    | user | required | optional | required | no |
    | chain | no | required | no | no |
    | sponsor | no | optional (required when there is no user) | no | no |
    | approver | optional (required by approval evidence) | optional | no | no |
    | service | no | no | no | required |
    | evidence | required | no | no | no |
    | act | no | optional | no | no |
    | grants | optional | optional | no | no |

11. **One written form.** Attributes appear in the order of the grammar, each at most once. Every octet of a domain or
    subject that is not unreserved is written `%XX` with uppercase hex, and an unreserved octet never is. A reader
    refuses lowercase hex, an encoded unreserved octet, a raw reserved octet, an encoding that is not UTF-8, an unknown
    or empty attribute, and any attribute out of order. So two strings name the same identity exactly when they are
    byte-equal, and `render(parse(s)) == s` for every accepted `s`.
12. **Size and characters.** At most 8192 octets, all printable ASCII, with no quote, backslash, space or comma, so the
    string goes into a JSON string, a Rego or Cedar string literal or a CSV cell unescaped.

An unknown attribute is refused, never skipped: a reader that dropped an attribute it did not know would merge two
identities, and for an access list that grants one the other's entries.

## The structured form

`document()` gives the same identity as JSON: `id` (the canonical string), `version` (1), `kind`, and each attribute
present. A ref is `{"id", "type", "environment", "domain", "subject"}`, `chain` and `sponsor` are non-empty lists of
refs (`sponsor` sorted as in rule 8, even when it holds one ref), `evidence` is `{"method", "digest"}`, and an absent
attribute is omitted, never null. In Python and TypeScript the attribute is `sponsors`, a tuple or array that is empty
when no sponsor answers for the agent. A document whose `id` is not the render of its
own parts is refused, so an engine that compares the id and one that reads the parts cannot disagree about who acted.

## Using it in a policy engine

- **Access lists.** Look up `acl_key()`: the plain user ref for a human-attested identity, the full string otherwise.
  An entry for an agent acting for a user is written as that full string, or as a rule over the structured form.
- **OpenID AuthZEN 1.0.** The subject of an Access Evaluation request is `{"type": "identity", "id": <canonical
  string>, "properties": <structured form>}`. The `id` is scoped to the type, as section 5.1 requires.
- **OPA.** Put the structured forms in the input document; a Rego rule tests `input.identity.kind == "agent"` and the
  refs it needs. A rule over sponsors iterates the list, `some s in input.identity.sponsor`, so a deny on one sponsor
  fires whichever others are named.
- **Cedar.** The principal is the entity whose id is the canonical string, with the structured form's members as
  record attributes; an absent member is omitted, and a policy tests it with `has`.

When a request has a transport identity, decide on both identities and allow only when both are allowed.

## Refusal codes

`identity_string_malformed`, `identity_version_unknown`, `identity_kind_unknown`, `identity_attribute_unknown`,
`identity_attribute_order`, `identity_attribute_empty`, `identity_attribute_missing`, `identity_attribute_not_allowed`,
`identity_ref_malformed`, `identity_ref_type_unknown`, `identity_ref_type_mismatch`, `identity_environment_malformed`,
`identity_component_not_canonical`, `identity_value_not_utf8`, `identity_digest_malformed`, `identity_evidence_malformed`,
`identity_chain_malformed`, `identity_chain_repeats_agent`, `identity_chain_too_deep`, `identity_sponsor_malformed`,
`identity_sponsor_order`, `identity_sponsor_repeated`, `identity_too_long`,
`identity_string_not_canonical`, `identity_document_malformed`, `identity_document_id_mismatch`,
`identity_not_human_attested`, `identity_actor_unknown` and `identity_profile_unknown`.

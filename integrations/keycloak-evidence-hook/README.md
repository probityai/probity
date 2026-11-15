# keycloak-evidence-hook

A Keycloak event listener that writes a signed receipt for every token exchange, client credentials grant and CIBA grant, so anyone holding the realm's recorder key can check offline which client got which token for whom.

It's for teams that broker agent and service identity through Keycloak and need grant records an auditor or a relying party can verify without trusting the server's logs.

## Install

Build the provider jar (needs Docker; Maven runs in an image pinned by digest, and every fetched artifact is checked against `maven.lock`):

```sh
integrations/keycloak-evidence-hook/build.sh
```

Copy `target/keycloak-evidence-hook-0.1.0.jar` into `/opt/keycloak/providers/`, give Keycloak an Ed25519 key pair, and start it with:

```sh
openssl genpkey -algorithm ed25519 -out recorder.pem
openssl pkey -in recorder.pem -pubout -out recorder.pub.pem
kc.sh start \
  --spi-events-listener--evidence-hook--signing-key-file=/etc/evidence/recorder.pem \
  --spi-events-listener--evidence-hook--public-key-file=/etc/evidence/recorder.pub.pem \
  --spi-events-listener--evidence-hook--sink-file=/var/lib/evidence/receipts.jsonl
```

Then add `evidence-hook` to the realm's event listeners (Realm settings, Events, Event listeners).

## What a receipt looks like

Each line of `receipts.jsonl` is a DSSE envelope over an in-toto Statement of type `https://w3id.org/agent-evidence/predicate/v1/token-grant-receipt`. Decoded, a token exchange reads:

```json
{"subject": [{"name": "access-token-id", "digest": {"sha256": "<sha256 of the issued jti>"}}],
 "predicate": {"grantType": "urn:ietf:params:oauth:grant-type:token-exchange",
   "actor": {"clientId": "agent-gateway", "authMethod": "client-secret"},
   "subject": {"userId": "<keycloak user id>"},
   "subjectToken": {"sha256": "<sha256 of the presented token>", "issuedTo": "agent-ui"},
   "audience": ["tools-api"], "scope": ["tools:execute", "tools:read"],
   "chain": {"stream": "node-1", "index": 0, "previous": null}, "...": "..."}}
```

No token value is written: tokens appear only as SHA-256 digests.

## Check a receipt offline

```sh
pip install agent-evidence-verify
agent-evidence-verify case.json --policy policy.json --json
```

The `token_grant_receipt/v1` claim type checks the signature under the key you pin, the receipt's shape, an optional whole log's hash chain, and each value you expect (issuer, grant type, client, token digest, user, audience, allowed scope). The [end-to-end run](e2e/RUN-LOG.md) writes real receipts from Keycloak 26.4.7 and checks them.

## Status

Version 0.1.0, tested against Keycloak 26.4.7. The claim type ships in the next agent-evidence-verify release.

## Documentation

| page | read it for |
| --- | --- |
| [Design](docs/design.md) | what is recorded and why, key custody, the chain, and what a receipt does not prove |
| [End-to-end run](e2e/RUN-LOG.md) | the recorded run: three grants, six checks |
| [Claim type](../../packages/agent-evidence-verify/docs/token-grant-receipt.md) | the verifier's inputs, decisions and reasons |

# Keycloak quickstart

Start Keycloak in a container, get a client-credentials token for an agent, record one agent action, and check that the signed record names the principal behind it: the token's issuer, subject, client id, key id and RFC 7638 key thumbprint.

It is for teams that run agents behind Keycloak and want a record a reviewer can check without trusting the agent, the logs or the realm's admin console. It needs no account anywhere.

## Run it

You need Docker, OpenSSL, curl and [uv](https://docs.astral.sh/uv/). Clone at the release tag and run the script:

```sh
git clone --branch keycloak-quickstart--v0.1.0 https://github.com/probityai/probity
bash probity/examples/keycloak-quickstart/run.sh
```

The Python side is pinned in `pyproject.toml` and `uv.lock`: `agent-evidence-vectors` for the record format and `probity-verify` for the check. The Keycloak image is pinned by digest in `run.sh`.

## What it prints

<!-- EXPECTED-OUTPUT -->

## What the steps do

1. Make a throwaway certificate, so the issuer is an `https` URL, as the record format requires.
2. Start Keycloak 26.8.2 with a `probity-demo` realm that holds one confidential client, `reconciler`, with a service account and an audience of `mcp://files`.
3. Ask the token endpoint for a client-credentials token with the client secret.
4. Check the token's signature against the realm's JWKS and read its claims into the record's `principal` member.
5. Append one line to a ledger file as the agent's action, and seal an audit record about that write. The record binds the token's digest to the agent, so the principal cannot be swapped for another token's.
6. Check the record with `probity-verify`: it is accepted. Swap the thumbprint for another realm key's, re-seal it, and check again: it is refused as `principal-thumbprint-mismatch`.

## What a pass means

`supported` means the record is well formed, its signature is the observer's, and its principal agrees with the rest of the record: the token digest is the agent's credential digest, the thumbprint recomputes from the key, and the assertion was valid when the decision was reported. It does not say the realm is trustworthy or that the key belongs to the realm: the consumer pins the issuer's JWKS and the observer's public key. The observer here is this script with a throwaway key, so the posture and evaluation members are fixtures.

## Status

Version 0.1.0. CI runs the unit tests and this script against a Keycloak container on every change. The Auth0, Okta and Entra pages follow.

## Files

| file | what it holds |
| --- | --- |
| [run.sh](run.sh) | the whole run |
| [realm/probity-demo.json](realm/probity-demo.json) | the realm Keycloak imports |
| [src/keycloak_quickstart/principal.py](src/keycloak_quickstart/principal.py) | token to `principal` member |
| [src/keycloak_quickstart/record.py](src/keycloak_quickstart/record.py) | the action and the sealed record |
| [expected-output.txt](expected-output.txt) | a recorded run |

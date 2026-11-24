# Release @probityai/records-verify

The package is the TypeScript twin of the `probity-records` verifier. It is published to npm by
`.github/workflows/release-npm.yml`, separately from the PyPI releases in `release.yml`.

## Cut a release

1. Set `version` in `package.json` (and `package-lock.json`) and land it on `main`.
2. Create a non-prerelease GitHub release tagged `records-verify-v<version>` on that commit of `main`.
3. The workflow checks that the tag matches `package.json`, runs `npm ci` and `node --test test/*.test.ts`, then runs
   `npm publish --access public --provenance` in the `npm` environment. The environment holds the `NPM_TOKEN`
   secret and allows only tags that match `records-verify-v*`.
4. The last step reads the version back with `npm view @probityai/records-verify version`. A release whose version is
   already on npm publishes nothing and ends green.

`prepack` builds `dist/` from `src/` with `scripts/build.mjs`, so a packed tarball holds plain JavaScript.

## Publish by hand

When the workflow cannot run, publish from this directory with an automation token passed through the environment,
never written to a file:

```sh
npm ci && node --test test/*.test.ts
NODE_AUTH_TOKEN="$token" npm publish --access public
npm view @probityai/records-verify version
```

`release.yml` skips every tag that starts with `records-verify-v`, so this prefix never reaches the PyPI resolver.

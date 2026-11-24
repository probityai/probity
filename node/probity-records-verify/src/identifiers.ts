// The one host constant behind every identifier this package writes, and the two spellings it reads as ours.
//
// A signed record cannot be edited without breaking its signature, so every record already issued keeps the
// identifiers it was signed with, under `https://probityai.github.io/`, forever. From the release that flips
// `IDENTIFIER_HOST`, new records carry `https://probityai.org/`. Both hosts are ours: GitHub serves the old one for
// the probityai organisation and forwards every path on it to the same path on the new one, which is verified for
// that organisation. So the two spellings name one type, and a verifier that accepted only one would reject either
// every record already issued or every record issued from now on. Accepting both widens nothing an attacker
// controls: an identifier is a label, not a credential, and trust comes from the signature and the key, which this
// code does not change. The match is byte-exact on the scheme and the host; no other spelling is recognised.
//
// The rule, shared with the Python and Go twins:
//   - `IDENTIFIER_HOST` is the host every identifier we WRITE uses.
//   - `RECOGNISED_HOSTS` are the hosts whose identifiers we READ as ours.
//   - `canonicalIdentifier(s)` maps a recognised spelling to the `IDENTIFIER_HOST` spelling and returns anything
//     else unchanged. A verdict or receipt keeps the record's own bytes; only the comparison is canonical.

/** The host every identifier we write uses. */
export const IDENTIFIER_HOST = "probityai.github.io";

/** The hosts whose identifiers we read as ours. */
export const RECOGNISED_HOSTS: readonly string[] = ["probityai.github.io", "probityai.org"];

/** `https://<IDENTIFIER_HOST>/<path>`: constants are built through it, so a host change is one line. */
export function identifier(path: string): string {
  return `https://${IDENTIFIER_HOST}/${path}`;
}

/**
 * When `s` is a string starting with exactly `https://<h>/` for a host `h` in RECOGNISED_HOSTS, the same string
 * under `https://<IDENTIFIER_HOST>/`, the rest unchanged. Anything else, a non-string included, comes back unchanged:
 * `http://`, `www.`, a port, a trailing dot, upper case, userinfo and a longer host name stay unrecognised.
 */
export function canonicalIdentifier<T>(s: T): T | string {
  if (typeof s !== "string") return s;
  for (const host of RECOGNISED_HOSTS) {
    const prefix = `https://${host}/`;
    if (s.startsWith(prefix)) return `https://${IDENTIFIER_HOST}/${s.slice(prefix.length)}`;
  }
  return s;
}

/** True when `a` and `b` name one identifier under either recognised spelling. */
export function sameIdentifier(a: unknown, b: unknown): boolean {
  return canonicalIdentifier(a) === canonicalIdentifier(b);
}

// Build dist/ for publishing: Node refuses to run TypeScript that sits under node_modules, so the
// published package ships plain JavaScript made by Node's own type stripper (no extra dependency).
import { stripTypeScriptTypes } from "node:module";
import { chmodSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
mkdirSync(join(root, "dist"), { recursive: true });
for (const name of ["verify", "identifiers", "identity", "sf", "x509", "verified", "revocation", "delegation", "corpus", "webbotauth", "cli"]) {
  const source = readFileSync(join(root, "src", `${name}.ts`), "utf8");
  const code = stripTypeScriptTypes(source, { mode: "strip" }).replace(/(from\s+")(\.\/[a-z]+)\.ts(")/g, "$1$2.js$3");
  const out = join(root, "dist", `${name}.js`);
  writeFileSync(out, code);
  if (name === "cli") chmodSync(out, 0o755);
}

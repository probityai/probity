"""Build discovery recipes from real adapters and checked sample decisions."""

from __future__ import annotations

import argparse
import hashlib
import json
import tomllib
from pathlib import Path

from probity_verify.cli import _load
from probity_verify.core import ADAPTERS, adjudicate

ROOT = Path(__file__).resolve().parents[1]
REGENERATE = "uv run --directory packages/probity-verify python scripts/build-recipes.py"

# The manifest keys that decide what `pip install .` puts on disk and what the
# recipe's `probity-verify` command runs against. Optional extras, project URLs,
# descriptive text and tool settings for tests or linters do not reach a recipe's
# decision, so a change to them (a dependency-bot bump of the `a2a` extra, say)
# leaves the index true and must not make it stale.
PACKAGE_KEYS = (
    ("build-system",),
    ("project", "name"),
    ("project", "version"),
    ("project", "requires-python"),
    ("project", "dependencies"),
    ("project", "scripts"),
    ("tool", "setuptools"),
)


def released_version() -> str:
    """The published version, from docs/release.json, the one record of the release."""
    return json.loads((ROOT / "docs/release.json").read_text(encoding="utf-8"))["version"]


def local_file(root: Path, name: str) -> Path:
    path = (root / name).resolve()
    if Path(name).is_absolute() or not path.is_relative_to(root.resolve()):
        raise ValueError(f"recipe path escapes the repository: {name}")
    if not path.is_file():
        raise ValueError(f"recipe file is missing: {name}")
    return path


def binding(root: Path, path: Path) -> dict:
    raw = path.read_bytes()
    return {"path": path.relative_to(root).as_posix(), "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest()}


def package_binding(root: Path) -> dict:
    """Bind the install-relevant keys of the package manifest, not its raw bytes."""
    path = local_file(root, "pyproject.toml")
    manifest = tomllib.loads(path.read_text(encoding="utf-8"))
    values = {}
    for key in PACKAGE_KEYS:
        node = manifest
        for part in key:
            if not isinstance(node, dict) or part not in node:
                raise ValueError(f"package manifest lacks {'.'.join(key)}")
            node = node[part]
        values[".".join(key)] = node
    canonical = json.dumps(values, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("ascii")
    return {"path": "pyproject.toml", "scope": "install-relevant keys",
            "values": values, "sha256": hashlib.sha256(canonical).hexdigest()}


def build(root: Path, source: dict) -> dict:
    recipes = source["recipes"]
    claims = {recipe["claim_type"] for recipe in recipes}
    if claims != set(ADAPTERS):
        raise ValueError("recipe coverage does not match registered adapters")
    result = []
    seen = set()
    for recipe in recipes:
        pair = (recipe["case"], recipe["policy"])
        if pair in seen:
            raise ValueError(f"duplicate case and policy: {pair}")
        seen.add(pair)
        case_path = local_file(root, recipe["case"])
        policy_path = local_file(root, recipe["policy"])
        local_file(root, recipe["documentation"])
        case = _load(case_path)
        policy = _load(policy_path)
        decision = adjudicate(case, policy, case_path.parent)
        if decision["claim_type"] != recipe["claim_type"]:
            raise ValueError(f"recipe claim differs from consumer policy: {pair}")
        if decision["decision"] != recipe["expected_decision"]:
            raise ValueError(f"recipe decision changed: {pair}")
        files = [case_path, policy_path]
        for artifact in case["artifacts"].values():
            name = (case_path.parent / artifact["path"]).relative_to(root).as_posix()
            files.append(local_file(root, name))
        result.append({**recipe, "case_id": decision["case_id"],
                       "expected_reason": decision["reason"], "exit_code": 0,
                       "argv": ["probity-verify", recipe["case"], "--policy",
                                recipe["policy"], "--json"],
                       "bindings": [binding(root, path) for path in files]})
    return {
        "schema_version": "probity-recipes/v2",
        "schema_scope": "Project recipe convention; not a discovery standard.",
        "repository": "https://github.com/probityai/probity/tree/main/packages/probity-verify",
        "distribution": {"name": "probity-verify", "status": "published",
                         "installation": "docs/install.md", "python": ">=3.11"},
        "fixture_scope": "source-checkout",
        "operator": "author-run synthetic fixtures",
        "error_behavior": {"exit_code": 2, "verdict": False},
        "package_metadata": package_binding(root),
        "implementation": [binding(root, path) for path in
                           sorted((root / "src/probity_verify").rglob("*.py"))],
        "recipes": result,
    }



def render_tasks(result: dict) -> bytes:
    lines = [
        "# Choose a claim check", "",
        "Choose a task, then install the same source snapshot as its recipe index in a [separate environment](install.md#use-this-checkouts-recipe-index).",
        "All examples are authored synthetic records. They do not establish independent operation or live framework execution.", "",
        "| Task | Claim type | Expected decision | Scope |",
        "| --- | --- | --- | --- |",
    ]
    for recipe in result["recipes"]:
        lines.append(f"| [{recipe['task']}]({Path(recipe['documentation']).name}) | "
                     f"`{recipe['claim_type']}` | `{recipe['expected_decision']}` | {recipe['scope']} |")
    lines.extend([
        "", "## Retrieve a command", "",
        "The [JSON recipe index](recipes.json) gives complete case and policy paths, argument arrays, expected reasons and digests.",
        "Every recipe uses the `probity-verify` distribution and CLI. These source-checkout fixtures need no extra framework package.",
        "`probity-recipes/v2` is a project convention, not a discovery standard.", "",
        "The JSON `distribution.status` describes package-name availability: `probity-verify` has a public PyPI release.",
        "It does not assert that the source candidate bound by `package_metadata` has been uploaded.",
        "The separate `fixture_scope` describes where the indexed case and policy files live.", "",
        f"The [pinned registry recipe](install.md#install-the-published-package) pairs version {released_version()} with the sample inputs its wheel carries.",
        "For this index, install its own checkout, then use the index's `argv` from that checkout root.",
        "Replace its first argument with your installed executable's path when the environment is separate.",
        "The index binds its inputs and implementation to exact bytes.",
        "From the package manifest it binds only the keys that decide the installed command: the build system, name, version, Python requirement, runtime dependencies, scripts and setuptools layout.",
        "Optional extras, URLs, descriptive text and test or lint settings do not reach a recipe decision and are not bound.",
        "Use the index with the source snapshot from which it was generated; a later index may describe newer examples.", "",
        "All valid decisions exit zero. Malformed inputs exit two without a verdict.",
        "Select your own consumer policy for actual evidence. An example policy is not an authority choice for your deployment.", "",
        "## Maintain the index", "",
        "Edit task text and expected decisions in [recipe-source.json](recipe-source.json).",
        f"From the repository root, run `{REGENERATE}` to regenerate both this page and the JSON index.",
        "CI runs the same script with `--check`. When it fails, it names each changed binding and prints that command.", "",
        "The generator runs actual registered adapters against pinned artifacts.",
        "It refuses an unexpected decision, an incorrect claim, an escaped path or a missing adapter recipe.",
        "CI checks exact generated bytes. Changed code or inputs need a new reviewed index. Keep source fixtures immutable.", "",
    ])
    return "\n".join(lines).encode("ascii")


def changed_bindings(root: Path, result: dict) -> list[str]:
    """Name each binding whose digest differs from the committed index."""
    try:
        committed = json.loads((root / "docs/recipes.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ["docs/recipes.json (missing or unreadable)"]

    def digests(index: dict) -> dict:
        found = {}
        metadata = index.get("package_metadata") or {}
        found[f"{metadata.get('path', 'pyproject.toml')} (install-relevant keys)"] = metadata.get("sha256")
        for item in index.get("implementation", []):
            found[item["path"]] = item["sha256"]
        for recipe in index.get("recipes", []):
            for item in recipe.get("bindings", []):
                found[item["path"]] = item["sha256"]
        return found

    old, new = digests(committed), digests(result)
    names = sorted(name for name in old.keys() | new.keys() if old.get(name) != new.get(name))
    return names or ["recipe text or task page (no digest changed)"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    try:
        source = _load(ROOT / "docs/recipe-source.json")
        result = build(ROOT, source)
    except (ValueError, OSError, KeyError, TypeError) as exc:
        parser.exit(2, f"build-recipes: {exc}\n")
    raw = (json.dumps(result, indent=2, ensure_ascii=True) + "\n").encode("ascii")
    outputs = {ROOT / "docs/recipes.json": raw,
               ROOT / "docs/recipes.md": render_tasks(result)}
    if args.check:
        stale = [output for output, content in outputs.items()
                 if not output.is_file() or output.read_bytes() != content]
        if stale:
            lines = [f"build-recipes: {', '.join(p.name for p in stale)} out of date"]
            lines += [f"  changed: {name}" for name in changed_bindings(ROOT, result)]
            lines.append(f"  regenerate from the repository root: {REGENERATE}")
            parser.exit(1, "\n".join(lines) + "\n")
    else:
        for output, content in outputs.items():
            output.write_bytes(content)
    print(f"build-recipes: {len(result['recipes'])} checked recipes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

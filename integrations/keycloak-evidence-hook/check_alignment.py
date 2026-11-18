"""Check that the hook builds and runs against one Keycloak release.

    python3 -I check_alignment.py <hook dir> <maven repository>
    python3 -I check_alignment.py --image <hook dir> <jar listing>

Every dependency the listener needs at run time (every scope but test, in the pom's own
dependencies and in its profiles) is loaded from Keycloak, never from the provider jar, so it
must be the version Keycloak ships:

- an org.keycloak artifact is at the pom's keycloak.version;
- any other artifact is at the version keycloak-parent manages for that release, read the way
  Maven reads it: keycloak-parent's own entries and its parents' first (the nearest pom wins),
  then the BOMs it imports in declaration order (the first import that manages it wins).
  keycloak-parent 26.6.3 sets jakarta.mail-api, snakeyaml, wildfly-common and postgresql
  itself, over the Quarkus BOM, and the distribution ships its versions.

The first form also holds the e2e/docker-compose.yml image tag to keycloak.version, and reads
keycloak-parent and its BOMs from the Maven repository the build just filled, so it needs no
network. A tag does not bind the digest beside it, so the second form checks what the image
holds: the listing is the jar file names under /opt/keycloak/lib/lib/{boot,main} in the pinned
image (e2e/run.sh writes it), where Keycloak names each jar <groupId>.<artifactId>-<version>.jar.

Exit 0 when everything agrees, 1 on a mismatch (one ALIGN_MISMATCH line each), and 2 when an
input is missing, unreadable or empty, which is no verdict either way.
"""

from __future__ import annotations

import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

NS = {"m": "http://maven.apache.org/POM/4.0.0"}
IMAGE = re.compile(
    r"^\s*image:\s*quay\.io/keycloak/keycloak:(?P<tag>[^@\s]+)@sha256:[0-9a-f]{64}\s*$",
    re.MULTILINE,
)
PROPERTY = re.compile(r"\$\{([^}]+)\}")
MAX_POMS = 50


class NotRun(Exception):
    """An input the check needs is missing, unreadable or empty."""


def parse(path: Path) -> ET.Element:
    try:
        return ET.parse(path).getroot()
    except (OSError, ET.ParseError) as exc:
        raise NotRun(f"{path}: {exc}") from exc


def properties(root: ET.Element) -> dict[str, str]:
    props = root.find("m:properties", NS)
    if props is None:
        return {}
    return {child.tag.split("}", 1)[1]: (child.text or "").strip() for child in props}


def resolve(value: str, props: dict[str, str]) -> str:
    for _ in range(10):
        new = PROPERTY.sub(lambda m: props.get(m.group(1), m.group(0)), value)
        if new == value:
            break
        value = new
    return value


def text(dep: ET.Element, name: str) -> str:
    node = dep.find(f"m:{name}", NS)
    return (node.text or "").strip() if node is not None else ""


def pom_path(repo: Path, group: str, artifact: str, version: str) -> Path:
    return (
        repo
        / group.replace(".", "/")
        / artifact
        / version
        / f"{artifact}-{version}.pom"
    )


def lineage(repo: Path, coords: tuple[str, str, str]) -> list[ET.Element]:
    """The pom at coords and each of its parents, nearest first, all read from repo."""
    chain = []
    while True:
        if len(chain) >= MAX_POMS:
            raise NotRun(
                f"parent chain of {':'.join(coords)} is longer than {MAX_POMS}"
            )
        root = parse(pom_path(repo, *coords))
        chain.append(root)
        parent = root.find("m:parent", NS)
        if parent is None:
            return chain
        coords = (
            text(parent, "groupId"),
            text(parent, "artifactId"),
            text(parent, "version"),
        )


def chain_properties(chain: list[ET.Element], version: str) -> dict[str, str]:
    props: dict[str, str] = {}
    for root in reversed(chain):
        props.update(properties(root))
    props.update({"project.version": version, "pom.version": version})
    return props


def own_entries(
    root: ET.Element, props: dict[str, str]
) -> tuple[dict[tuple[str, str], str | None], list[ET.Element]]:
    """The jar entries one pom manages itself, and its import entries in order.

    A pom that manages one jar twice at different versions maps it to None: the check does not
    guess which one Maven keeps.
    """
    local: dict[tuple[str, str], str | None] = {}
    imports = []
    for dep in root.findall("m:dependencyManagement/m:dependencies/m:dependency", NS):
        if text(dep, "scope") == "import":
            imports.append(dep)
        elif text(dep, "type") in ("", "jar") and not text(dep, "classifier"):
            key = (text(dep, "groupId"), text(dep, "artifactId"))
            version = resolve(text(dep, "version"), props)
            local[key] = None if key in local and local[key] != version else version
    return local, imports


def management(
    repo: Path, coords: tuple[str, str, str], seen: frozenset = frozenset()
) -> dict[tuple[str, str], str | None]:
    """(groupId, artifactId) -> version as Maven manages it for the pom at coords."""
    if coords in seen or len(seen) >= MAX_POMS:
        raise NotRun(f"BOM import cycle or depth at {':'.join(coords)}")
    chain = lineage(repo, coords)
    props = chain_properties(chain, coords[2])
    out: dict[tuple[str, str], str | None] = {}
    imports: list[ET.Element] = []
    for root in chain:
        local, more = own_entries(root, props)
        imports += more
        for key, version in local.items():
            out.setdefault(key, version)
    for dep in imports:
        bom = tuple(
            resolve(text(dep, n), props) for n in ("groupId", "artifactId", "version")
        )
        for key, version in management(repo, bom, seen | {coords}).items():
            out.setdefault(key, version)
    return out


def runtime_dependencies(pom: ET.Element) -> list[tuple[str, str, str]]:
    """(groupId, artifactId, declared version) of every non-test dependency, profiles too."""
    if pom.find("m:parent", NS) is not None:
        raise NotRun(
            "the hook pom has a parent, whose properties and management the check does not read"
        )
    props = properties(pom)
    deps = pom.findall("m:dependencies/m:dependency", NS)
    deps += pom.findall("m:profiles/m:profile/m:dependencies/m:dependency", NS)
    return [
        (
            text(dep, "groupId"),
            text(dep, "artifactId"),
            resolve(text(dep, "version"), props),
        )
        for dep in deps
        if text(dep, "scope") != "test"
    ]


def keycloak_version(pom: ET.Element, hook: Path) -> str:
    version = properties(pom).get("keycloak.version")
    if not version:
        raise NotRun(f"{hook / 'pom.xml'}: no keycloak.version property")
    return version


def compose_problems(hook: Path, version: str) -> list[str]:
    compose_path = hook / "e2e" / "docker-compose.yml"
    try:
        compose = compose_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise NotRun(f"{compose_path}: {exc}") from exc
    tags = [m.group("tag") for m in IMAGE.finditer(compose)]
    if len(tags) != 1:
        return [
            f"{compose_path.name}: expected one digest-pinned quay.io/keycloak/keycloak image, found {len(tags)}"
        ]
    if tags[0] != version:
        return [
            f"{compose_path.name}: image tag {tags[0]} != pom keycloak.version {version}"
        ]
    return []


def check(hook: Path, repo: Path) -> list[str]:
    """Return one line per mismatch; raise NotRun when an input is missing."""
    pom = parse(hook / "pom.xml")
    version = keycloak_version(pom, hook)
    problems = compose_problems(hook, version)
    managed = management(repo, ("org.keycloak", "keycloak-parent", version))
    where = f"keycloak-parent {version}"
    for group, artifact, declared in runtime_dependencies(pom):
        name = f"{group}:{artifact}"
        if group == "org.keycloak":
            if declared != version:
                problems.append(f"{name}: pom {declared} != keycloak.version {version}")
            continue
        if (group, artifact) not in managed:
            problems.append(f"{name}: not managed by {where}")
        elif managed[(group, artifact)] is None:
            problems.append(
                f"{name}: managed twice at different versions by one pom under {where}"
            )
        elif declared != managed[(group, artifact)]:
            problems.append(
                f"{name}: pom {declared} != {where} {managed[(group, artifact)]}"
            )
    return problems


def check_image(hook: Path, listing: Path) -> list[str]:
    """Return one line per runtime dependency the image does not ship at the pom's version."""
    try:
        lines = listing.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise NotRun(f"{listing}: {exc}") from exc
    jars = {
        line.strip().rsplit("/", 1)[-1]
        for line in lines
        if line.strip().endswith(".jar")
    }
    if not jars:
        raise NotRun(f"{listing}: lists no jar, so the image was not read")
    pom = parse(hook / "pom.xml")
    keycloak_version(pom, hook)
    problems = []
    for group, artifact, declared in runtime_dependencies(pom):
        if f"{group}.{artifact}-{declared}.jar" in jars:
            continue
        shipped = re.compile(re.escape(f"{group}.{artifact}-") + r"(\d[^/]*)\.jar")
        found = sorted(m.group(1) for jar in jars if (m := shipped.fullmatch(jar)))
        if found:
            problems.append(
                f"{group}:{artifact}: pom {declared}, image ships {', '.join(found)}"
            )
        else:
            problems.append(
                f"{group}:{artifact}: the image ships no {group}.{artifact} jar"
            )
    return problems


def main(argv: list[str]) -> int:
    image = bool(argv) and argv[0] == "--image"
    args = argv[1:] if image else argv
    if len(args) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        problems = (check_image if image else check)(Path(args[0]), Path(args[1]))
    except NotRun as exc:
        print(f"ALIGN_NOT_RUN {exc}", file=sys.stderr)
        return 2
    for line in problems:
        print(f"ALIGN_MISMATCH {line}", file=sys.stderr)
    if problems:
        return 1
    if image:
        print(
            "ALIGN_OK the pinned image ships every runtime dependency at the pom's version"
        )
    else:
        print(
            "ALIGN_OK pom, compose image and runtime dependencies follow one Keycloak release"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

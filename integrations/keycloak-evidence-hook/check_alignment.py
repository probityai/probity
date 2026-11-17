"""Check that the hook builds and runs against one Keycloak release.

    python3 -I check_alignment.py <hook dir> <maven repository>

Three things must agree, and each one is bumped by hand or by a separate Dependabot entry:
the pom's keycloak.version, the Keycloak image tag in e2e/docker-compose.yml, and every
provided dependency that is not a Keycloak artifact (jboss-logging, jakarta.ws.rs-api), which
must sit at the version the Quarkus BOM imported by that keycloak-parent manages, because
that is the version Keycloak loads at run time. The BOM and keycloak-parent are read from the
Maven repository the build just filled, so the check needs no network.

Exit 0 when everything agrees, 1 on a mismatch (one ALIGN_MISMATCH line each), and 2 when a
file the check reads is missing or unreadable, which is no verdict either way.
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


class NotRun(Exception):
    """A file the check needs is missing or unreadable."""


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


def managed(bom: ET.Element) -> dict[tuple[str, str], str]:
    props = properties(bom)
    out = {}
    for dep in bom.findall("m:dependencyManagement/m:dependencies/m:dependency", NS):
        out[(text(dep, "groupId"), text(dep, "artifactId"))] = resolve(
            text(dep, "version"), props
        )
    return out


def check(hook: Path, repo: Path) -> list[str]:
    """Return one line per mismatch; raise NotRun when an input is missing."""
    pom = parse(hook / "pom.xml")
    props = properties(pom)
    version = props.get("keycloak.version")
    if not version:
        raise NotRun(f"{hook / 'pom.xml'}: no keycloak.version property")
    problems = []
    compose_path = hook / "e2e" / "docker-compose.yml"
    try:
        compose = compose_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise NotRun(f"{compose_path}: {exc}") from exc
    tags = [m.group("tag") for m in IMAGE.finditer(compose)]
    if len(tags) != 1:
        problems.append(
            f"{compose_path.name}: expected one digest-pinned quay.io/keycloak/keycloak image, found {len(tags)}"
        )
    elif tags[0] != version:
        problems.append(
            f"{compose_path.name}: image tag {tags[0]} != pom keycloak.version {version}"
        )
    parent = parse(
        repo
        / "org/keycloak/keycloak-parent"
        / version
        / f"keycloak-parent-{version}.pom"
    )
    quarkus = properties(parent).get("quarkus.version")
    if not quarkus:
        raise NotRun(f"keycloak-parent {version} names no quarkus.version")
    bom = managed(
        parse(
            repo
            / "io/quarkus/platform/quarkus-bom"
            / quarkus
            / f"quarkus-bom-{quarkus}.pom"
        )
    )
    for dep in pom.findall("m:dependencies/m:dependency", NS):
        group, artifact = text(dep, "groupId"), text(dep, "artifactId")
        if text(dep, "scope") != "provided" or group == "org.keycloak":
            continue
        declared = resolve(text(dep, "version"), props)
        expected = bom.get((group, artifact))
        if expected is None:
            problems.append(f"{group}:{artifact}: not managed by quarkus-bom {quarkus}")
        elif declared != expected:
            problems.append(
                f"{group}:{artifact}: pom {declared} != quarkus-bom {quarkus} {expected}"
            )
    return problems


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        problems = check(Path(argv[0]), Path(argv[1]))
    except NotRun as exc:
        print(f"ALIGN_NOT_RUN {exc}", file=sys.stderr)
        return 2
    for line in problems:
        print(f"ALIGN_MISMATCH {line}", file=sys.stderr)
    if problems:
        return 1
    print(
        "ALIGN_OK pom, compose image and provided dependencies follow one Keycloak release"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

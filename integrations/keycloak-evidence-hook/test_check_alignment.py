"""Tests for check_alignment.py. Run: python3 -I test_check_alignment.py (e2e/run.sh does)."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location(
    "check_alignment", HERE / "check_alignment.py"
)
ca = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ca)

DIGEST = "0" * 64
POM = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <properties>
    <keycloak.version>{kv}</keycloak.version>
    <logging.version>{logging}</logging.version>
  </properties>
  <dependencies>
    <dependency><groupId>org.keycloak</groupId><artifactId>keycloak-core</artifactId>
      <version>${{keycloak.version}}</version><scope>provided</scope></dependency>
    <dependency><groupId>org.jboss.logging</groupId><artifactId>jboss-logging</artifactId>
      <version>${{logging.version}}</version><scope>provided</scope></dependency>
    <dependency><groupId>jakarta.ws.rs</groupId><artifactId>jakarta.ws.rs-api</artifactId>
      <version>{rs}</version><scope>provided</scope></dependency>
    <dependency><groupId>org.junit.jupiter</groupId><artifactId>junit-jupiter</artifactId>
      <version>5.13.4</version><scope>test</scope></dependency>
  </dependencies>
</project>
"""
PARENT = """<project xmlns="http://maven.apache.org/POM/4.0.0">
  <properties><quarkus.version>3.33.2</quarkus.version></properties>
</project>
"""
BOM = """<project xmlns="http://maven.apache.org/POM/4.0.0">
  <properties><jboss-logging.version>3.6.2.Final</jboss-logging.version></properties>
  <dependencyManagement><dependencies>
    <dependency><groupId>org.jboss.logging</groupId><artifactId>jboss-logging</artifactId>
      <version>${jboss-logging.version}</version></dependency>
    <dependency><groupId>jakarta.ws.rs</groupId><artifactId>jakarta.ws.rs-api</artifactId>
      <version>3.1.0</version></dependency>
  </dependencies></dependencyManagement>
</project>
"""


class CheckAlignment(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        root = Path(self._tmp.name)
        self.hook = root / "hook"
        self.repo = root / "m2"
        (self.hook / "e2e").mkdir(parents=True)
        self.write(kv="26.6.3", logging="3.6.2.Final", rs="3.1.0", tag="26.6.3")
        parent = (
            self.repo / "org/keycloak/keycloak-parent/26.6.3/keycloak-parent-26.6.3.pom"
        )
        parent.parent.mkdir(parents=True)
        parent.write_text(PARENT)
        bom = (
            self.repo / "io/quarkus/platform/quarkus-bom/3.33.2/quarkus-bom-3.33.2.pom"
        )
        bom.parent.mkdir(parents=True)
        bom.write_text(BOM)

    def write(
        self, *, kv: str, logging: str, rs: str, tag: str, image: str | None = None
    ) -> None:
        (self.hook / "pom.xml").write_text(POM.format(kv=kv, logging=logging, rs=rs))
        line = (
            image
            if image is not None
            else f"quay.io/keycloak/keycloak:{tag}@sha256:{DIGEST}"
        )
        (self.hook / "e2e/docker-compose.yml").write_text(
            f"services:\n  keycloak:\n    image: {line}\n"
        )

    def run_main(self) -> tuple[int, str]:
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            rc = ca.main([str(self.hook), str(self.repo)])
        return rc, err.getvalue()

    def test_aligned_release_passes(self) -> None:
        self.assertEqual(ca.check(self.hook, self.repo), [])
        self.assertEqual(self.run_main()[0], 0)

    def test_compose_tag_behind_the_pom_fails(self) -> None:
        self.write(kv="26.6.3", logging="3.6.2.Final", rs="3.1.0", tag="26.4.7")
        rc, err = self.run_main()
        self.assertEqual(rc, 1)
        self.assertIn("image tag 26.4.7 != pom keycloak.version 26.6.3", err)

    def test_image_without_digest_fails(self) -> None:
        self.write(
            kv="26.6.3",
            logging="3.6.2.Final",
            rs="3.1.0",
            tag="",
            image="quay.io/keycloak/keycloak:26.6.3",
        )
        problems = ca.check(self.hook, self.repo)
        self.assertEqual(len(problems), 1)
        self.assertIn("found 0", problems[0])

    def test_provided_dependency_off_the_bom_fails(self) -> None:
        self.write(kv="26.6.3", logging="3.6.1.Final", rs="4.0.0", tag="26.6.3")
        problems = ca.check(self.hook, self.repo)
        self.assertEqual(
            problems,
            [
                "org.jboss.logging:jboss-logging: pom 3.6.1.Final != quarkus-bom 3.33.2 3.6.2.Final",
                "jakarta.ws.rs:jakarta.ws.rs-api: pom 4.0.0 != quarkus-bom 3.33.2 3.1.0",
            ],
        )

    def test_provided_dependency_the_bom_does_not_manage_fails(self) -> None:
        pom = (
            (self.hook / "pom.xml")
            .read_text()
            .replace("jakarta.ws.rs-api", "jakarta.ws.rs-other")
        )
        (self.hook / "pom.xml").write_text(pom)
        self.assertEqual(
            ca.check(self.hook, self.repo),
            ["jakarta.ws.rs:jakarta.ws.rs-other: not managed by quarkus-bom 3.33.2"],
        )

    def test_missing_keycloak_parent_is_no_verdict(self) -> None:
        self.write(kv="26.7.0", logging="3.6.2.Final", rs="3.1.0", tag="26.7.0")
        rc, err = self.run_main()
        self.assertEqual(rc, 2)
        self.assertIn("ALIGN_NOT_RUN", err)

    def test_missing_quarkus_version_is_no_verdict(self) -> None:
        (
            self.repo / "org/keycloak/keycloak-parent/26.6.3/keycloak-parent-26.6.3.pom"
        ).write_text('<project xmlns="http://maven.apache.org/POM/4.0.0"/>')
        self.assertEqual(self.run_main()[0], 2)

    def test_wrong_argument_count_is_usage(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(ca.main([]), 2)


if __name__ == "__main__":
    unittest.main()

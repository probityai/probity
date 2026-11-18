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
# keycloak-parent sets jakarta.mail-api itself, over the Quarkus BOM, as 26.6.3 does, and has
# a parent of its own, as 26.6.3 does (jboss-parent).
PARENT = """<project xmlns="http://maven.apache.org/POM/4.0.0">
  <parent><groupId>org.jboss</groupId><artifactId>jboss-parent</artifactId><version>39</version></parent>
  <properties><quarkus.version>3.33.2</quarkus.version></properties>
  <dependencyManagement><dependencies>
    <dependency><groupId>jakarta.mail</groupId><artifactId>jakarta.mail-api</artifactId>
      <version>2.1.1</version></dependency>
    <dependency><groupId>io.quarkus.platform</groupId><artifactId>quarkus-bom</artifactId>
      <version>${quarkus.version}</version><type>pom</type><scope>import</scope></dependency>
  </dependencies></dependencyManagement>
</project>
"""
JBOSS_PARENT = """<project xmlns="http://maven.apache.org/POM/4.0.0">
  <properties><mail.version>9.9.9</mail.version></properties>
  <dependencyManagement><dependencies>
    <dependency><groupId>jakarta.mail</groupId><artifactId>jakarta.mail-api</artifactId>
      <version>${mail.version}</version></dependency>
  </dependencies></dependencyManagement>
</project>
"""
BOM = """<project xmlns="http://maven.apache.org/POM/4.0.0">
  <properties><jboss-logging.version>3.6.2.Final</jboss-logging.version></properties>
  <dependencyManagement><dependencies>
    <dependency><groupId>org.jboss.logging</groupId><artifactId>jboss-logging</artifactId>
      <version>${jboss-logging.version}</version></dependency>
    <dependency><groupId>jakarta.ws.rs</groupId><artifactId>jakarta.ws.rs-api</artifactId>
      <version>3.1.0</version></dependency>
    <dependency><groupId>jakarta.ws.rs</groupId><artifactId>jakarta.ws.rs-api</artifactId>
      <version>9.0.0</version><classifier>sources</classifier></dependency>
    <dependency><groupId>org.jboss.logging</groupId><artifactId>jboss-logging</artifactId>
      <version>9.0.0</version><type>test-jar</type></dependency>
    <dependency><groupId>jakarta.mail</groupId><artifactId>jakarta.mail-api</artifactId>
      <version>2.1.5</version></dependency>
  </dependencies></dependencyManagement>
</project>
"""
# The jar names Keycloak 26.6.3 ships for the pom's runtime dependencies, as e2e/run.sh lists them.
LISTING = """/opt/keycloak/lib/lib/boot:
org.jboss.logging.jboss-logging-3.6.2.Final.jar

/opt/keycloak/lib/lib/main:
jakarta.ws.rs.jakarta.ws.rs-api-3.1.0.jar
org.keycloak.keycloak-core-26.6.3.jar
org.keycloak.keycloak-core-private-1.0.jar
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
        jboss = self.repo / "org/jboss/jboss-parent/39/jboss-parent-39.pom"
        jboss.parent.mkdir(parents=True)
        jboss.write_text(JBOSS_PARENT)
        self.listing = root / "image-jars.txt"
        self.listing.write_text(LISTING)

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

    def run_main(self, *argv: str) -> tuple[int, str]:
        err = io.StringIO()
        args = list(argv) or [str(self.hook), str(self.repo)]
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            rc = ca.main(args)
        return rc, err.getvalue()

    def add_dependency(self, xml: str, *, where: str = "  </dependencies>") -> None:
        pom = (self.hook / "pom.xml").read_text()
        assert where in pom
        (self.hook / "pom.xml").write_text(pom.replace(where, xml + "\n" + where, 1))

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
                "org.jboss.logging:jboss-logging: pom 3.6.1.Final != keycloak-parent 26.6.3 3.6.2.Final",
                "jakarta.ws.rs:jakarta.ws.rs-api: pom 4.0.0 != keycloak-parent 26.6.3 3.1.0",
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
            [
                "jakarta.ws.rs:jakarta.ws.rs-other: not managed by keycloak-parent 26.6.3"
            ],
        )

    def test_missing_keycloak_parent_is_no_verdict(self) -> None:
        self.write(kv="26.7.0", logging="3.6.2.Final", rs="3.1.0", tag="26.7.0")
        rc, err = self.run_main()
        self.assertEqual(rc, 2)
        self.assertIn("ALIGN_NOT_RUN", err)

    def test_missing_quarkus_version_is_no_verdict(self) -> None:
        parent = (
            self.repo / "org/keycloak/keycloak-parent/26.6.3/keycloak-parent-26.6.3.pom"
        )
        parent.write_text(
            PARENT.replace("<quarkus.version>3.33.2</quarkus.version>", "")
        )
        rc, err = self.run_main()
        self.assertEqual(rc, 2)
        self.assertIn("${quarkus.version}", err)

    def test_missing_parent_of_keycloak_parent_is_no_verdict(self) -> None:
        (self.repo / "org/jboss/jboss-parent/39/jboss-parent-39.pom").unlink()
        self.assertEqual(self.run_main()[0], 2)

    def test_keycloak_artifact_off_keycloak_version_fails(self) -> None:
        self.add_dependency(
            "<dependency><groupId>org.keycloak</groupId><artifactId>keycloak-common</artifactId>"
            "<version>26.4.7</version><scope>provided</scope></dependency>"
        )
        self.assertEqual(
            ca.check(self.hook, self.repo),
            ["org.keycloak:keycloak-common: pom 26.4.7 != keycloak.version 26.6.3"],
        )

    def test_every_non_test_scope_is_checked(self) -> None:
        for scope in (
            "",
            "<scope>compile</scope>",
            "<scope>runtime</scope>",
            "<scope>system</scope>",
        ):
            with self.subTest(scope=scope):
                self.write(kv="26.6.3", logging="3.6.2.Final", rs="3.1.0", tag="26.6.3")
                pom = (
                    (self.hook / "pom.xml")
                    .read_text()
                    .replace(
                        "<version>3.1.0</version><scope>provided</scope>",
                        f"<version>4.0.0</version>{scope}",
                    )
                )
                (self.hook / "pom.xml").write_text(pom)
                self.assertEqual(
                    ca.check(self.hook, self.repo),
                    [
                        "jakarta.ws.rs:jakarta.ws.rs-api: pom 4.0.0 != keycloak-parent 26.6.3 3.1.0"
                    ],
                )

    def test_profile_dependency_is_checked(self) -> None:
        pom = (
            (self.hook / "pom.xml")
            .read_text()
            .replace(
                "</dependencies>\n</project>",
                "</dependencies>\n  <profiles><profile><id>x</id><dependencies>"
                "<dependency><groupId>jakarta.ws.rs</groupId><artifactId>jakarta.ws.rs-api</artifactId>"
                "<version>4.0.0</version><scope>provided</scope></dependency>"
                "</dependencies></profile></profiles>\n</project>",
            )
        )
        (self.hook / "pom.xml").write_text(pom)
        self.assertEqual(
            ca.check(self.hook, self.repo),
            [
                "jakarta.ws.rs:jakarta.ws.rs-api: pom 4.0.0 != keycloak-parent 26.6.3 3.1.0"
            ],
        )

    def test_keycloak_parent_entry_wins_over_the_bom(self) -> None:
        # Keycloak 26.6.3 ships jakarta.mail-api 2.1.1 (its parent's), not the BOM's 2.1.5,
        # and not the 9.9.9 of the parent's parent either.
        self.add_dependency(
            "<dependency><groupId>jakarta.mail</groupId><artifactId>jakarta.mail-api</artifactId>"
            "<version>2.1.1</version><scope>provided</scope></dependency>"
        )
        self.assertEqual(ca.check(self.hook, self.repo), [])
        pom = (self.hook / "pom.xml").read_text().replace("2.1.1", "2.1.5")
        (self.hook / "pom.xml").write_text(pom)
        self.assertEqual(
            ca.check(self.hook, self.repo),
            [
                "jakarta.mail:jakarta.mail-api: pom 2.1.5 != keycloak-parent 26.6.3 2.1.1"
            ],
        )

    def test_first_import_wins(self) -> None:
        early = self.repo / "org/example/early-bom/1/early-bom-1.pom"
        early.parent.mkdir(parents=True)
        early.write_text(
            BOM.replace(
                "3.6.2.Final</jboss-logging.version>",
                "3.0.0.Final</jboss-logging.version>",
            )
        )
        parent = (
            self.repo / "org/keycloak/keycloak-parent/26.6.3/keycloak-parent-26.6.3.pom"
        )
        parent.write_text(
            PARENT.replace(
                "    <dependency><groupId>io.quarkus.platform</groupId>",
                "    <dependency><groupId>org.example</groupId><artifactId>early-bom</artifactId>"
                "<version>1</version><type>pom</type><scope>import</scope></dependency>\n"
                "    <dependency><groupId>io.quarkus.platform</groupId>",
            )
        )
        self.assertEqual(
            ca.check(self.hook, self.repo),
            [
                "org.jboss.logging:jboss-logging: pom 3.6.2.Final != keycloak-parent 26.6.3 3.0.0.Final"
            ],
        )

    def test_one_pom_managing_a_jar_twice_is_a_mismatch(self) -> None:
        bom = (
            self.repo / "io/quarkus/platform/quarkus-bom/3.33.2/quarkus-bom-3.33.2.pom"
        )
        bom.write_text(
            BOM.replace(
                "  </dependencies></dependencyManagement>",
                "    <dependency><groupId>jakarta.ws.rs</groupId><artifactId>jakarta.ws.rs-api</artifactId>"
                "<version>4.0.0</version></dependency>\n  </dependencies></dependencyManagement>",
            )
        )
        self.assertEqual(
            ca.check(self.hook, self.repo),
            [
                "jakarta.ws.rs:jakarta.ws.rs-api: managed twice at different versions by one pom under keycloak-parent 26.6.3"
            ],
        )

    def test_import_cycle_is_no_verdict(self) -> None:
        bom = (
            self.repo / "io/quarkus/platform/quarkus-bom/3.33.2/quarkus-bom-3.33.2.pom"
        )
        bom.write_text(
            BOM.replace(
                "  </dependencies></dependencyManagement>",
                "    <dependency><groupId>io.quarkus.platform</groupId><artifactId>quarkus-bom</artifactId>"
                "<version>3.33.2</version><type>pom</type><scope>import</scope></dependency>\n"
                "  </dependencies></dependencyManagement>",
            )
        )
        rc, err = self.run_main()
        self.assertEqual(rc, 2)
        self.assertIn("cycle", err)

    def test_hook_pom_with_a_parent_is_no_verdict(self) -> None:
        pom = (
            (self.hook / "pom.xml")
            .read_text()
            .replace(
                "<properties>",
                "<parent><groupId>g</groupId><artifactId>a</artifactId><version>1</version></parent>\n  <properties>",
                1,
            )
        )
        (self.hook / "pom.xml").write_text(pom)
        self.assertEqual(self.run_main()[0], 2)

    def test_image_shipping_the_pom_versions_passes(self) -> None:
        rc, err = self.run_main("--image", str(self.hook), str(self.listing))
        self.assertEqual((rc, err), (0, ""))

    def test_image_tag_over_an_older_digest_fails(self) -> None:
        # The compose tag says 26.6.3, but the digest is 26.4.7's: the jars give it away.
        self.listing.write_text(
            LISTING.replace("keycloak-core-26.6.3", "keycloak-core-26.4.7").replace(
                "3.6.2.Final", "3.6.1.Final"
            )
        )
        self.assertEqual(
            ca.check_image(self.hook, self.listing),
            [
                "org.keycloak:keycloak-core: pom 26.6.3, image ships 26.4.7",
                "org.jboss.logging:jboss-logging: pom 3.6.2.Final, image ships 3.6.1.Final",
            ],
        )
        rc, err = self.run_main("--image", str(self.hook), str(self.listing))
        self.assertEqual(rc, 1)
        self.assertIn("ALIGN_MISMATCH", err)

    def test_image_without_the_jar_fails(self) -> None:
        self.listing.write_text(
            LISTING.replace("jakarta.ws.rs.jakarta.ws.rs-api-3.1.0.jar\n", "")
        )
        self.assertEqual(
            ca.check_image(self.hook, self.listing),
            [
                "jakarta.ws.rs:jakarta.ws.rs-api: the image ships no jakarta.ws.rs.jakarta.ws.rs-api jar"
            ],
        )

    def test_empty_or_missing_listing_is_no_verdict(self) -> None:
        self.listing.write_text(
            "ls: cannot access '/opt/keycloak/lib/lib/main': No such file or directory\n"
        )
        self.assertEqual(
            self.run_main("--image", str(self.hook), str(self.listing))[0], 2
        )
        self.listing.unlink()
        self.assertEqual(
            self.run_main("--image", str(self.hook), str(self.listing))[0], 2
        )

    def test_image_form_needs_two_paths(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(ca.main(["--image", str(self.hook)]), 2)

    def test_wrong_argument_count_is_usage(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(ca.main([]), 2)


if __name__ == "__main__":
    unittest.main()

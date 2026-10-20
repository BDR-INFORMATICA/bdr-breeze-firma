"""BDR Group. Comprueba edicion y publicador sin servicios externos."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]
IDENTITY = "Developer ID Installer: BDR Group (ABCDEFGHIJ)"


class ManifestTests(unittest.TestCase):
    def run_builder(self, attestation=None, dry=False):
        source = (ROOT / ".github/workflows/sign-release.yml").read_text()
        code = source.split("      - name: Generate release artifact manifest\n", 1)[1]
        code = textwrap.dedent(code.split("python3 <<'PY'\n", 1)[1].split("          PY\n", 1)[0])
        with tempfile.TemporaryDirectory(prefix="bdr-efg-firma-") as tmp:
            work = Path(tmp)
            (work / "release-assets").mkdir()
            (work / "attest").mkdir()
            asset = "breeze-agent-darwin-arm64.pkg" if attestation else "breeze-agent-linux-amd64"
            (work / "release-assets" / asset).write_bytes(b"test payload")
            (work / "attest/mirrored.txt").write_text("" if attestation else asset + "\n")
            if attestation:
                (work / "attest/macos.tsv").write_text(asset + "\t" + attestation + "\n")
            official = work / "official.json"
            official.write_text(json.dumps({"assets": [{"name": asset, "platformTrust": "release-workflow-produced"}]}))
            env = {**os.environ, "DRY_RUN": str(dry).lower(), "WINDOWS_RAN": "false",
                   "MACOS_RAN": str(bool(attestation)).lower(), "OFFICIAL_MANIFEST_PATH": str(official),
                   "GITHUB_REPOSITORY": "BDR-INFORMATICA/bdr-breeze-firma", "SIGN_VERSION": "9.9.9",
                   "SOURCE_COMMIT": "a" * 40}
            result = subprocess.run(["python3", "-c", code], cwd=tmp, env=env, capture_output=True, text=True)
            output = work / "release-assets/release-artifact-manifest.json"
            return result, json.loads(output.read_text()) if output.exists() else None

    def test_mirrors_carry_self_host_edition(self):
        result, manifest = self.run_builder()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(manifest["assets"][0].get("edition"), "self-host")

    def test_signed_pkg_binds_verified_publisher_and_team(self):
        result, manifest = self.run_builder("macos-developer-id-notarization-required\t" + IDENTITY + "\tABCDEFGHIJ")
        self.assertEqual(result.returncode, 0, result.stderr)
        entry = manifest["assets"][0]
        self.assertEqual(entry.get("signingIdentity"), IDENTITY)
        self.assertEqual(entry.get("signingTeamId"), "ABCDEFGHIJ")
        self.assertEqual(entry.get("platformTrust"), "macos-developer-id-notarization-required")

    def test_signed_pkg_without_publisher_is_rejected(self):
        result, _ = self.run_builder("macos-developer-id-notarization-required")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("lacks publisher attestation", result.stderr)

    def test_wrong_team_is_rejected(self):
        result, _ = self.run_builder("macos-developer-id-notarization-required\t" + IDENTITY + "\tXXXXXXXXXX")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invalid macOS package signing identity", result.stderr)

    def test_dry_run_keeps_unsigned_trust(self):
        result, manifest = self.run_builder("unsigned-dry-run", dry=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(manifest["assets"][0]["platformTrust"], "none")
        self.assertEqual(manifest["assets"][0].get("edition"), "self-host")


class AttestationTests(unittest.TestCase):
    def run_attestation(self, signer=IDENTITY, status="0"):
        with tempfile.TemporaryDirectory(prefix="bdr-efg-firma-") as tmp:
            directory = Path(tmp)
            package = directory / "test.pkg"
            package.write_bytes(b"test")
            fake = directory / "pkgutil"
            fake.write_text('#!/bin/sh\nprintf "Certificate Chain:\\n  1. %s\\n" "$TEST_SIGNER"\nexit "$TEST_STATUS"\n')
            fake.chmod(0o700)
            return subprocess.run(["bash", str(ROOT / "scripts/attest-macos-pkg.sh"), str(package),
                                   "test.pkg", IDENTITY, "ABCDEFGHIJ"], capture_output=True, text=True,
                                  env={**os.environ, "PKGUTIL_BIN": str(fake), "TEST_SIGNER": signer, "TEST_STATUS": status})

    def test_verified_publisher_is_attested(self):
        result = self.run_attestation()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip().split("\t")[-2:], [IDENTITY, "ABCDEFGHIJ"])

    def test_different_publisher_is_rejected(self):
        result = self.run_attestation("Developer ID Installer: Other (ABCDEFGHIJ)")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unexpected package signing identity", result.stderr)

    def test_pkgutil_failure_is_rejected(self):
        result = self.run_attestation(status="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("pkgutil rejected package signature", result.stderr)


if __name__ == "__main__":
    unittest.main()

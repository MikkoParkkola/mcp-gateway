# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""sign-release-assets.sh fails closed.

cosign and syft are replaced by stubs on PATH. The cosign stub records each
file's SHA-256 and the signing identity in the bundle, and verify-blob checks
both, so a tampered asset, the wrong identity and the wrong issuer each make
the real script exit non-zero before its checker reports success.
"""

import os
import pathlib
import shutil
import stat
import subprocess
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).with_name("sign-release-assets.sh")
NAMES = ["mcp-gateway-linux-x86_64", "mcp-gateway-windows-x86_64.exe"]
VERSION = "4.0.0"
IDENTITY = "https://github.com/MikkoParkkola/mcp-gateway/.github/workflows/release.yml@refs/tags/v4.0.0"
ISSUER = "https://token.actions.githubusercontent.com"
SUCCESS = "binaries signed, each with an SBOM"

SYFT = """#!/usr/bin/env python3
import json, sys
out = next(a for a in sys.argv if a.startswith("spdx-json=")).split("=", 1)[1]
purls = ["pkg:cargo/mcp-gateway@4.0.0", "pkg:cargo/tokio@1.47.0"]
json.dump({"spdxVersion": "SPDX-2.3", "packages": [
    {"name": p, "externalRefs": [{"referenceType": "purl", "referenceLocator": p}]} for p in purls]},
    open(out, "w"))
"""

COSIGN = """#!/usr/bin/env python3
import hashlib, json, os, sys
args = sys.argv[1:]
verb, target = args[0], args[-1]
if os.environ.get("STUB_LOG"):
    open(os.environ["STUB_LOG"], "a").write(f"{verb} {os.path.basename(target)}\\n")
if verb == "sign-blob" and os.path.basename(target) == os.environ.get("STUB_FAIL_SIGN"):
    sys.exit(1)
bundle = args[args.index("--bundle") + 1]
digest = hashlib.sha256(open(target, "rb").read()).hexdigest()
if verb == "sign-blob":
    json.dump({"sha256": digest, "identity": os.environ["STUB_SIGNER_IDENTITY"],
               "issuer": os.environ["STUB_SIGNER_ISSUER"]}, open(bundle, "w"))
    sys.exit(0)
if verb == "verify-blob":
    b = json.load(open(bundle))
    ok = (b["sha256"] == digest
          and b["identity"] == args[args.index("--certificate-identity") + 1]
          and b["issuer"] == args[args.index("--certificate-oidc-issuer") + 1])
    if not ok:
        print("Error: none of the expected identities matched", file=sys.stderr)
    sys.exit(0 if ok else 1)
sys.exit(2)
"""

TAMPER = """#!/usr/bin/env python3
# Stands in for cosign; before verify-blob of the first binary it appends a
# byte to that file, as a swapped download would.
import os, subprocess, sys
args = sys.argv[1:]
if args[0] == "verify-blob" and args[-1] == os.environ["STUB_TAMPER"]:
    open(args[-1], "ab").write(b"x")
sys.exit(subprocess.call([os.environ["STUB_REAL_COSIGN"], *args]))
"""


def executable(path, text):
    path.write_text(text)
    path.chmod(path.stat().st_mode | stat.S_IEXEC)


class SignReleaseAssets(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = pathlib.Path(temp.name)
        self.bin = root / "bin"
        self.bin.mkdir()
        executable(self.bin / "syft", SYFT)
        executable(self.bin / "cosign-real", COSIGN)
        shutil.copy(self.bin / "cosign-real", self.bin / "cosign")
        self.assets = root / "release"
        self.assets.mkdir()
        for name in NAMES:
            (self.assets / name).write_bytes(os.urandom(64))
        # Every full signing names its documents (--doc is required); the base cases carry the man page.
        (self.assets / "mcp-gateway.1").write_text('.TH mcp-gateway 1  "mcp-gateway 4.0.0"\n.SH NAME\nx\n')

    def run_script(self, *, identity=IDENTITY, issuer=ISSUER, signer=IDENTITY, signer_issuer=ISSUER, env=None):
        environ = {
            **os.environ,
            "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}",
            "IDENTITY": identity,
            "ISSUER": issuer,
            "STUB_SIGNER_IDENTITY": signer,
            "STUB_SIGNER_ISSUER": signer_issuer,
            **(env or {}),
        }
        return subprocess.run(
            ["bash", str(SCRIPT), str(self.assets), VERSION, "--doc", "mcp-gateway.1", *NAMES],
            env=environ, capture_output=True, text=True,
        )

    def test_signs_every_asset_and_passes_the_checker(self):
        done = self.run_script()
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn(SUCCESS, done.stdout)
        for name in NAMES:
            for suffix in (".sigstore.json", ".spdx.json", ".spdx.json.sigstore.json"):
                self.assertTrue((self.assets / (name + suffix)).is_file(), name + suffix)
        self.assertTrue((self.assets / "SHA256SUMS.txt.sigstore.json").is_file())

    def test_a_tampered_asset_fails_before_the_checker(self):
        executable(self.bin / "cosign", TAMPER)
        done = self.run_script(env={
            "STUB_TAMPER": NAMES[0],
            "STUB_REAL_COSIGN": str(self.bin / "cosign-real"),
        })
        self.assertNotEqual(done.returncode, 0)
        self.assertNotIn(SUCCESS, done.stdout)
        # Refused by verify-blob, not by some earlier step.
        self.assertIn("none of the expected identities matched", done.stderr)

    def test_the_wrong_identity_fails(self):
        done = self.run_script(signer="https://github.com/someone-else/fork/.github/workflows/release.yml@refs/tags/v4.0.0")
        self.assertNotEqual(done.returncode, 0)
        self.assertNotIn(SUCCESS, done.stdout)
        # Refused by verify-blob, not by some earlier step.
        self.assertIn("none of the expected identities matched", done.stderr)

    def test_the_wrong_issuer_fails(self):
        done = self.run_script(signer_issuer="https://accounts.example.invalid")
        self.assertNotEqual(done.returncode, 0)
        self.assertNotIn(SUCCESS, done.stdout)
        # Refused by verify-blob, not by some earlier step.
        self.assertIn("none of the expected identities matched", done.stderr)

    def test_missing_identity_is_refused(self):
        done = self.run_script(identity="")
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("IDENTITY", done.stderr)



VERIFY = SCRIPT.with_name("verify-release-assets.sh")
DOCS = ["mcp-gateway.1", "NOTICE.txt"]
PAGE = '.TH mcp-gateway 1  "mcp-gateway 4.0.0"\n.SH NAME\nmcp\\-gateway\n'


class SignReleaseDocuments(SignReleaseAssets):
    """M3 (MIK-9681.CLIUX.20): sign and verify take a repeatable --doc; every document is signed, listed and verified,
    the second one as surely as the first."""

    def setUp(self):
        super().setUp()
        (self.assets / "mcp-gateway.1").write_text(PAGE)
        (self.assets / "NOTICE.txt").write_text("notice\n")
        self.log = self.assets.parent / "cosign.log"

    def run_doc_script(self, script=SCRIPT, docs=DOCS, env=None):
        argv = ["bash", str(script), str(self.assets), VERSION]
        for doc in docs:
            argv += ["--doc", doc]
        environ = {
            **os.environ,
            "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}",
            "IDENTITY": IDENTITY, "ISSUER": ISSUER,
            "STUB_SIGNER_IDENTITY": IDENTITY, "STUB_SIGNER_ISSUER": ISSUER,
            "STUB_LOG": str(self.log),
            **(env or {}),
        }
        return subprocess.run([*argv, *NAMES], env=environ, capture_output=True, text=True)

    def signed(self):
        done = self.run_doc_script()
        self.assertEqual(done.returncode, 0, done.stderr)
        self.log.write_text("")

    def test_sign_signs_and_lists_both_documents(self):
        done = self.run_doc_script()
        self.assertEqual(done.returncode, 0, done.stderr)
        sums = (self.assets / "SHA256SUMS.txt").read_text()
        log = self.log.read_text().splitlines()
        for doc in DOCS:
            self.assertTrue((self.assets / (doc + ".sigstore.json")).is_file(), doc)
            self.assertIn(f"  {doc}\n", sums)
            self.assertIn(f"sign-blob {doc}", log)
            self.assertIn(f"verify-blob {doc}", log)

    def test_sign_refuses_a_missing_or_empty_document(self):
        (self.assets / "NOTICE.txt").unlink()
        done = self.run_doc_script()
        self.assertEqual(done.returncode, 1, done.stderr)
        self.assertIn("missing or empty document: NOTICE.txt", done.stderr)
        (self.assets / "NOTICE.txt").write_text("")
        done = self.run_doc_script()
        self.assertEqual(done.returncode, 1, done.stderr)
        self.assertIn("missing or empty document: NOTICE.txt", done.stderr)

    def test_sign_fails_when_cosign_fails_on_the_page(self):
        done = self.run_doc_script(env={"STUB_FAIL_SIGN": "mcp-gateway.1"})
        self.assertNotEqual(done.returncode, 0)
        log = self.log.read_text().splitlines() if self.log.exists() else []
        self.assertEqual(log[-1:], ["sign-blob mcp-gateway.1"], done.stderr)

    def test_sign_without_doc_is_a_usage_error(self):
        done = self.run_doc_script(docs=[])
        self.assertEqual(done.returncode, 2, done.stderr)
        self.assertIn("--doc NAME", done.stderr)

    def test_sign_forwards_every_doc_to_its_own_verify(self):
        executable(self.bin / "cosign", TAMPER)
        for doc in DOCS:
            done = self.run_doc_script(env={"STUB_TAMPER": doc, "STUB_REAL_COSIGN": str(self.bin / "cosign-real")})
            self.assertNotEqual(done.returncode, 0, doc)
            self.assertIn(f"verify-release-assets: {doc}: signature check failed", done.stderr)

    def assert_verify_fails(self, name, message):
        done = self.run_doc_script(script=VERIFY)
        self.assertEqual(done.returncode, 1, f"{name}: {done.stderr}")
        self.assertIn(message, done.stdout + done.stderr, name)

    def test_verify_refuses_each_document_fault(self):
        for doc in DOCS:
            for fault in ("edited", "no bundle", "corrupted bundle", "no sums line"):
                with self.subTest(doc=doc, fault=fault):
                    self.setUp()
                    self.signed()
                    path = self.assets / doc
                    bundle = self.assets / (doc + ".sigstore.json")
                    if fault == "edited":
                        path.write_text(path.read_text() + "x\n")
                        self.assert_verify_fails(fault, f"verify-release-assets: {doc}: signature check failed")
                    elif fault == "no bundle":
                        bundle.unlink()
                        self.assert_verify_fails(fault, f"verify-release-assets: {doc}: signature check failed")
                    elif fault == "corrupted bundle":
                        bundle.write_text(bundle.read_text().replace('"sha256": "', '"sha256": "0'))
                        self.assert_verify_fails(fault, f"verify-release-assets: {doc}: signature check failed")
                    else:
                        sums = self.assets / "SHA256SUMS.txt"
                        kept = [l for l in sums.read_text().splitlines() if not l.endswith(f"  {doc}")]
                        sums.write_text("\n".join(kept) + "\n")
                        # SHA256SUMS.txt itself is re-signed so only the missing line can be the fault.
                        subprocess.run([str(self.bin / "cosign-real"), "sign-blob", "--yes", "--bundle", str(sums) + ".sigstore.json", str(sums)],
                                       env={**os.environ, "STUB_SIGNER_IDENTITY": IDENTITY, "STUB_SIGNER_ISSUER": ISSUER}, check=True)
                        self.assert_verify_fails(fault, f"SHA256SUMS.txt: does not list {doc}")

    def test_verify_refuses_the_page_carrying_the_binarys_bundle(self):
        self.signed()
        shutil.copy(self.assets / (NAMES[0] + ".sigstore.json"), self.assets / "mcp-gateway.1.sigstore.json")
        self.assert_verify_fails("swapped", "verify-release-assets: mcp-gateway.1: signature check failed")

    def test_verify_without_doc_is_a_usage_error(self):
        done = self.run_doc_script(script=VERIFY, docs=[])
        self.assertEqual(done.returncode, 2, done.stderr)
        self.assertIn("--doc NAME", done.stderr)


if __name__ == "__main__":
    unittest.main()

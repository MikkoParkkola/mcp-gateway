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
            ["bash", str(SCRIPT), str(self.assets), VERSION, *NAMES],
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


if __name__ == "__main__":
    unittest.main()

# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""publish_pinned_chart.sh never replaces a published chart version (MIK-7952).

The script runs against stub helm, docker and cosign on PATH, in a throwaway
repository holding a minimal chart. The stub registry keeps one pushed archive.
Four cases: an unpublished version is pushed; a rerun with identical bytes
passes; different contents under the version stop the run before any push; a
lookup that fails for another reason (403) stops it too.
"""

import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).resolve().with_name("publish_pinned_chart.sh")
DIGEST = "sha256:" + "1" * 64

HELM = r'''#!/usr/bin/env python3
import gzip, hashlib, io, os, pathlib, re, shutil, sys, tarfile
state = pathlib.Path(os.environ["STUB_STATE"])
pushed = state / "pushed.tgz"
args = sys.argv[1:]
def log(line):
    with open(state / "calls", "a") as f:
        f.write(line + "\n")
if args[0] == "package":
    src = pathlib.Path(args[1]); out = pathlib.Path(args[args.index("-d") + 1])
    version = re.search(r"(?m)^version: *(\S+)", (src / "Chart.yaml").read_text()).group(1)
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tar:
        for path in sorted(src.rglob("*")):
            info = tar.gettarinfo(str(path), "mcp-gateway/" + path.relative_to(src).as_posix())
            info.uid = info.gid = 0; info.uname = info.gname = ""
            tar.addfile(info, path.open("rb") if path.is_file() else None)
    out.mkdir(parents=True, exist_ok=True)
    with gzip.GzipFile(out / f"mcp-gateway-{version}.tgz", "wb", mtime=0) as gz:
        gz.write(raw.getvalue())
elif args[0] == "push":
    log("push")
    shutil.copy(args[1], pushed)
    print("Digest: sha256:" + hashlib.sha256(pushed.read_bytes()).hexdigest())
elif args[0] == "pull":
    log("pull")
    mode = os.environ.get("STUB_LOOKUP", "")
    version = args[args.index("--version") + 1]; dest = pathlib.Path(args[args.index("-d") + 1])
    if mode == "error":
        print('Error: GET "https://ghcr.io/token": response status code 403: denied', file=sys.stderr); sys.exit(1)
    if mode == "blob":
        print('Error: failed to perform "Fetch" on source: sha256:abc: not found', file=sys.stderr); sys.exit(1)
    if not pushed.exists():
        # Helm 4.3.0's wording for a tag that does not resolve.
        print(f'Error: failed to perform "FetchReference" on source: ghcr.io/mikkoparkkola/charts/mcp-gateway:{version}: not found', file=sys.stderr); sys.exit(1)
    shutil.copy(pushed, dest / f"mcp-gateway-{version}.tgz")
    print("Digest: sha256:" + hashlib.sha256(pushed.read_bytes()).hexdigest())
elif args[0] == "template":
    with tarfile.open(args[2]) as tar:
        values = tar.extractfile("mcp-gateway/values.yaml").read().decode()
    get = lambda key: re.search(rf"(?m)^  {key}: *\"?([^\"\n]*)", values).group(1)
    print(f"kind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n        - image: {get('registry')}/{get('repository')}@{get('digest')}")
else:
    sys.exit(f"stub helm: {args}")
'''


class ExistingVersion(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        self.bin = self.tmp / "bin"; self.bin.mkdir()
        self.state = self.tmp / "state"; self.state.mkdir()
        stubs = {
            "helm": HELM,
            "docker": f'#!/bin/sh\necho \'"{DIGEST}"\'\n',
            "cosign": "#!/bin/sh\nexit 0\n",
        }
        for name, body in stubs.items():
            (self.bin / name).write_text(body)
            (self.bin / name).chmod(0o755)
        self.repo = self.tmp / "repo"
        chart = self.repo / "deploy" / "helm" / "mcp-gateway"
        chart.mkdir(parents=True)
        (chart / "Chart.yaml").write_text("apiVersion: v2\nname: mcp-gateway\nversion: 0.2.0\n")
        (chart / "values.yaml").write_text(
            'image:\n  registry: ghcr.io\n  repository: mikkoparkkola/mcp-gateway\n  digest: ""\n')
        git = ["git", "-C", str(self.repo), "-c", "user.name=t", "-c", "user.email=t@t"]
        subprocess.run([*git[:3], "init", "-q"], check=True)
        subprocess.run([*git, "add", "."], check=True)
        subprocess.run([*git, "commit", "-qm", "chart"], check=True)
        self.commit = subprocess.run([*git[:3], "rev-parse", "HEAD"], check=True,
                                     capture_output=True, text=True).stdout.strip()

    def publish(self, lookup=""):
        env = {**os.environ, "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}",
               "STUB_STATE": str(self.state), "STUB_LOOKUP": lookup,
               "TAG_COMMIT": self.commit, "SIGNER_IDENTITY": "id", "SIGNER_ISSUER": "iss",
               "CHART_NOTES": str(self.tmp / "notes.md")}
        return subprocess.run(["bash", str(SCRIPT), "ghcr.io/mikkoparkkola/mcp-gateway@" + DIGEST,
                               "oci://ghcr.io/mikkoparkkola/charts"],
                              cwd=self.repo, env=env, capture_output=True, text=True)

    def pushes(self):
        calls = self.state / "calls"
        return calls.read_text().split().count("push") if calls.exists() else 0

    def test_an_unpublished_version_is_pushed(self):
        done = self.publish()
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(self.pushes(), 1)

    def test_a_rerun_with_identical_bytes_passes(self):
        self.assertEqual(self.publish().returncode, 0)
        done = self.publish()
        self.assertEqual(done.returncode, 0, done.stderr)

    def test_different_contents_under_the_version_stop_before_a_push(self):
        (self.state / "pushed.tgz").write_bytes(b"another chart")
        done = self.publish()
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("already published with other contents", done.stderr)
        self.assertEqual(self.pushes(), 0)
        self.assertEqual((self.state / "pushed.tgz").read_bytes(), b"another chart")

    def test_a_lookup_error_stops_before_a_push(self):
        for lookup in ("error", "blob"):
            with self.subTest(lookup=lookup):
                done = self.publish(lookup=lookup)
                self.assertNotEqual(done.returncode, 0)
                self.assertIn("could not tell whether chart", done.stderr)
                self.assertEqual(self.pushes(), 0)
                self.assertFalse((self.state / "pushed.tgz").exists())


if __name__ == "__main__":
    sys.exit(unittest.main())

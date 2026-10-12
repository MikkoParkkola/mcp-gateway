#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""A negated Helm guard must refuse the text it exists to reject (MIK-8333).

Under `set -euo pipefail`, `! echo "$x" | grep -q bad` passes when `bad` IS
present and `$x` outgrows the pipe buffer: `grep -q` exits on its first match,
`echo` takes SIGPIPE (141), the pipeline reports failure, and `!` turns that
into success. This runs the real `helm-chart-smoke.sh` against a stub `helm`
whose RBAC render names a ClusterRole first and then ~300 KB of padding, and
requires the script to stop at its ClusterRole guard.
"""

from __future__ import annotations

import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/dev/helm-chart-smoke.sh"

# A stub `helm` that satisfies every check before the RBAC guard. Each render
# is chosen from the arguments the smoke script passes.
STUB = r"""#!/usr/bin/env bash
args="$*"
case "$1" in lint) exit 0 ;; esac
case "$args" in
  *notanumber*|*image.bogus*) exit 1 ;;
esac
pad() { head -c 300000 /dev/zero | tr '\0' '#'; echo; }
if [[ "$args" == *rbac.create=true* && "$args" == *networkPolicy.enabled=true* ]]; then
  printf 'kind: NetworkPolicy\nkind: Role\nkind: RoleBinding\n'; exit 0
fi
if [[ "$args" == *rbac.create=true* ]]; then
  # The bad line first, so grep -q exits while `echo` is still writing the
  # padding. `rules: []` last, so the positive check before it reads to the end
  # and passes either way: the row isolates the negated guard.
  printf 'kind: ClusterRole\n'; pad; printf 'rules: []\n'; exit 0
fi
if [[ "$args" == *networkPolicy.enabled=true* ]]; then
  printf 'policyTypes: ["Ingress", "Egress"]\nport: 53\n'; exit 0
fi
# One small write (`cat` of a heredoc): the piped `grep -q` checks before the
# RBAC guard are the same bug, and a render split over several writes fails
# them at random before the row reaches the guard it tests.
cat <<'YAML'
kind: ConfigMap
kind: Deployment
kind: NetworkPolicy
kind: Service
kind: ServiceAccount
image: ghcr.io/x/mcp-gateway@sha256:0
app.kubernetes.io/instance: rel1
runAsNonRoot: true
seccompProfile:
  type: RuntimeDefault
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
drop: ["ALL"]
YAML
"""


class NegatedGuard(unittest.TestCase):
    def test_the_clusterrole_guard_refuses_a_large_render_that_names_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            helm = Path(tmp) / "helm"
            helm.write_text(STUB)
            helm.chmod(helm.stat().st_mode | stat.S_IXUSR)
            run = subprocess.run(
                ["bash", str(SCRIPT)],
                env={**os.environ, "HELM": str(helm)},
                capture_output=True,
                text=True,
                timeout=120,
            )
        out = run.stdout + run.stderr
        self.assertIn("== RBAC is least-privilege", out, "the stub did not reach the RBAC guard:\n" + out[-2000:])
        self.assertIn(
            "FAIL: chart renders a ClusterRole",
            out,
            "the ClusterRole guard passed on a render that names a ClusterRole:\n" + out[-2000:],
        )
        self.assertNotEqual(run.returncode, 0)


if __name__ == "__main__":
    unittest.main()

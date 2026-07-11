#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
set -euo pipefail

# First-use usability smoke for MIK-6552.
# Proves the supported local path is automation-first: no stdin prompts, no
# manual YAML edits, safe client-config apply, doctor JSON, and a routed tool
# call through the first-run smoke.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
bin="${MCP_GATEWAY_BIN:-$repo_root/target/debug/mcp-gateway}"

if [[ ! -x "$bin" ]]; then
  (cd "$repo_root" && cargo build --quiet --bin mcp-gateway)
fi

tmp="${MCP_GATEWAY_USABILITY_SMOKE_DIR:-$(mktemp -d)}"
work="$tmp/work"
home="$tmp/home"
mkdir -p "$work" "$home"

export MCP_GATEWAY_BIN="$bin"

python3 - "$bin" "$work" "$home" <<'PY'
import json
import os
import re
import subprocess
import sys
from pathlib import Path

bin_path, work, home = sys.argv[1:4]
work = Path(work)
home = Path(home)

env = os.environ.copy()
env["HOME"] = str(home)

prompt_patterns = [
    re.compile(pattern, re.IGNORECASE | re.MULTILINE)
    for pattern in (
        r"\bpress enter\b",
        r"\bselect one\b",
        r"\bchoose\b",
        r"\bconfirm\b.*\?",
        r"\boverwrite\b.*\?",
        r"\bcontinue\b.*\?",
        r"\by/n\b",
        r"\byes/no\b",
        r"\bpassword:\s*$",
    )
]


def run_step(name, args, timeout=60, allowed_returncodes=(0,)):
    proc = subprocess.run(
        args,
        cwd=work,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
        check=False,
    )
    output = f"{proc.stdout}\n{proc.stderr}"
    if proc.returncode not in allowed_returncodes:
        raise SystemExit(
            f"{name} failed with exit {proc.returncode}\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
        )
    for pattern in prompt_patterns:
        if pattern.search(output):
            raise SystemExit(f"{name} emitted prompt-like text matching {pattern.pattern!r}")
    return proc.stdout


init_out = run_step(
    "init",
    [bin_path, "init", "--profile", "local", "--output", "gateway.yaml"],
)
if not (work / "gateway.yaml").exists():
    raise SystemExit("init did not create gateway.yaml")
for capability in (
    work / "capabilities/knowledge/weather_current.yaml",
    work / "capabilities/knowledge/public_holidays.yaml",
):
    if not capability.exists():
        raise SystemExit(f"init did not create {capability.relative_to(work)}")
gateway_text = (work / "gateway.yaml").read_text(encoding="utf-8")
for forbidden in ("API_KEY", "docs/strategy", "docs/competitive", "protected auth material"):
    if forbidden in gateway_text:
        raise SystemExit(f"gateway.yaml contains forbidden first-run marker: {forbidden}")

claude_config = home / ".claude.json"
claude_config.write_text(
    json.dumps({"mcpServers": {"existing": {"command": "echo", "args": ["ok"]}}}),
    encoding="utf-8",
)

dry_run_out = run_step(
    "setup export dry-run",
    [bin_path, "setup", "export", "--target", "claude-code", "--dry-run", "--config", "gateway.yaml"],
)
for expected in ("Planned gateway entry", "Entry name", "Gateway endpoint"):
    if expected not in dry_run_out:
        raise SystemExit(f"dry-run did not explain {expected}")

apply_out = run_step(
    "setup export apply",
    [bin_path, "setup", "export", "--target", "claude-code", "--config", "gateway.yaml"],
)
for expected in ("backup", "rollback", "verified"):
    if expected not in apply_out.lower():
        raise SystemExit(f"setup export apply did not report {expected}")

updated = json.loads(claude_config.read_text(encoding="utf-8"))
servers = updated.get("mcpServers", {})
if "existing" not in servers or "gateway" not in servers:
    raise SystemExit("setup export did not preserve existing config and add gateway")

doctor_out = run_step(
    "doctor json",
    [bin_path, "doctor", "--config", "gateway.yaml", "--format", "json"],
    allowed_returncodes=(0, 1),
)
doctor = json.loads(doctor_out)
if doctor.get("schema_version") != "doctor.v1":
    raise SystemExit("doctor JSON schema_version is not doctor.v1")
if not doctor.get("checks"):
    raise SystemExit("doctor JSON contains no checks")

print("usability noninteractive checks passed")
print(f"init output bytes: {len(init_out)}")
PY

MCP_GATEWAY_SMOKE_DIR="$tmp/first-run" "$repo_root/scripts/dev/first-run-smoke.sh" >/dev/null

echo "usability smoke passed"
echo "workdir: $tmp"

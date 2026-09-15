#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
[[ "$(uname -s)" == Linux ]] || { echo 'Run this TLS/OIDC fixture on Linux (CI or Spark).' >&2; exit 1; }
log_dir="${MCP_GATEWAY_TASK_SDK_LOG_DIR:-$(mktemp -d "$repo_root/target-sdk-recovery.XXXXXX")}"
mkdir -p "$log_dir"
container=''
cleanup() {
  local rc=$?
  trap - EXIT
  if [[ -n "$container" ]]; then
    docker logs "$container" >"$log_dir/redis.log" 2>&1 || true
    docker stop --time 3 "$container" >"$log_dir/redis-stop.log" 2>&1 || rc=1
    if docker inspect "$container" >/dev/null 2>&1; then
      echo 'Owned Redis container was not removed.' >&2
      rc=1
    else
      echo 'owned Redis removed' >"$log_dir/redis-cleanup.log"
    fi
  fi
  echo "Evidence: $log_dir" >&2
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [[ -z "${MCP_GATEWAY_TASK_SDK_PYTHON:-}" ]]; then
  python3 -m venv "$log_dir/venv"
  "$log_dir/venv/bin/python" -m pip install --disable-pip-version-check \
    'fastmcp==4.0.3' 'fastmcp-tasks==4.0.3' 'pydocket==0.25.0'
  export MCP_GATEWAY_TASK_SDK_PYTHON="$log_dir/venv/bin/python"
fi
"$MCP_GATEWAY_TASK_SDK_PYTHON" - <<'PY'
from importlib.metadata import version
for package, expected in [('fastmcp', '4.0.3'), ('fastmcp-tasks', '4.0.3'), ('pydocket', '0.25.0')]:
    actual = version(package)
    if actual != expected:
        raise SystemExit(f'{package}: expected {expected}, found {actual}')
PY

if [[ -z "${MCP_GATEWAY_TASK_SDK_REDIS_URL:-}" ]]; then
  image='redis@sha256:ff02b58f971e7d7d156a1267e283fcbbeee91773b6aa36c49dac28ecfe28eadf'
  container="$(docker run --detach --rm --label codex.task=task-sdk-recovery \
    --publish 127.0.0.1::6379 --memory 256m --cpus 1 --pids-limit 128 \
    --tmpfs /data:rw,nosuid,nodev,size=64m "$image" \
    redis-server --save '' --appendonly no)"
  docker inspect --format '{{.Id}} {{.Image}}' "$container" >"$log_dir/redis-image.log"
  port="$(docker inspect --format '{{(index (index .NetworkSettings.Ports "6379/tcp") 0).HostPort}}' "$container")"
  export MCP_GATEWAY_TASK_SDK_REDIS_URL="redis://127.0.0.1:$port/0"
fi

python3 - <<'PY'
import os, socket, time
from urllib.parse import urlsplit
url = urlsplit(os.environ['MCP_GATEWAY_TASK_SDK_REDIS_URL'])
if url.scheme != 'redis' or url.hostname not in ('127.0.0.1', '::1') or url.username or url.password:
    raise SystemExit('The fixture requires a credential-free loopback redis:// endpoint.')
deadline = time.monotonic() + 10
while True:
    try:
        with socket.create_connection((url.hostname, url.port or 6379), timeout=1) as conn:
            conn.sendall(b'PING\r\n')
            if not conn.recv(16).startswith(b'+PONG'):
                raise OSError('Redis did not answer PONG')
        break
    except OSError:
        if time.monotonic() >= deadline:
            raise
        time.sleep(0.1)
PY

# Preserve the caller's RUSTFLAGS, including CI's -Dwarnings.
cargo test --locked --all-features --test task_upstream_recovery_sdk --jobs 1 \
  --color never -- --nocapture --test-threads 1 2>&1 | tee "$log_dir/cargo-test.log"
grep -q 'test result: ok. 1 passed; 0 failed; 0 ignored;' "$log_dir/cargo-test.log" || {
  echo 'The SDK journey must execute exactly one test, with no skips.' >&2
  exit 1
}

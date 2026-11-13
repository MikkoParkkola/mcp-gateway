#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
#
# check-unlocked-install.sh BINARY
#
# Starts BINARY with the key server enabled and passes only when it serves.
# The key server's startup runs the email-hash self-check before any key is
# read, and refuses to start when normalization no longer gives its known
# answers. Run on a binary from `cargo install` without the lock file, this is
# the check that the dependencies a user's install resolves today still give
# the frozen email hash.
set -euo pipefail

bin=${1:?usage: check-unlocked-install.sh BINARY}
dir=$(mktemp -d)
pid=
cleanup() {
  if [ -n "$pid" ]; then
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
  # The CI job uploads the log; the temp dir goes with this script.
  if [ -n "${UNLOCKED_INSTALL_LOG:-}" ] && [ -f "$dir/gateway.log" ]; then
    cp "$dir/gateway.log" "$UNLOCKED_INSTALL_LOG" || true
  fi
  rm -rf "$dir"
}
trap cleanup EXIT

home="$dir/home"
mkdir -p "$home" "$dir/state"
log="$dir/gateway.log"
config="$dir/gateway.yaml"
# The shape tests/b2_single_replica_state.rs starts: the key server needs the
# audit log, and the task store goes to the temp dir.
cat > "$config" <<EOF
server:
  host: 127.0.0.1
  port: 0
auth:
  enabled: false
key_server:
  enabled: false
security:
  transparency_log:
    enabled: true
    path: $dir/audit/transparency.jsonl
tasks:
  store_dir: $dir/tasks
EOF
chmod 600 "$config"

# An isolated home on every lookup path, so nothing reads or writes the
# runner's own; RUST_LOG keeps the info-level banner the wait reads.
HOME="$home" USERPROFILE="$home" MCP_GATEWAY_TEST_HOME_DIR="$home" \
  XDG_CONFIG_HOME="$home/.config" XDG_DATA_HOME="$home/.local/share" \
  XDG_STATE_HOME="$home/.local/state" MCP_GATEWAY_CONFIG_DIR="$dir/state" \
  RUST_LOG=info "$bin" --config "$config" < /dev/null > "$log" 2>&1 &
pid=$!

fail() {
  echo "::error::$1"
  echo "--- gateway log ---"
  cat "$log"
  exit 1
}

# The wait, in seconds (the self-test shortens it).
wait_s=${UNLOCKED_INSTALL_WAIT:-120}
deadline=$((SECONDS + wait_s))
port=
while :; do
  if ! kill -0 "$pid" 2>/dev/null; then
    status=0
    wait "$pid" || status=$?
    pid=
    fail "the installed gateway exited (status $status) before serving; a refusal by the email-hash self-check names the known answer that missed"
  fi
  # Only complete lines: a last line without its newline may be mid-write, and
  # a prefix such as `port=39` would read as a wrong port.
  if [ -n "$(tail -c 1 "$log")" ]; then
    text=$(sed '$d' "$log")
  else
    text=$(cat "$log")
  fi
  # The bound port from the `Listening` banner, colour codes removed.
  port=$(printf '%s\n' "$text" | sed -E 's/\x1b\[[0-9;]*m//g' | grep 'Listening' | grep -oE 'port=[0-9]+' | tail -n 1 | cut -d= -f2 || true)
  # Both, in one wait: serving, and the line `start_key_server` logs only after
  # `email_hash::self_check()` passed (a failing check stops the start).
  if [ -n "$port" ] &&
    grep -q 'Key server enabled' <<< "$text" &&
    curl -fsS --max-time 5 "http://127.0.0.1:$port/livez" > /dev/null 2>&1; then
    break
  fi
  if [ "$SECONDS" -ge "$deadline" ]; then
    fail "within $wait_s s the installed gateway did not both answer /livez and log that its key server started (the email-hash self-check runs only when it starts)"
  fi
  sleep 1
done

echo "ok: the installed gateway started its key server (email-hash self-check passed) and answered /livez on port $port"

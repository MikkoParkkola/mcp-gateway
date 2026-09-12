#!/usr/bin/env bash
# NFR.WORKLOAD.1 runner. Spark only; nothing here runs on the Mac.
#
# Two defects from the NFR.PERF.1 rehearsal void are fixed by construction:
#   D1  every k6 output goes to its own path. The JSON-lines stream, the text
#       summary and the summary-export never share a descriptor.
#   D4  launch argv and per-arm checkout SHA are written BEFORE the arm runs,
#       so a run that dies mid-arm still says what it was running.
#
# Usage:
#   run_workload.sh build <run-dir>
#   run_workload.sh measure <run-dir>
#   run_workload.sh all <run-dir>

set -Eeuo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"

# --- pins -------------------------------------------------------------------
# The k6 image is pinned by digest. A tag would let the load generator change
# between the reference run and the scored run, and that would be charged to
# the gateway. There is deliberately no fallback to a mutable tag.
case "${K6_IMAGE_DIGEST:-}" in
  sha256:*) ;;
  "") echo "void: K6_IMAGE_DIGEST is unset; pin a sha256: digest, never a tag" >&2; exit 3 ;;
  *) echo "void: K6_IMAGE_DIGEST must be a sha256: digest, never a tag" >&2; exit 3 ;;
esac
K6_IMAGE="grafana/k6@${K6_IMAGE_DIGEST}"

REF_A="${REF_A:-v3.5.0}"
REF_B="${REF_B:-v3.5.1}"
REF_C="${REF_C:-HEAD}"

FEATURES="a2a,webui,config-export,cost-governance,firewall,discovery,semantic-search,tool-profiles,metrics"

BACKEND_NAME="workload"
TOOL_NAME="workload_probe"
EXPECT_TEXT="WORKLOAD_OK case=042 bundle=deterministic"
LEGACY_PROTOCOL="2025-06-18"
MODERN_PROTOCOL="2026-07-28"

# cell -> ref port config client-protocol
cell_ref()    { case "$1" in A) echo "$REF_A";; B) echo "$REF_B";; *) echo "$REF_C";; esac; }
cell_port()   { case "$1" in A) echo 39420;; B) echo 39421;; C) echo 39422;; D) echo 39423;; E) echo 39424;; esac; }
# The gateway expands ${VAR} in a backend's `headers`, `env` and in
# `capabilities.directories` -- NOT in `command` (src/config/mod.rs,
# expand_env_vars). A ${WORKLOAD_FIXTURE} left in `command` would be passed to
# the shell verbatim and every cell would void at backend start. So the
# committed files are templates and the runner renders them once per run, with
# the fixture's absolute path substituted. One render is shared by A, B, C and
# D, which keeps the gating cells on a single byte-identical config file rather
# than three files argued to be equivalent.
CONFIG_DIR=""
cell_config() { case "$1" in E) echo "$CONFIG_DIR/gateway.workload.mixed.yaml";; *) echo "$CONFIG_DIR/gateway.workload.yaml";; esac; }

render_configs() {
  local run="$1"
  CONFIG_DIR="$run/config"
  mkdir -p "$CONFIG_DIR"
  local fixture="$HERE/mcp_backend.py"
  [[ -f "$fixture" ]] || die "fixture not found at $fixture"
  local name
  for name in gateway.workload.yaml gateway.workload.mixed.yaml; do
    python3 - "$HERE/$name" "$CONFIG_DIR/$name" "$fixture" <<'PY'
import sys
src, dst, fixture = sys.argv[1:4]
text = open(src).read()
if "${WORKLOAD_FIXTURE}" not in text:
    raise SystemExit(f"void: {src} has no ${{WORKLOAD_FIXTURE}} placeholder")
open(dst, "w").write(text.replace("${WORKLOAD_FIXTURE}", fixture))
PY
    sha256_of "$HERE/$name" "$CONFIG_DIR/$name" >> "$run/config.sha256"
  done
}
cell_proto()  { case "$1" in D|E) echo "$MODERN_PROTOCOL";; *) echo "$LEGACY_PROTOCOL";; esac; }

ARMS_DIR="${ARMS_DIR:-$HOME/perf-workload/arms}"

die() { echo "void: $*" >&2; exit 3; }

# Spark is Linux and has sha256sum; the fallback keeps the script runnable for
# a dry read on a Mac rather than dying on the first digest.
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"
  else shasum -a 256 "$@"; fi
}

# --- build ------------------------------------------------------------------
# --release --locked, deliberately outside CI's RUSTFLAGS: -Dwarnings. The
# binary is what is being measured, not the lint gate.
build_arm() {
  local cell="$1" ref; ref="$(cell_ref "$cell")"
  local dir="$ARMS_DIR/$cell"
  # `^{commit}` is load-bearing: v3.5.0 and v3.5.1 are ANNOTATED tags, so a bare
  # rev-parse yields the tag object (7197dbbf for v3.5.0), not the commit
  # (32f135a6) that the NFR.PERF.1 contract pins as the baseline. Recording the
  # tag object would put an identifier in .checkout_sha that matches neither the
  # sibling contract nor `git rev-parse HEAD` inside the built worktree.
  local sha; sha="$(git -C "$REPO" rev-parse "${ref}^{commit}")"

  echo "[build] cell $cell ref $ref sha $sha"
  # A rebuilt arm carries several GB of untracked target/ output, which
  # `worktree remove` refuses to delete and this repo forbids forcing past. So
  # delete the directory outright and prune the administrative entry after,
  # rather than leading with a removal that can only ever fail here.
  rm -rf "$dir"
  git -C "$REPO" worktree prune
  git -C "$REPO" worktree add --detach "$dir" "$sha" >/dev/null
  ( cd "$dir" && cargo build --release --locked --features "$FEATURES" )
  echo "$sha" > "$dir/.checkout_sha"
}

do_build() {
  mkdir -p "$ARMS_DIR"
  for cell in A B C; do build_arm "$cell"; done
  # D and E reuse the C binary; same ref, different protocol path.
  for cell in D E; do
    rm -rf "${ARMS_DIR:?}/$cell"
    ln -s "$ARMS_DIR/C" "$ARMS_DIR/$cell"
  done
}

# --- gateway lifecycle ------------------------------------------------------
GW_PID=""
GW_PORT=""

port_open() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && { exec 3>&- 2>/dev/null || true; return 0; }; return 1; }

stop_gateway() {
  if [[ -n "$GW_PID" ]] && kill -0 "$GW_PID" 2>/dev/null; then
    kill "$GW_PID" 2>/dev/null || true
    wait "$GW_PID" 2>/dev/null || true
  fi
  GW_PID=""
  # The next rep voids on any listener, so wait for this cell's port to close
  # rather than charging a lingering socket to the following arm.
  if [[ -n "${GW_PORT:-}" ]]; then
    local waited=0
    while port_open "$GW_PORT"; do
      sleep 0.2; waited=$((waited + 1))
      [[ $waited -lt 100 ]] || break
    done
    GW_PORT=""
  fi
}
trap stop_gateway EXIT

start_gateway() {
  local cell="$1" run="$2" rep="$3"
  local port config bin
  port="$(cell_port "$cell")"
  config="$(cell_config "$cell")"
  bin="$ARMS_DIR/$cell/target/release/mcp-gateway"

  [[ -x "$bin" ]] || die "$rep: no built binary at $bin"

  # One gateway at a time. A second listener on any cell port voids the run.
  local other
  for other in 39420 39421 39422 39423 39424; do
    if port_open "$other"; then
      die "$rep: port $other already has a listener"
    fi
  done

  export WORKLOAD_FIXTURE="$HERE/mcp_backend.py"
  [[ -n "$CONFIG_DIR" && -f "$config" ]] || die "$rep: config not rendered at $config"

  # argv is recorded here, before the process starts.
  GW_ARGV="$bin --config $config --port $port"
  GW_PORT="$port"
  "$bin" --config "$config" --port "$port" \
    > "$run/$rep.gateway.stdout" 2> "$run/$rep.gateway.stderr" &
  GW_PID=$!

  local waited=0
  until curl -fsS "http://127.0.0.1:$port/health" > "$run/$rep.health.json" 2>/dev/null; do
    sleep 0.2; waited=$((waited + 1))
    [[ $waited -lt 150 ]] || die "$rep: gateway did not become healthy"
    kill -0 "$GW_PID" 2>/dev/null || die "$rep: gateway exited during startup"
  done
}

# --- one rep ----------------------------------------------------------------
run_rep() {
  local cell="$1" rep="$2" run="$3" measured="$4"
  local port sha
  port="$(cell_port "$cell")"
  sha="$(cat "$ARMS_DIR/$cell/.checkout_sha")"

  start_gateway "$cell" "$run" "$rep"

  local version
  version="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("version",""))' \
    "$run/$rep.health.json")"

  # Written BEFORE k6 starts. A rep that dies mid-arm still leaves this behind.
  python3 - "$run/$rep.meta.json" "$GW_ARGV" "$sha" "$version" "$K6_IMAGE_DIGEST" "$(uptime)" <<'PY'
import json, sys
path, argv, sha, version, digest, load = sys.argv[1:7]
json.dump({
    "argv": argv.split(),
    "checkout_sha": sha,
    "health_version": version,
    "k6_image_digest": digest,
    "uptime": load,
}, open(path, "w"), indent=2)
PY

  # D1: three separate paths, no shared descriptor anywhere. The script mount
  # stays read-only; k6's own outputs go to a separate writable mount, so
  # nothing is written back into the committed harness directory and there is
  # no post-run rename to race against.
  docker run --rm --network host \
    -v "$HERE:/scripts:ro" \
    -v "$run:/out" \
    -e BASE_URL="http://127.0.0.1:$port" \
    -e BACKEND_NAME="$BACKEND_NAME" \
    -e TOOL_NAME="$TOOL_NAME" \
    -e EXPECT_TEXT="$EXPECT_TEXT" \
    -e PROTOCOL_VERSION="$(cell_proto "$cell")" \
    -e SCENARIO=load \
    "$K6_IMAGE" run \
      --summary-trend-stats="avg,min,med,p(50),p(90),p(95),p(99),max" \
      --summary-export="/out/$rep.summary.json" \
      --out "json=/out/$rep.raw.json" \
      /scripts/k6_workload.js \
      > "$run/$rep.k6.txt" 2> "$run/$rep.k6.err" || die "$rep: k6 exited non-zero"

  [[ -s "$run/$rep.summary.json" ]] || die "$rep: k6 wrote no summary export"

  stop_gateway
  [[ "$measured" == "measured" ]] || rm -f "$run/$rep.summary.json"
}

# --- schedule ---------------------------------------------------------------
do_measure() {
  local run="$1"
  mkdir -p "$run"
  render_configs "$run"

  python3 - "$run/pins.json" "$K6_IMAGE_DIGEST" \
    "$(cat "$ARMS_DIR/A/.checkout_sha")" "$(cat "$ARMS_DIR/B/.checkout_sha")" \
    "$(cat "$ARMS_DIR/C/.checkout_sha")" <<'PY'
import json, subprocess, sys
path, digest, a, b, c = sys.argv[1:6]
def ver(ref):
    out = subprocess.run(["git","show",f"{ref}:Cargo.toml"],capture_output=True,text=True).stdout
    for line in out.splitlines():
        if line.startswith("version"):
            return line.split('"')[1]
    raise SystemExit(f"could not read version at {ref}")
cells = {
    "A": {"checkout_sha": a, "health_version": ver(a)},
    "B": {"checkout_sha": b, "health_version": ver(b)},
}
for cell in ("C","D","E"):
    cells[cell] = {"checkout_sha": c, "health_version": ver(c)}
json.dump({"k6_image_digest": digest, "cells": cells}, open(path,"w"), indent=2)
PY

  # Warm-up, discarded.
  for cell in A B C; do run_rep "$cell" "${cell}0" "$run" warmup; done

  # Measured, interleaved. Spark is shared, so the arms must see the same
  # machine conditions rather than consecutive blocks of time.
  for n in 1 2 3; do
    for cell in A B C; do run_rep "$cell" "${cell}${n}" "$run" measured; done
  done

  # Report-only cells. No counterpart arm exists, so these are never compared.
  for n in 1 2 3; do
    for cell in D E; do run_rep "$cell" "${cell}${n}" "$run" measured; done
  done

  echo "[done] run dir $run"
}

# One cell, one rep, discarded. Proves the plumbing -- config render, backend
# spawn, health shape, k6 write path -- before twelve reps are spent finding out
# the same thing. Its output is never scored.
do_smoke() {
  local run="$1" cell="${2:-C}"
  mkdir -p "$run"
  render_configs "$run"
  run_rep "$cell" "smoke-$cell" "$run" warmup
  echo "[smoke] ok: cell $cell plumbing clean; see $run/smoke-$cell.health.json"
}

case "${1:-}" in
  build)   do_build ;;
  smoke)   do_smoke "${2:?run dir required}" "${3:-C}" ;;
  measure) do_measure "${2:?run dir required}" ;;
  all)     do_build; do_measure "${2:?run dir required}" ;;
  *) echo "usage: $0 {build|smoke|measure|all} <run-dir> [cell]" >&2; exit 2 ;;
esac

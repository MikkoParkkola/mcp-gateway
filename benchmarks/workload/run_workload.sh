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
cell_config() { case "$1" in E) echo "$HERE/gateway.workload.mixed.yaml";; *) echo "$HERE/gateway.workload.yaml";; esac; }
cell_proto()  { case "$1" in D|E) echo "$MODERN_PROTOCOL";; *) echo "$LEGACY_PROTOCOL";; esac; }

ARMS_DIR="${ARMS_DIR:-$HOME/perf-workload/arms}"

die() { echo "void: $*" >&2; exit 3; }

# --- build ------------------------------------------------------------------
# --release --locked, deliberately outside CI's RUSTFLAGS: -Dwarnings. The
# binary is what is being measured, not the lint gate.
build_arm() {
  local cell="$1" ref; ref="$(cell_ref "$cell")"
  local dir="$ARMS_DIR/$cell"
  local sha; sha="$(git -C "$REPO" rev-parse "$ref")"

  echo "[build] cell $cell ref $ref sha $sha"
  rm -rf "$dir"
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

stop_gateway() {
  if [[ -n "$GW_PID" ]] && kill -0 "$GW_PID" 2>/dev/null; then
    kill "$GW_PID" 2>/dev/null || true
    wait "$GW_PID" 2>/dev/null || true
  fi
  GW_PID=""
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
    if (exec 3<>"/dev/tcp/127.0.0.1/$other") 2>/dev/null; then
      exec 3>&- 2>/dev/null || true
      die "$rep: port $other already has a listener"
    fi
  done

  export WORKLOAD_FIXTURE="$HERE/mcp_backend.py"

  # argv is recorded here, before the process starts.
  GW_ARGV="$bin --config $config --port $port"
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

  # D1: three separate paths, no shared descriptor anywhere.
  docker run --rm --network host \
    -v "$HERE:/scripts:ro" \
    -e BASE_URL="http://127.0.0.1:$port" \
    -e BACKEND_NAME="$BACKEND_NAME" \
    -e TOOL_NAME="$TOOL_NAME" \
    -e EXPECT_TEXT="$EXPECT_TEXT" \
    -e PROTOCOL_VERSION="$(cell_proto "$cell")" \
    -e SCENARIO=load \
    "$K6_IMAGE" run \
      --summary-trend-stats="avg,min,med,p(50),p(90),p(95),p(99),max" \
      --summary-export="/scripts/.export.json" \
      --out "json=/scripts/.stream.json" \
      /scripts/k6_workload.js \
      > "$run/$rep.k6.txt" 2> "$run/$rep.k6.err" || die "$rep: k6 exited non-zero"

  mv "$HERE/.export.json" "$run/$rep.summary.json"
  mv "$HERE/.stream.json" "$run/$rep.raw.json"

  stop_gateway
  [[ "$measured" == "measured" ]] || rm -f "$run/$rep.summary.json"
}

# --- schedule ---------------------------------------------------------------
do_measure() {
  local run="$1"
  mkdir -p "$run"

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

case "${1:-}" in
  build)   do_build ;;
  measure) do_measure "${2:?run dir required}" ;;
  all)     do_build; do_measure "${2:?run dir required}" ;;
  *) echo "usage: $0 {build|measure|all} <run-dir>" >&2; exit 2 ;;
esac

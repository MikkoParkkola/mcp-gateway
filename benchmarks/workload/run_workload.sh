#!/usr/bin/env bash
# NFR.WORKLOAD.1 runner. bench-host only; nothing here runs on the Mac.
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

# Rendered gateway configs must be owner-only: a 4.0 gateway refuses a config
# other users can read (UPGRADING-4.0 §35), so under a 0002 umask every 4.0 arm
# dies on its first rep. The k6 container runs as this uid, so it still reads.
umask 077

HERE="$(CDPATH= cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(CDPATH= cd -- "$HERE/../.." && pwd)"

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

# The measured sample size. Six is a floor, not a default to be tuned down: a
# distribution-free 95% median interval needs n>=6 before an interval exists at
# all, so a run below it cannot certify the criterion no matter how it lands.
REPS="${WORKLOAD_REPS:-6}"
case "$REPS" in
  ''|*[!0-9]*) echo "void: WORKLOAD_REPS must be a positive integer, got '$REPS'" >&2; exit 3 ;;
esac
[[ "$REPS" -ge 6 ]] || { echo "void: WORKLOAD_REPS=$REPS is below the n>=6 median-interval floor" >&2; exit 3; }

# The cell order is drawn per rep from this seed, which is recorded in
# pins.json so the run can be reproduced by passing it back in. A run that
# picks its own order and does not say which order it picked cannot be
# replayed, and its position effects cannot be checked after the fact.
SEED="${WORKLOAD_SEED:-$(date +%s)}"
case "$SEED" in
  ''|*[!0-9]*) echo "void: WORKLOAD_SEED must be a positive integer, got '$SEED'" >&2; exit 3 ;;
esac

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

# rep number -> the cell order that rep runs, a FRESH PERMUTATION of all five
# cells, deterministic in SEED. Not a rotation: under a rotation every cyclic
# relationship is invariant -- each cell keeps the same predecessor and the
# same distance to every other cell in every rep -- so a rotation randomises
# nothing that a fixed order does not already fix. Under the old fixed order C
# sat two slots after A in EVERY rep, and each cell's ratio therefore carried
# an uncancelled position term; doubling the reps from 6 to 12 made A.p50's
# half-width worse (0.059 -> 0.073), because more sampling cannot average out a
# term that never varies. Shuffling slot and neighbour together is what makes
# the per-rep pairing mean anything.
cell_order() {
  python3 -c 'import random,sys
cells = ["A","B","C","D","E"]
random.Random(f"{sys.argv[1]}:{sys.argv[2]}").shuffle(cells)
print(" ".join(cells))' "$SEED" "$1"
}
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

# bench-host is Linux and has sha256sum; the fallback keeps the script runnable for
# a dry read on a Mac rather than dying on the first digest.
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"
  else shasum -a 256 "$@"; fi
}

# --- machine conditions -----------------------------------------------------
# bench-host is shared -- 57 other users during the 2026-09-21 run -- so a rep can
# measure the machine's run queue instead of the gateway. The 2026-09-21 run
# did exactly that: a three-minute excursion to loadavg 34 on 20 CPUs put
# tools-call p99 at 58.7ms in A2, 75.0ms in B2 and 33.9ms in C2 against a body
# of ~3ms, and lifted /health p99 from 3.1ms to 69ms in the same three reps.
# /health does no routing and no backend round-trip, so the stall is not in the
# tool path; the same binary hand-run at loadavg 34.9-51.1, with no harness
# change, then reproduced those numbers from CPU scarcity alone.
#
# `uptime` was already sampled per rep and then never read by anything. It is
# replaced here by /proc/loadavg, which is exact rather than locale-formatted
# prose, and by a sample at BOTH ends of the rep: loadavg-1 is a trailing
# exponential average, so a single reading taken before k6 starts describes the
# minute BEFORE the measured window. That lag is why A2 recorded as clean at
# 7.75 while its own window ran at 20-plus.
ncpu() { getconf _NPROCESSORS_ONLN; }
loadavg1() {
  [[ -r /proc/loadavg ]] || die "no /proc/loadavg; the runner is Linux-only"
  cut -d' ' -f1 /proc/loadavg
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
  ( CDPATH= cd -- "$dir" && cargo build --release --locked --features "$FEATURES" )
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
  # Every arm gets its own empty home. The gateway keeps a version stamp under
  # the user's home directory and compares it to its own version at startup: a
  # shared home would make 3.5.1 run upgrade migrations over the directory 3.5.0
  # just stamped, and 3.5.0 log a downgrade against 4.0.0's. Startup work and
  # on-disk state would then depend on the order the cells happened to run in.
  local gwhome="$run/home-$rep"
  rm -rf "$gwhome"; mkdir -p "$gwhome"
  # Log verbosity is pinned rather than inherited. At the default level the
  # gateway writes an audit line per invoke -- nearly nine megabytes a minute,
  # written by the very process whose latency is being measured.
  HOME="$gwhome" RUST_LOG="${WORKLOAD_RUST_LOG:-error}" \
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
  python3 - "$run/$rep.meta.json" "$GW_ARGV" "$sha" "$version" "$K6_IMAGE_DIGEST" "$(uptime)" \
    "$(loadavg1)" "$(ncpu)" <<'PY'
import json, sys
path, argv, sha, version, digest, load, load1_start, ncpu = sys.argv[1:9]
json.dump({
    "argv": argv.split(),
    "checkout_sha": sha,
    "health_version": version,
    "k6_image_digest": digest,
    "uptime": load,
    "load1_start": float(load1_start),
    "ncpu": int(ncpu),
}, open(path, "w"), indent=2)
PY

  # D1: three separate paths, no shared descriptor anywhere. The script mount
  # stays read-only; k6's own outputs go to a separate writable mount, so
  # nothing is written back into the committed harness directory and there is
  # no post-run rename to race against.
  # The image's default user is not the user that owns the run directory, so
  # without this every write to /out is refused and the load generator dies
  # during init with nothing measured.
  docker run --rm --network host \
    --user "$(id -u):$(id -g)" \
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
      /scripts/k6_workload.js \
      > "$run/$rep.k6.txt" 2> "$run/$rep.k6.err" || die "$rep: k6 exited non-zero"

  [[ -s "$run/$rep.summary.json" ]] || die "$rep: k6 wrote no summary export"

  # The closing sample. It is taken here, before the gateway is stopped, so it
  # describes the minute the measurement actually ran in. A rep that died above
  # never reaches this line and so carries no load1_end -- which the evaluator
  # reads as a rep with no valid window, not as a rep that passed.
  python3 - "$run/$rep.meta.json" "$(loadavg1)" <<'PY'
import json, sys
path, load1_end = sys.argv[1:3]
meta = json.load(open(path))
meta["load1_end"] = float(load1_end)
json.dump(meta, open(path, "w"), indent=2)
PY

  stop_gateway
  [[ "$measured" == "measured" ]] || rm -f "$run/$rep.summary.json"
}

# --- schedule ---------------------------------------------------------------

# `docker -v` reads a relative source as a NAMED VOLUME, never as a host
# directory, so a run dir given relative to the checkout silently becomes an
# empty anonymous mount and k6 dies before it measures anything. Every run dir
# is made absolute here, once, before anything mounts or writes to it.
# `CDPATH=` is load-bearing: an inherited CDPATH makes `cd` echo the directory
# it picked, so the substitution would capture two lines and the mount source
# would be garbage. `--` keeps a leading-dash path from parsing as an option.
abs_run_dir() { mkdir -p -- "$1" && (CDPATH= cd -- "$1" && pwd -P); }

do_measure() {
  local run="$1"
  render_configs "$run"

  python3 - "$run/pins.json" "$K6_IMAGE_DIGEST" \
    "$(cat "$ARMS_DIR/A/.checkout_sha")" "$(cat "$ARMS_DIR/B/.checkout_sha")" \
    "$(cat "$ARMS_DIR/C/.checkout_sha")" "$REPS" "$(ncpu)" "$SEED" <<'PY'
import json, subprocess, sys
path, digest, a, b, c, reps, ncpu, seed = sys.argv[1:9]
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
# The envelope is DECLARED here, before any rep runs, and is the machine's own
# CPU count -- not a constant fitted to the gap in some past run. At loadavg
# >= ncpu every runnable thread is queued behind a core and the rep is timing
# the queue. Declaring it up front is what keeps this from being a filter
# chosen after the numbers were seen.
json.dump({"k6_image_digest": digest, "reps": list(range(1, int(reps) + 1)),
           "ncpu": int(ncpu), "load_envelope": {"max_load1": float(ncpu)},
           "cell_order_seed": seed, "cells": cells},
          open(path,"w"), indent=2)
PY

  # Warm-up, discarded. Every cell gets one, including the report-only pair:
  # a cell that skips it is measured on a colder page cache than its siblings.
  for cell in A B C D E; do run_rep "$cell" "${cell}0" "$run" warmup; done

  # Measured, interleaved, and in a fresh order every rep. bench-host is shared, so
  # the arms must see the same machine conditions rather than consecutive
  # blocks of time. D and E are in this loop for that reason and no other:
  # running them as a trailing block gave them a different machine. In the
  # 2026-09-21 run the gated cells drew a window averaging loadavg 7 and the
  # report-only pair, 35 minutes later, drew one averaging 3.4 -- which is the
  # whole of why D and E looked untouched by an excursion that was never about
  # which cells were gated.
  #
  # The order within a rep is drawn from cell_order and WRITTEN DOWN as it is
  # drawn. A declared order the loop then ignored would be invisible in a green
  # run, so the file records the sequence this loop actually iterates.
  # Truncated first: the run dir is only mkdir -p'd, so a second `measure`
  # over the same dir would append a second set of reps and a reader taking
  # line N as rep N would get the wrong order.
  : > "$run/cell_order.jsonl"
  for n in $(seq 1 "$REPS"); do
    read -r -a order <<< "$(cell_order "$n")"
    joined="${order[*]}"
    printf '{"rep": %s, "order": ["%s"]}\n' "$n" "${joined// /\", \"}" \
      >> "$run/cell_order.jsonl"
    for cell in "${order[@]}"; do run_rep "$cell" "${cell}${n}" "$run" measured; done
  done

  echo "[done] run dir $run"
}

# One cell, one rep, discarded. Proves the plumbing -- config render, backend
# spawn, health shape, k6 write path -- before twelve reps are spent finding out
# the same thing. Its output is never scored.
do_smoke() {
  local run="$1" cell="${2:-C}"
  render_configs "$run"
  run_rep "$cell" "smoke-$cell" "$run" warmup
  echo "[smoke] ok: cell $cell plumbing clean; see $run/smoke-$cell.health.json"
}

# The run dir is resolved HERE, at the one place a caller's argument enters the
# script, so no command can reach a docker mount with a relative path. The
# result lands in a variable first: a command substitution spliced straight into
# an argument list hides its own exit status from `set -e`, so a failed mkdir or
# cd would hand the caller an empty string and send every write to the
# filesystem root. A bare assignment fails loudly instead.
case "${1:-}" in
  build)   do_build ;;
  smoke)   run="$(abs_run_dir "${2:?run dir required}")"; do_smoke "$run" "${3:-C}" ;;
  measure) run="$(abs_run_dir "${2:?run dir required}")"; do_measure "$run" ;;
  all)     do_build; run="$(abs_run_dir "${2:?run dir required}")"; do_measure "$run" ;;
  *) echo "usage: $0 {build|smoke|measure|all} <run-dir> [cell]" >&2; exit 2 ;;
esac

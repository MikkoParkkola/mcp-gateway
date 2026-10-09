#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
#
# Build, or run, the test suite from the packaged crate (#1812).
#
# A test that reads a repository file compiles and passes in the checkout even
# when Cargo.toml `include` leaves that file out of the published crate; only a
# build from the packaged crate sees the gap. `build` compiles every test
# target there and runs on every pull request; `run` also executes them, with
# the same skip list as ci.yml's `test` job, after a merge.
#
#   scripts/ci/packaged-tests.sh build|run
set -euo pipefail

mode="${1:-}"
case "$mode" in
  build | run) ;;
  *)
    echo "usage: $0 build|run" >&2
    exit 2
    ;;
esac

root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"
target="${CARGO_TARGET_DIR:-$root/target}"
export CARGO_TARGET_DIR="$target"

cargo package --locked --no-verify
version="$(cargo metadata --format-version 1 --no-deps --locked \
  | python3 -c 'import json,sys; print(next(p["version"] for p in json.load(sys.stdin)["packages"] if p["name"] == "mcp-gateway"))')"
crate="$target/package/mcp-gateway-$version.crate"
test -s "$crate"

unpacked="$(mktemp -d)"
trap 'rm -rf -- "$unpacked"' EXIT
tar -xzf "$crate" -C "$unpacked"
cd "$unpacked/mcp-gateway-$version"

if [ "$mode" = build ]; then
  cargo test --all-features --locked --no-run
else
  # The first two skips are ci.yml `test`'s: each has a dedicated job that
  # provisions what it needs. The wiring test holds those lists equal.
  # (mik_5843_ is no longer skipped: docs/SHADOW_SCAN.md and README.md ship in
  # the crate, and packaged-suite is the post-merge run of ci.yml `test`, MIK-8163.)
  cargo test --all-features --locked --no-fail-fast -- \
    --skip a_real_sdk_job_outlives_the_gateway_and_its_owner_reads_the_result \
    --skip mik_7479_full_burst
fi

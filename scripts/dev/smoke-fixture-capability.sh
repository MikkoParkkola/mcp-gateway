#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
set -euo pipefail

# usage: smoke-fixture-capability.sh <work-dir> <fixture-proxy-url>
# Writes <work-dir>/capabilities/smoke/first_run_fixture.yaml: the sample
# weather capability `init --profile local` wrote, renamed and pointed at a
# reserved name (RFC 2606) that resolves nowhere. The smokes reach it only
# through the gateway's capability proxy, which is scripts/dev/smoke_fixture_server.py:
# a capability may not call a loopback address directly (the SSRF-pinning
# resolver refuses it), so the proxy is the route a local fixture can take (#1543).
# Capability calls ignore HTTP(S)_PROXY from the environment (#1881), so the
# proxy is set as `capabilities.egress_proxy` in <work-dir>/gateway.yaml.

work="$1"
proxy="$2"
sample="$work/capabilities/knowledge/weather_current.yaml"
out="$work/capabilities/smoke/first_run_fixture.yaml"
origin="http://first-run-fixture.example"

[[ -f "$sample" ]] || { echo "init wrote no $sample" >&2; exit 1; }
mkdir -p "$(dirname "$out")"
sed -e 's/^name: weather_current$/name: first_run_fixture/' \
  -e "s#base_url: https://api.open-meteo.com#base_url: $origin#" \
  "$sample" >"$out"
if ! grep -q "^name: first_run_fixture$" "$out" || ! grep -q "base_url: $origin$" "$out"; then
  echo "could not derive the fixture capability from $sample" >&2
  exit 1
fi

# The `capabilities:` block `init` wrote gains the proxy key.
python3 - "$work/gateway.yaml" "$proxy" <<'PY'
import sys
path, proxy = sys.argv[1], sys.argv[2]
text = open(path, encoding="utf-8").read()
lines = text.split("\n")
if lines.count("capabilities:") != 1:
    sys.exit(f"expected one top-level capabilities: block in {path}")
at = lines.index("capabilities:") + 1
lines.insert(at, f"  egress_proxy: \"{proxy}\"")
open(path, "w", encoding="utf-8").write("\n".join(lines))
PY

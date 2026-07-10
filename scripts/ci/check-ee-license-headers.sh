#!/usr/bin/env bash
# check-ee-license-headers.sh
#
# Enforce that every Enterprise Edition (EE) source file carries the
# PolyForm-Noncommercial SPDX header. EE = the multi-user / multitenant and
# security-governance features designated in LICENSE-EE.md.
#
# Why this exists: multi-user features (identity propagation, per-user
# capability grants, per-user OAuth isolation, and their admin surfaces) are
# EE by policy. A file that implements one of them but ships without the SPDX
# header leaks EE code under the repo's MIT default. This guard fails CI so
# that can't happen silently again.
#
# Adding a new EE file: give it the header AND add its path below (keep this
# list in sync with LICENSE-EE.md).
set -euo pipefail

HEADER='// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0'

# EE-designated directories (every *.rs under them must carry the header).
EE_DIRS=(
  src/security/firewall
  src/cost_accounting
  src/key_server
  src/transparency_log
  src/identity_propagation
)

# EE-designated individual files.
EE_FILES=(
  src/security/agent_identity.rs
  src/security/data_flow.rs
  src/security/message_signing.rs
  src/security/policy.rs
  src/security/response_inspect.rs
  src/security/response_scanner.rs
  src/security/scope_collision.rs
  src/security/tool_integrity.rs
  src/identity_grants.rs
  src/identity_grants_tests.rs
  src/cli/identity.rs
  src/commands/identity.rs
)

missing=()

check() {
  local f="$1"
  [ -f "$f" ] || return 0
  if [ "$(head -n 1 "$f")" != "$HEADER" ]; then
    missing+=("$f")
  fi
}

for d in "${EE_DIRS[@]}"; do
  if [ -d "$d" ]; then
    while IFS= read -r f; do check "$f"; done < <(find "$d" -name '*.rs')
  fi
done
for f in "${EE_FILES[@]}"; do check "$f"; done

if [ "${#missing[@]}" -gt 0 ]; then
  echo "error: the following EE files are missing the PolyForm-Noncommercial SPDX header:" >&2
  printf '  %s\n' "${missing[@]}" >&2
  echo "" >&2
  echo "Add '$HEADER' as the first line. See LICENSE-EE.md. Multi-user/multitenant" >&2
  echo "and security-governance features are Enterprise Edition, not MIT." >&2
  exit 1
fi

echo "ok: all ${#EE_FILES[@]} designated EE files + EE directories carry the PolyForm-Noncommercial header"

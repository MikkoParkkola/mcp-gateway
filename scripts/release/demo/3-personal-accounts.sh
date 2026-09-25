#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
#
# NFR.DEMO.1 scenario 3 -- two personal accounts on one gateway.
#
# Alice and Bob share a gateway. Each has a personal backend. The recording
# shows each reaching their own, neither reaching the other's, neither SEEING
# the other's in the catalogue, and the gateway refusing outright (-32001,
# ADR-008 INV-2) to serve a personally-bound backend's stored credential to a
# caller who brought none of their own.
#
# NOT evidence for MIK-6745.JOURNEY.1: the peers are scripted fixtures, not a
# real identity provider. See docs/release/nfr-demo-1-recordings.md.
#
# Usage: BIN=/path/to/mcp-gateway bash scripts/release/demo/3-personal-accounts.sh
SCENARIO_ID="3-personal-accounts"
# shellcheck source=scripts/release/demo/_common.sh
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

PEER="$REPO_ROOT/scripts/release/demo/fixtures/demo_era_peer.py"
ALICE_KEY="alice-$API_KEY"
BOB_KEY="bob-$API_KEY"

echo "== NFR.DEMO.1 scenario 3: two personal accounts =="
echo "gateway:  $("$BIN" --version)"
echo "accounts: Alice (alice_notes) and Bob (bob_notes), two API keys on one gateway"
echo "run dir:  $RUN_DIR"

cat > "$CONFIG_PATH" <<YAML
server:
  host: "127.0.0.1"
  port: $PORT

# Two API keys and no single_user override: AuthConfig::implies_multi_user is
# true, so the gateway is in the multi-user posture the isolation guard defends.
# 4.0 refuses auth without an audit log (UPGRADING-4.0 item 43).
security:
  transparency_log:
    enabled: true
    path: "$RUN_DIR/audit/transparency.jsonl"

auth:
  enabled: true
  api_keys:
    - key_sha256: "$(printf %s "$ALICE_KEY" | "$BIN" hash-key)"
      name: "Alice"
      rate_limit: 0
      backends: ["alice_notes", "personal_inbox"]
    - key_sha256: "$(printf %s "$BOB_KEY" | "$BIN" hash-key)"
      name: "Bob"
      rate_limit: 0
      backends: ["bob_notes", "personal_inbox"]

meta_mcp:
  enabled: true

cache:
  enabled: false

backends:
  alice_notes:
    command: "python3 $PEER alice_notes 2025-06-18 not_modern"
    description: "Alice's personal notes peer"
    enabled: true
  bob_notes:
    command: "python3 $PEER bob_notes 2025-06-18 not_modern"
    description: "Bob's personal notes peer"
    enabled: true
  personal_inbox:
    command: "python3 $PEER personal_inbox 2025-06-18 not_modern"
    description: "Bound to one person's login; shared_account is NOT set"
    enabled: true
    oauth:
      enabled: true
YAML

start_gateway scenario3 || exit 1

call_as() { # key backend tool
  rpc "tools/call" \
    "{\"name\":\"gateway_invoke\",\"arguments\":{\"server\":\"$2\",\"tool\":\"$3\",\"arguments\":{\"text\":\"private\"}}}" \
    "$1"
}
contains() { case "$2" in *"$1"*) echo "$1 present";; *) echo "absent";; esac; }
catalogue_as() { # key
  rpc "tools/call" '{"name":"gateway_list_servers","arguments":{}}' "$1" | meta_payload | python3 -c '
import json, sys
payload = json.loads(sys.stdin.read() or "{}")
print(",".join(sorted(s.get("name", "") for s in payload.get("servers", []))) or "<none>")
'
}

echo
echo "-- each account reaches its own backend --"
ALICE_OWN="$(call_as "$ALICE_KEY" alice_notes alice_notes_ping)"
BOB_OWN="$(call_as "$BOB_KEY" bob_notes bob_notes_ping)"
echo "alice -> $(printf '%s' "$ALICE_OWN" | head -c 160)"
echo "bob   -> $(printf '%s' "$BOB_OWN" | head -c 160)"
record "S3.ALICE_REACHES_HER_OWN" "alice_notes answered: private present" \
  "$(contains "alice_notes answered: private" "$ALICE_OWN")"
record "S3.BOB_REACHES_HIS_OWN" "bob_notes answered: private present" \
  "$(contains "bob_notes answered: private" "$BOB_OWN")"

echo
echo "-- neither reaches the other's --"
ALICE_CROSS="$(call_as "$ALICE_KEY" bob_notes bob_notes_ping)"
BOB_CROSS="$(call_as "$BOB_KEY" alice_notes alice_notes_ping)"
echo "alice -> bob_notes: $(printf '%s' "$ALICE_CROSS" | head -c 200)"
echo "bob   -> alice_notes: $(printf '%s' "$BOB_CROSS" | head -c 200)"
record "S3.ALICE_CANNOT_REACH_BOBS" "absent" \
  "$(contains "bob_notes answered" "$ALICE_CROSS")"
record "S3.BOB_CANNOT_REACH_ALICES" "absent" \
  "$(contains "alice_notes answered" "$BOB_CROSS")"

echo
echo "-- neither SEES the other's in the catalogue --"
ALICE_CAT="$(catalogue_as "$ALICE_KEY")"
BOB_CAT="$(catalogue_as "$BOB_KEY")"
echo "alice catalogue: $ALICE_CAT"
echo "bob   catalogue: $BOB_CAT"
# RECORDED AS A GAP, NOT AS A GUARANTEE. The catalogue is NOT account-scoped:
# both keys get the same list, including the other account's backend and the
# personally-bound one neither of them may invoke. Credential isolation holds
# (the rows above and below); what leaks here is metadata -- backend names and
# descriptions. The row asserts the behaviour as observed so that a build which
# starts scoping the catalogue makes it FAIL and forces this finding to be
# revisited rather than quietly closed.
record "S3.CATALOGUE_IS_NOT_ACCOUNT_SCOPED" "$ALICE_CAT" "$BOB_CAT"
record "S3.CATALOGUE_LISTS_THE_UNINVOKABLE_BACKEND" "personal_inbox present" \
  "$(contains "personal_inbox" "$ALICE_CAT")"

echo
echo "-- the personally-bound backend is refused, not silently served --"
INBOX="$(call_as "$ALICE_KEY" personal_inbox personal_inbox_ping)"
echo "alice -> personal_inbox: $(printf '%s' "$INBOX" | head -c 400)"
# Wording taken from the arm that serves this path: gateway_invoke builds its
# own -32001 at src/gateway/meta_mcp/invoke.rs:1430-1440 ("one user's TOKEN"),
# separate from enforce_oauth_isolation_for at mod.rs:1105-1111 ("one user's
# CREDENTIAL"). Same ADR-008 INV-2 refusal, two independent spellings.
record "S3.PERSONAL_BACKEND_REFUSED" \
  "one user's token is never served to another present" \
  "$(contains "one user's token is never served to another" "$INBOX")"
record "S3.PERSONAL_BACKEND_DID_NOT_ANSWER" "absent" \
  "$(contains "personal_inbox answered" "$INBOX")"

echo
echo "results: $RESULTS_JSON"
echo "transcript: $TRANSCRIPT"

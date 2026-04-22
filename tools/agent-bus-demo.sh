#!/usr/bin/env bash
# agent-bus-demo.sh — MIK-2970 Agent Bus round-trip demo
# Two simulated agents publish/pull a message. Measures latency. PASS if <2s.
#
# Hardened version:
#   * Scalar SurrealQL inputs bound via URL query string ($topic, $from_agent…)
#     so SurrealQL injection through the topic field is impossible.
#   * Publish signs the message body with an ed25519 key (auto-generated if
#     ED25519_PRIVKEY env is unset). Pull verifies the signature against the
#     publisher's pubkey.
#   * Agent-name validation is enforced server-side by the schema ASSERT.
#   * Demonstrates DM filtering: agent-c does NOT see the DM addressed to
#     agent-b.

set -euo pipefail

SURREAL="http://127.0.0.1:8000/sql"
NS="Surreal-Ns:agent_bus"
DB="Surreal-Db:prod"
AUTH="Authorization:Basic cm9vdDpyb290"
ACCEPT="Accept:application/json"
TOPIC="bus.demo.mik2970.roundtrip"

fail() { echo "FAIL: $1" >&2; exit 1; }

# ── ed25519 keypair (generated once per run unless ED25519_PRIVKEY is set) ───
read -r ED25519_PRIVKEY ED25519_PUBKEY < <(python3 - <<'PY'
import base64, os, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

raw_priv = os.environ.get("ED25519_PRIVKEY")
if raw_priv:
    priv_bytes = base64.b64decode(raw_priv)
    priv = Ed25519PrivateKey.from_private_bytes(priv_bytes)
else:
    priv = Ed25519PrivateKey.generate()
    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )

pub_bytes = priv.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)
print(base64.b64encode(priv_bytes).decode(), base64.b64encode(pub_bytes).decode())
PY
)

# Signs "topic|from_agent|to_agent|kind|body_json" with $ED25519_PRIVKEY.
sign_msg() {
    local topic="$1" from_agent="$2" to_agent="$3" kind="$4" body_json="$5"
    ED25519_PRIVKEY="$ED25519_PRIVKEY" \
    SIG_TOPIC="$topic" SIG_FROM="$from_agent" SIG_TO="$to_agent" \
    SIG_KIND="$kind" SIG_BODY="$body_json" \
    python3 - <<'PY'
import base64, os
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
priv = Ed25519PrivateKey.from_private_bytes(base64.b64decode(os.environ["ED25519_PRIVKEY"]))
canonical = "|".join([
    os.environ["SIG_TOPIC"],
    os.environ["SIG_FROM"],
    os.environ["SIG_TO"],
    os.environ["SIG_KIND"],
    os.environ["SIG_BODY"],
]).encode("utf-8")
sig = priv.sign(canonical)
print(base64.b64encode(sig).decode(), end="")
PY
}

# Verifies signature against pubkey. Exits 0 on success, non-zero on failure.
verify_msg() {
    local pubkey_b64="$1" sig_b64="$2" topic="$3" from_agent="$4" to_agent="$5" kind="$6" body_json="$7"
    SIG_PUB="$pubkey_b64" SIG_VAL="$sig_b64" \
    SIG_TOPIC="$topic" SIG_FROM="$from_agent" SIG_TO="$to_agent" \
    SIG_KIND="$kind" SIG_BODY="$body_json" \
    python3 - <<'PY'
import base64, os, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(os.environ["SIG_PUB"]))
canonical = "|".join([
    os.environ["SIG_TOPIC"],
    os.environ["SIG_FROM"],
    os.environ["SIG_TO"],
    os.environ["SIG_KIND"],
    os.environ["SIG_BODY"],
]).encode("utf-8")
try:
    pub.verify(base64.b64decode(os.environ["SIG_VAL"]), canonical)
except InvalidSignature:
    sys.exit(1)
PY
}

echo "=== Agent Bus Round-Trip Demo (MIK-2970, hardened) ==="
echo "[setup] ed25519 pubkey: ${ED25519_PUBKEY:0:24}..."
echo ""

# ── Register agent-a in bus_agent (with pubkey) ──────────────────────────────
echo "[agent-a] Announcing in registry with pubkey"
xh --ignore-stdin POST "$SURREAL" "$NS" "$DB" "$AUTH" "$ACCEPT" \
    "name==agent-a:demo" "provider==demo" "host==localhost" "pubkey==$ED25519_PUBKEY" \
    --raw 'UPSERT bus_agent CONTENT { name: $name, provider: $provider, host: $host, pubkey: $pubkey, ts_last: time::now() };' \
    >/dev/null
echo ""

# ── Agent A: subscribe (get cursor) ──────────────────────────────────────────
echo "[agent-b] Subscribing to topic prefix: $TOPIC"
CURSOR=$(python3 -c "from datetime import datetime, timezone; print(datetime.now(timezone.utc).isoformat())")
echo "[agent-b] Cursor (since_ts): $CURSOR"
echo ""

# ── Agent A: publish (parameterized + signed) ────────────────────────────────
MSG_ID="demo-$(python3 -c 'import random,string; print("".join(random.choices(string.ascii_lowercase+string.digits,k=8)))')"
BODY_JSON="{\"msg_id\":\"$MSG_ID\",\"text\":\"ping from agent-a\"}"
SIG=$(sign_msg "$TOPIC" "agent-a:demo" "agent-b:demo" "request" "$BODY_JSON")
echo "[agent-a] Publishing id=$MSG_ID to $TOPIC (DM to agent-b:demo, signed)"
T0=$(python3 -c "import time; print(int(time.time()*1000))")

PUB_RESULT=$(xh --ignore-stdin POST "$SURREAL" "$NS" "$DB" "$AUTH" "$ACCEPT" \
    "topic==$TOPIC" "from_agent==agent-a:demo" "to_agent==agent-b:demo" \
    "kind==request" "sig==$SIG" \
    --raw "INSERT INTO bus_msg { topic: \$topic, from_agent: \$from_agent, to_agent: \$to_agent, kind: \$kind, signature: \$sig, body: $BODY_JSON };" 2>&1)

if ! echo "$PUB_RESULT" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d[0]['status']=='OK'" 2>/dev/null; then
    fail "Publish failed: $PUB_RESULT"
fi
echo "[agent-a] Publish OK"
echo ""

# ── Agent B: poll until message appears (DM filter targets agent-b) ──────────
echo "[agent-b] Polling with DM filter (current_agent=agent-b:demo)..."
FOUND=0
ATTEMPTS=0
MAX_ATTEMPTS=10
POLL_RESULT=""

while [[ $ATTEMPTS -lt $MAX_ATTEMPTS ]]; do
    POLL_RESULT=$(xh --ignore-stdin POST "$SURREAL" "$NS" "$DB" "$AUTH" "$ACCEPT" \
        "topic_pattern==$TOPIC" "since_ts==$CURSOR" "current_agent==agent-b:demo" "max_msgs==10" \
        --raw 'SELECT * FROM bus_msg WHERE string::starts_with(topic, $topic_pattern) AND ts > <datetime> $since_ts AND (to_agent IS NONE OR to_agent = $current_agent) ORDER BY ts ASC LIMIT type::int($max_msgs);' 2>&1)
    COUNT=$(echo "$POLL_RESULT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d[0].get('result',[])))" 2>/dev/null || echo 0)
    if [[ "$COUNT" -gt 0 ]]; then
        FOUND=1
        break
    fi
    ATTEMPTS=$((ATTEMPTS+1))
done

T1=$(python3 -c "import time; print(int(time.time()*1000))")
LATENCY_MS=$((T1 - T0))

if [[ $FOUND -eq 0 ]]; then
    fail "No message received by agent-b after $MAX_ATTEMPTS polls"
fi

echo "[agent-b] Received $COUNT message(s) after $ATTEMPTS poll(s)"

# ── Agent B: verify signature ────────────────────────────────────────────────
echo "[agent-b] Verifying ed25519 signature against agent-a's pubkey"
VERIFY_INPUT=$(echo "$POLL_RESULT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
m = d[0]['result'][0]
print(m.get('signature',''))
print(m.get('topic',''))
print(m.get('from_agent',''))
print(m.get('to_agent',''))
print(m.get('kind',''))
print(json.dumps(m.get('body',{}), separators=(',',':')))
")
mapfile -t VERIFY_LINES <<< "$VERIFY_INPUT"
if verify_msg "$ED25519_PUBKEY" "${VERIFY_LINES[0]}" "${VERIFY_LINES[1]}" "${VERIFY_LINES[2]}" "${VERIFY_LINES[3]}" "${VERIFY_LINES[4]}" "${VERIFY_LINES[5]}"; then
    echo "[agent-b] Signature OK"
else
    fail "Signature verification failed"
fi
echo ""

# ── Agent C (third party) confirms DM filter excludes them ───────────────────
echo "[agent-c] Polling with current_agent=agent-c:demo (should NOT see DM)"
THIRD_RESULT=$(xh --ignore-stdin POST "$SURREAL" "$NS" "$DB" "$AUTH" "$ACCEPT" \
    "topic_pattern==$TOPIC" "since_ts==$CURSOR" "current_agent==agent-c:demo" "max_msgs==10" \
    --raw 'SELECT * FROM bus_msg WHERE string::starts_with(topic, $topic_pattern) AND ts > <datetime> $since_ts AND (to_agent IS NONE OR to_agent = $current_agent) ORDER BY ts ASC LIMIT type::int($max_msgs);' 2>&1)
THIRD_COUNT=$(echo "$THIRD_RESULT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d[0].get('result',[])))" 2>/dev/null || echo 0)
if [[ "$THIRD_COUNT" -ne 0 ]]; then
    fail "DM filter leak: agent-c saw $THIRD_COUNT message(s) addressed to agent-b"
fi
echo "[agent-c] DM filter OK (saw 0 messages)"
echo ""

# ── Name-validation regression check ─────────────────────────────────────────
echo "[validation] Attempting to register agent with invalid name ('bad name; DROP')"
INVALID_RESULT=$(xh --ignore-stdin POST "$SURREAL" "$NS" "$DB" "$AUTH" "$ACCEPT" \
    --raw "UPSERT bus_agent CONTENT { name: 'bad name; DROP', provider: 'test' };" 2>&1)
if echo "$INVALID_RESULT" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d[0]['status']=='OK'" 2>/dev/null; then
    fail "Name validation did not reject invalid agent name"
fi
echo "[validation] Invalid name rejected as expected"
echo ""

# ── TTL cleanup smoke test ───────────────────────────────────────────────────
echo "[cleanup] Calling fn::bus_cleanup_expired()"
CLEAN_RESULT=$(xh --ignore-stdin POST "$SURREAL" "$NS" "$DB" "$AUTH" "$ACCEPT" \
    --raw 'RETURN fn::bus_cleanup_expired();' 2>&1)
DELETED=$(echo "$CLEAN_RESULT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d[0]['result']['deleted'])" 2>/dev/null || echo "?")
echo "[cleanup] fn::bus_cleanup_expired() deleted $DELETED expired row(s)"
echo ""

# ── Result ───────────────────────────────────────────────────────────────────
echo "=== Latency: ${LATENCY_MS}ms ==="
if [[ $LATENCY_MS -lt 2000 ]]; then
    echo "PASS (${LATENCY_MS}ms < 2000ms)"
else
    echo "FAIL (${LATENCY_MS}ms >= 2000ms threshold)"
    exit 1
fi

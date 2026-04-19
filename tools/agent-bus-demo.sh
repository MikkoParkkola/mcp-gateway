#!/usr/bin/env bash
# agent-bus-demo.sh — MIK-2970 Agent Bus round-trip demo
# Two simulated agents publish/pull a message. Measures latency. PASS if <2s.

set -euo pipefail

SURREAL="http://127.0.0.1:8000/sql"
NS="Surreal-Ns:agent_bus"
DB="Surreal-Db:prod"
AUTH="Authorization:Basic cm9vdDpyb290"
ACCEPT="Accept:application/json"
TOPIC="bus.demo.mik2970.roundtrip"

fail() { echo "FAIL: $1" >&2; exit 1; }
surql() { xh --ignore-stdin POST "$SURREAL" "$NS" "$DB" "$AUTH" "$ACCEPT" --raw "$1"; }

echo "=== Agent Bus Round-Trip Demo (MIK-2970) ==="
echo ""

# ── Agent A: subscribe (get cursor) ──────────────────────────────────────────
echo "[agent-a] Subscribing to topic prefix: $TOPIC"
CURSOR=$(python3 -c "from datetime import datetime, timezone; print(datetime.now(timezone.utc).isoformat())")
echo "[agent-a] Cursor (since_ts): $CURSOR"
echo ""

# ── Agent A: publish ──────────────────────────────────────────────────────────
MSG_ID="demo-$(python3 -c 'import random,string; print("".join(random.choices(string.ascii_lowercase+string.digits,k=8)))')"
echo "[agent-a] Publishing message id=$MSG_ID to $TOPIC"
T0=$(python3 -c "import time; print(int(time.time()*1000))")

PUB_RESULT=$(surql "INSERT INTO bus_msg (topic, from_agent, kind, body) VALUES ('$TOPIC', 'agent-a:demo', 'request', {msg_id: '$MSG_ID', text: 'ping from agent-a'});" 2>&1)
if ! echo "$PUB_RESULT" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d[0]['status']=='OK'" 2>/dev/null; then
  fail "Publish failed: $PUB_RESULT"
fi
echo "[agent-a] Publish OK"
echo ""

# ── Agent B: poll until message appears (max 2s) ─────────────────────────────
echo "[agent-b] Polling for messages on $TOPIC since cursor..."
FOUND=0
ATTEMPTS=0
MAX_ATTEMPTS=10
POLL_RESULT=""

while [[ $ATTEMPTS -lt $MAX_ATTEMPTS ]]; do
  POLL_RESULT=$(surql "SELECT id, body, ts FROM bus_msg WHERE string::starts_with(topic, '$TOPIC') AND ts > <datetime>'$CURSOR' ORDER BY ts ASC LIMIT 10;" 2>&1)
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
echo "[agent-b] First message:"
echo "$POLL_RESULT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
msgs = d[0].get('result', [])
for m in msgs[:1]:
    print('  id    :', m.get('id'))
    print('  ts    :', m.get('ts'))
    print('  body  :', json.dumps(m.get('body')))
" 2>/dev/null || echo "  (raw): $POLL_RESULT"
echo ""

# ── Result ───────────────────────────────────────────────────────────────────
echo "=== Latency: ${LATENCY_MS}ms ==="
if [[ $LATENCY_MS -lt 2000 ]]; then
  echo "PASS (${LATENCY_MS}ms < 2000ms)"
else
  echo "FAIL (${LATENCY_MS}ms >= 2000ms threshold)"
  exit 1
fi

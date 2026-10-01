#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""MCP Events fail-fast stub (MIK-7630). Stdlib only.

Answers one question before any product code exists: can a real MCP Events
client (ChatGPT) reach an endpoint we control, list a stub event, subscribe
with a webhook callback, pass the verification handshake, and accept a signed
delivery?

  serve     stub MCP server: server/discover, events/list|subscribe|unsubscribe
  receiver  local Standard-Webhooks receiver that checks every signature
  selftest  loopback run of serve + receiver; exit 0 only if the round trip holds

Every request the stub receives is appended to --log as one JSON line; that
log is the evidence. See docs/design/2026-10-01-mik-7630-mcp-events.md.
"""
import argparse
import base64
import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import socket
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PROTOCOL = "2026-07-28"
EVENT = {
    "name": "stub.ping",
    "description": "Fires when the operator triggers a ping on the fail-fast stub.",
    "delivery": ["webhook"],
    "inputSchema": {
        "type": "object",
        "properties": {"topic": {"type": "string", "description": "Only pings for this topic."}},
        "required": ["topic"],
        "additionalProperties": False,
    },
    "payloadSchema": {
        "type": "object",
        "properties": {"topic": {"type": "string"}, "seq": {"type": "integer"}},
        "required": ["topic", "seq"],
        "additionalProperties": False,
    },
}
MAX_BODY = 256 * 1024
DEFAULT_TTL_MS = 3_600_000
MIN_TTL_MS = 60_000


def canonical(v):
    """Canonical JSON for identity: sorted keys, no whitespace."""
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def decode_whsec(secret):
    """Return the key bytes, or None when the value is not whsec_ + base64 of 24..64 bytes."""
    if not isinstance(secret, str) or not secret.startswith("whsec_"):
        return None
    try:
        raw = base64.b64decode(secret[6:], validate=True)
    except ValueError:
        return None
    return raw if 24 <= len(raw) <= 64 else None


def sign(key, msg_id, ts, body):
    mac = hmac.new(key, f"{msg_id}.{ts}.".encode() + body, hashlib.sha256).digest()
    return "v1," + base64.b64encode(mac).decode()


def verify(key, msg_id, ts, body, header, tolerance=300):
    if abs(time.time() - int(ts)) > tolerance:
        return False
    want = sign(key, msg_id, ts, body)
    return any(hmac.compare_digest(want, s) for s in header.split(" "))


def public_ip(ip):
    return ipaddress.ip_address(ip).is_global


def post_signed(url, key, msg_id, sub_id, body, allow_local):
    """POST once. Resolve, check, and connect to the checked address; no redirects."""
    u = urllib.parse.urlsplit(url)
    if u.scheme != "https" and not allow_local:
        return None, "tls_error"
    host, port = u.hostname, u.port or (443 if u.scheme == "https" else 80)
    try:
        addr = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)[0][4][0]
    except OSError:
        return None, "connection_refused"
    if not public_ip(addr) and not allow_local:
        return None, "connection_refused"
    ts = str(int(time.time()))
    headers = {
        "Content-Type": "application/json",
        "webhook-id": msg_id,
        "webhook-timestamp": ts,
        "webhook-signature": sign(key, msg_id, ts, body),
        "X-MCP-Subscription-Id": sub_id,
    }
    # ponytail: urllib re-resolves the host, so this stub has a check-to-connect
    # window; the gateway pins the checked address (design doc, SSRF section).
    opener = urllib.request.build_opener(NoRedirect)
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with opener.open(req, timeout=10) as r:
            return r.status, r.read(64 * 1024)
    except urllib.error.HTTPError as e:
        return e.code, b""
    except (urllib.error.URLError, OSError) as e:
        return None, "timeout" if "timed out" in str(e) else "connection_refused"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


class Stub:
    """In-file store: survives a stub restart, which the design requires of the gateway."""

    def __init__(self, store, log, bearer, allow_local):
        self.store, self.log, self.bearer, self.allow_local = store, log, bearer, allow_local
        self.lock = threading.Lock()
        self.subs = json.load(open(store)) if os.path.exists(store) else {}
        self.verified = set()  # (principal, url): verification cache, per spec
        self.seq = 0

    def save(self):
        tmp = self.store + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.subs, f, indent=1)
        os.replace(tmp, self.store)

    def record(self, entry):
        with self.lock, open(self.log, "a") as f:
            f.write(json.dumps({"at": datetime.now(timezone.utc).isoformat(), **entry}) + "\n")

    def principal(self, headers):
        auth = headers.get("Authorization", "")
        if self.bearer:
            ok = hmac.compare_digest(auth, "Bearer " + self.bearer)
            return "bearer:" + hashlib.sha256(self.bearer.encode()).hexdigest()[:12] if ok else None
        # ponytail: no-auth stub uses one fixed principal; the gateway uses the
        # authenticated caller and refuses webhook mode without one (spec, Subscription Identity).
        return "stub-anonymous"

    def rpc(self, msg, headers):
        method, params, mid = msg.get("method"), msg.get("params") or {}, msg.get("id")
        if mid is None:
            return None  # notification
        ok = lambda r: {"jsonrpc": "2.0", "id": mid, "result": r}
        err = lambda c, m, d=None: {"jsonrpc": "2.0", "id": mid,
                                    "error": {"code": c, "message": m, **({"data": d} if d else {})}}
        caps = {"tools": {}, "events": {"listChanged": False}}
        info = {"name": "mcp-events-failfast-stub", "version": "0.1.0"}
        if method == "server/discover":
            return ok({"resultType": "complete", "supportedVersions": [PROTOCOL],
                       "capabilities": caps, "serverInfo": info})
        if method == "initialize":
            return ok({"protocolVersion": params.get("protocolVersion", PROTOCOL),
                       "capabilities": caps, "serverInfo": info})
        if method == "ping":
            return ok({})
        if method == "tools/list":
            return ok({"tools": [{"name": "stub_status", "description": "Count of active stub subscriptions.",
                                  "inputSchema": {"type": "object", "properties": {}}}]})
        if method == "tools/call":
            return ok({"content": [{"type": "text", "text": f"{len(self.subs)} subscription(s)"}]})
        if method == "events/list":
            return ok({"events": [EVENT]})
        if method in ("events/subscribe", "events/unsubscribe"):
            who = self.principal(headers)
            if who is None:
                return err(-32012, "Forbidden")
            if params.get("name") != EVENT["name"]:
                return err(-32011, "NotFound", {"kind": "event"})
            args = params.get("arguments") or {}
            if not isinstance(args.get("topic"), str) or set(args) - {"topic"}:
                return err(-32602, "InvalidParams")
            url = (params.get("delivery") or {}).get("url", "")
            if not (url.startswith("https://") or self.allow_local):
                return err(-32602, "InvalidParams", {"field": "delivery.url"})
            sid = "sub_" + hashlib.sha256(canonical([who, url, EVENT["name"], args]).encode()).hexdigest()[:24]
            if method == "events/unsubscribe":
                with self.lock:
                    self.subs.pop(sid, None)
                    self.save()
                return ok({})
            key = decode_whsec((params.get("delivery") or {}).get("secret"))
            if key is None:
                return err(-32602, "InvalidParams", {"field": "delivery.secret"})
            if (who, url) not in self.verified:
                reason = self.challenge(url, key, sid)
                if reason:
                    return err(-32015, "CallbackEndpointError", {"reason": reason})
                self.verified.add((who, url))
            ttl = params.get("ttlMs", DEFAULT_TTL_MS)
            exp = None if ttl is None else (datetime.now(timezone.utc)
                                           + timedelta(milliseconds=max(int(ttl), MIN_TTL_MS)))
            with self.lock:
                self.subs[sid] = {"principal": who, "url": url, "name": EVENT["name"], "arguments": args,
                                  "secret": params["delivery"]["secret"],
                                  "expires": exp and exp.isoformat()}
                self.save()
            return ok({"id": sid, "refreshBefore": exp and exp.strftime("%Y-%m-%dT%H:%M:%SZ"),
                       "cursor": None, "truncated": False})
        return err(-32601, "Method not found")

    def challenge(self, url, key, sid):
        nonce = secrets.token_urlsafe(32)
        body = canonical({"type": "verification", "challenge": nonce}).encode()
        status, resp = post_signed(url, key, "msg_verification_" + secrets.token_hex(8), sid, body,
                                   self.allow_local)
        self.record({"kind": "verification", "url": url, "status": status})
        if status is None:
            return resp
        if not 200 <= status < 300:
            return "http_4xx" if status < 500 else "http_5xx"
        try:
            echoed = json.loads(resp).get("challenge", "")
        except (ValueError, AttributeError):
            return "challenge_failed"
        return None if hmac.compare_digest(str(echoed).encode(), nonce.encode()) else "challenge_failed"

    def emit(self, topic):
        """Deliver one stub.ping to every live subscription whose topic matches."""
        self.seq += 1
        out, now = [], datetime.now(timezone.utc)
        for sid, s in list(self.subs.items()):
            if s["arguments"]["topic"] != topic or (s["expires"] and datetime.fromisoformat(s["expires"]) < now):
                continue
            eid = "evt_" + secrets.token_hex(12)
            body = canonical({"eventId": eid, "name": s["name"], "timestamp": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                              "data": {"topic": topic, "seq": self.seq}, "cursor": None}).encode()
            assert len(body) <= MAX_BODY
            status = None
            for attempt in range(3):  # same webhook-id each attempt, fresh timestamp and signature
                status, _ = post_signed(s["url"], decode_whsec(s["secret"]), eid, sid, body, self.allow_local)
                if status is not None and (200 <= status < 300 or status in (410, 413)):
                    break
                time.sleep(2 ** attempt)
            self.record({"kind": "delivery", "subscription": sid, "eventId": eid, "status": status})
            out.append({"subscription": sid, "eventId": eid, "status": status})
        return out


def stub_handler(stub, emit_token):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def reply(self, code, obj=None):
            data = b"" if obj is None else json.dumps(obj).encode()
            self.send_response(code)
            if obj is not None:
                self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            u = urllib.parse.urlsplit(self.path)
            q = urllib.parse.parse_qs(u.query)
            # The tunnel makes every caller look like loopback, so emit needs its own token.
            if u.path == "/emit" and hmac.compare_digest(q.get("token", [""])[0], emit_token):
                return self.reply(200, stub.emit(q.get("topic", [""])[0]))
            self.reply(404, {"error": "not found"})

        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0)
            if n > MAX_BODY:
                return self.reply(413, {"error": "too large"})
            raw = self.rfile.read(n)
            hdrs = {k: v for k, v in self.headers.items() if k.lower() not in ("authorization", "cookie")}
            try:
                msg = json.loads(raw)
            except ValueError:
                stub.record({"kind": "request", "path": self.path, "headers": hdrs,
                             "unparsed": raw[:2048].decode("utf-8", "replace")})
                return self.reply(400, {"jsonrpc": "2.0", "id": None,
                                        "error": {"code": -32700, "message": "Parse error"}})
            stub.record({"kind": "request", "path": self.path, "headers": hdrs, "body": msg})
            resp = stub.rpc(msg, self.headers)
            stub.record({"kind": "response", "method": msg.get("method"), "body": resp})
            self.reply(202) if resp is None else self.reply(200, resp)

    return H


def receiver_handler(secret, seen):
    key = decode_whsec(secret)
    need = ("webhook-id", "webhook-timestamp", "webhook-signature", "X-MCP-Subscription-Id")

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            h = self.headers
            ok = all(h.get(x) for x in need) and verify(
                key, h["webhook-id"], h["webhook-timestamp"], body, h["webhook-signature"])
            if not ok:
                seen.append({"rejected": h.get("webhook-id")})
                self.send_response(401)
                self.end_headers()
                return
            msg = json.loads(body)
            seen.append({"webhook-id": h["webhook-id"], "sub": h["X-MCP-Subscription-Id"], "body": msg})
            reply = {"challenge": msg["challenge"]} if msg.get("type") == "verification" else {}
            out = json.dumps(reply).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

    return H


def start(handler, port=0):
    srv = ThreadingHTTPServer(("127.0.0.1", port), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def call(url, method, params=None, mid=1):
    data = json.dumps({"jsonrpc": "2.0", "id": mid, "method": method, "params": params or {}}).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read())


def selftest(workdir):
    """Loopback round trip. Each assert is one clause the stub must hold."""
    secret = "whsec_" + base64.b64encode(secrets.token_bytes(32)).decode()
    seen = []
    rcv = start(receiver_handler(secret, seen))
    cb = f"http://127.0.0.1:{rcv.server_port}/hook"
    store, log, token = os.path.join(workdir, "subs.json"), os.path.join(workdir, "log.jsonl"), "t0k"
    stub = Stub(store, log, None, allow_local=True)
    srv = start(stub_handler(stub, token))
    base = f"http://127.0.0.1:{srv.server_port}"
    mcp = base + "/mcp"
    emit = lambda topic: urllib.request.urlopen(f"{base}/emit?token={token}&topic={topic}").read()

    d = call(mcp, "server/discover")["result"]
    assert "events" in d["capabilities"] and PROTOCOL in d["supportedVersions"], d
    assert call(mcp, "events/list")["result"]["events"][0]["name"] == "stub.ping"
    short = {"mode": "webhook", "url": cb, "secret": "whsec_Zm9v"}  # 3 bytes: below the 24-byte floor
    bad = call(mcp, "events/subscribe", {"name": "stub.ping", "arguments": {"topic": "a"}, "delivery": short})
    assert bad["error"]["code"] == -32602, bad
    p = {"name": "stub.ping", "arguments": {"topic": "a"},
         "delivery": {"mode": "webhook", "url": cb, "secret": secret}}
    r1 = call(mcp, "events/subscribe", p)["result"]
    assert seen and seen[0]["body"]["type"] == "verification", seen
    r2 = call(mcp, "events/subscribe", p)["result"]
    assert r1["id"] == r2["id"] and len(seen) == 1, "idempotent; verification cached"
    assert Stub(store, log, None, True).subs.keys() == {r1["id"]}, "persisted across restart"
    emit("b")
    assert len(seen) == 1, "filter: topic b must not deliver"
    emit("a")
    ev = seen[-1]
    assert "rejected" not in ev, "receiver rejected the delivery signature"
    assert ev["webhook-id"] == ev["body"]["eventId"] and ev["sub"] == r1["id"], ev
    assert set(ev["body"]) == {"eventId", "name", "timestamp", "data", "cursor"}, "no injected fields"
    un = {"name": "stub.ping", "arguments": {"topic": "a"}, "delivery": {"url": cb}}
    assert call(mcp, "events/unsubscribe", un)["result"] == {}
    assert call(mcp, "events/unsubscribe", un)["result"] == {}, "idempotent unsubscribe"
    emit("a")
    assert len([s for s in seen if "body" in s]) == 2 and not any("rejected" in s for s in seen), seen
    srv.shutdown()
    rcv.shutdown()
    print("selftest PASS: discover, list, short-secret, verify, idempotent, persist, filter, sign, unsubscribe")
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve")
    s.add_argument("--port", type=int, default=8765)
    s.add_argument("--dir", default=".", help="where subs.json and log.jsonl are written")
    s.add_argument("--bearer", default=os.environ.get("STUB_BEARER"), help="require this bearer token")
    r = sub.add_parser("receiver")
    r.add_argument("--port", type=int, default=8766)
    r.add_argument("--secret", required=True)
    t = sub.add_parser("selftest")
    t.add_argument("--dir", required=True, help="empty scratch directory for the run")
    a = ap.parse_args()
    if a.cmd == "selftest":
        return selftest(a.dir)
    if a.cmd == "receiver":
        srv = ThreadingHTTPServer(("127.0.0.1", a.port), receiver_handler(a.secret, []))
        print(f"receiver on 127.0.0.1:{a.port}")
        return srv.serve_forever()
    token = secrets.token_urlsafe(16)
    stub = Stub(os.path.join(a.dir, "subs.json"), os.path.join(a.dir, "log.jsonl"), a.bearer, allow_local=False)
    srv = ThreadingHTTPServer(("127.0.0.1", a.port), stub_handler(stub, token))
    print(f"stub MCP endpoint: http://127.0.0.1:{a.port}/mcp")
    print(f"expose it:         cloudflared tunnel --url http://127.0.0.1:{a.port}")
    print(f"fire an event:     curl 'http://127.0.0.1:{a.port}/emit?token={token}&topic=<topic>'")
    print(f"evidence log:      {stub.log}")
    return srv.serve_forever()


if __name__ == "__main__":
    sys.exit(main())

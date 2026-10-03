#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Test-only OAuth 2.1 front for one gateway, for the EVENTS.8 ChatGPT run.

The gateway is an OAuth resource server and publishes no authorization-server
metadata, which ChatGPT needs before it will call an authenticated MCP
endpoint. This shim serves that metadata, dynamic client registration, an
auto-approving authorize step and a PKCE token step that hands out one
configured API key as the access token, and proxies everything else to the
gateway. It writes a JSONL evidence log (method names and statuses only: no
tokens, secrets, callback paths or bodies).

NOT for production: the authorize step approves every request. Run it only
behind a short-lived tunnel. Stdlib only.
"""
import argparse, os, base64, hashlib, http.client, json, secrets, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlparse

CODES = {}
REFRESH = set()
CLIENTS = {}  # client_id -> registered redirect_uris


class Shim(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    cfg = None

    def log_message(self, *args):
        pass

    def evidence(self, **entry):
        entry["ts"] = round(time.time(), 3)
        with self.cfg.lock, open(self.cfg.log, "a") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")

    def origin(self):
        return self.cfg.public

    def send_json(self, status, body, headers=()):
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(raw)))
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def body(self):
        return self.rfile.read(int(self.headers.get("content-length") or 0))

    def do_GET(self):
        self.route("GET")

    def do_POST(self):
        self.route("POST")

    def do_DELETE(self):
        self.route("DELETE")

    def route(self, verb):
        path = urlparse(self.path).path
        o = self.origin()
        if path.startswith("/.well-known/oauth-protected-resource"):
            return self.send_json(200, {"resource": o + "/mcp", "authorization_servers": [o],
                                        "bearer_methods_supported": ["header"]})
        if path in ("/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"):
            return self.send_json(200, {
                "issuer": o, "authorization_endpoint": o + "/authorize",
                "token_endpoint": o + "/token", "registration_endpoint": o + "/register",
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code", "refresh_token"],
                "code_challenge_methods_supported": ["S256"],
                "token_endpoint_auth_methods_supported": ["none"], "scopes_supported": []})
        if path == "/register" and verb == "POST":
            return self.register()
        if path == "/authorize" and verb == "GET":
            return self.authorize()
        if path == "/token" and verb == "POST":
            return self.token()
        self.proxy(verb, path)

    def register(self):
        try:
            req = json.loads(self.body() or b"{}")
        except ValueError:
            return self.send_json(400, {"error": "invalid_client_metadata"})
        uris = req.get("redirect_uris") or []
        if not uris or not all(self.redirect_ok(u) for u in uris):
            return self.send_json(400, {"error": "invalid_redirect_uri"})
        client = "c-" + secrets.token_urlsafe(12)
        CLIENTS[client] = list(uris)
        self.evidence(kind="oauth", step="register")
        self.send_json(201, {"client_id": client, "redirect_uris": uris,
                             "token_endpoint_auth_method": "none",
                             "grant_types": ["authorization_code", "refresh_token"],
                             "response_types": ["code"]})

    def redirect_ok(self, uri):
        u = urlparse(uri)
        host = u.hostname or ""
        if u.scheme == "http" and host in ("127.0.0.1", "localhost"):
            return True
        return u.scheme == "https" and any(
            host == h or host.endswith("." + h) for h in self.cfg.redirect_hosts)

    def authorize(self):
        q = {k: v[0] for k, v in parse_qs(urlparse(self.path).query).items()}
        uri = q.get("redirect_uri", "")
        resource = q.get("resource")
        if uri not in CLIENTS.get(q.get("client_id", ""), []) \
                or (resource is not None and resource != self.origin() + "/mcp"):
            return self.send_json(400, {"error": "invalid_request"})
        if q.get("response_type") != "code" or not self.redirect_ok(uri) \
                or q.get("code_challenge_method") != "S256" or not q.get("code_challenge"):
            return self.send_json(400, {"error": "invalid_request"})
        code = secrets.token_urlsafe(24)
        CODES[code] = (q["code_challenge"], uri, q.get("client_id"), time.time(), resource)
        self.evidence(kind="oauth", step="authorize")
        back = {"code": code}
        if "state" in q:
            back["state"] = q["state"]
        sep = "&" if "?" in uri else "?"
        self.send_response(302)
        self.send_header("location", uri + sep + urlencode(back))
        self.send_header("content-length", "0")
        self.end_headers()

    def token(self):
        f = {k: v[0] for k, v in parse_qs(self.body().decode()).items()}
        if f.get("grant_type") == "refresh_token":
            if f.get("refresh_token") not in REFRESH:
                return self.send_json(400, {"error": "invalid_grant"})
            self.evidence(kind="oauth", step="refresh")
            return self.token_reply()
        entry = CODES.pop(f.get("code", ""), None)
        if not entry or time.time() - entry[3] > 120 or f.get("redirect_uri") != entry[1] \
                or f.get("client_id") != entry[2] \
                or (f.get("resource") is not None and f.get("resource") != entry[4]):
            return self.send_json(400, {"error": "invalid_grant"})
        digest = base64.urlsafe_b64encode(
            hashlib.sha256(f.get("code_verifier", "").encode()).digest()).rstrip(b"=").decode()
        if not secrets.compare_digest(digest, entry[0]):
            return self.send_json(400, {"error": "invalid_grant"})
        self.evidence(kind="oauth", step="token")
        self.token_reply()

    def token_reply(self):
        refresh = "r-" + secrets.token_urlsafe(16)
        REFRESH.add(refresh)
        self.send_json(200, {"access_token": self.cfg.api_key, "token_type": "Bearer",
                             "expires_in": 3600, "refresh_token": refresh})

    def proxy(self, verb, path):
        data = self.body()
        rpc, rpc_params = [], []
        if path == "/mcp" and verb == "POST":
            try:
                doc = json.loads(data)
                calls = doc if isinstance(doc, list) else [doc]
                rpc = [d.get("method") for d in calls]
                # Subscription identity only (never the delivery url or secret):
                # the evidence check must see WHICH subscription a call named.
                for d in calls:
                    if d.get("method") in ("events/subscribe", "events/unsubscribe"):
                        p = d.get("params") or {}
                        args = p.get("arguments") if isinstance(p.get("arguments"), dict) else {}
                        # Allowlisted filter keys only: arguments are caller-supplied.
                        rpc_params.append({"method": d["method"], "name": p.get("name"),
                                           "arguments": {k: v for k, v in args.items()
                                                         if k in ("repo", "ref", "event_type")
                                                         and isinstance(v, str)}})
            except (ValueError, AttributeError):
                pass
        headers = {k: v for k, v in self.headers.items()
                   if k.lower() not in ("host", "connection", "content-length", "accept-encoding")}
        headers["accept-encoding"] = "identity"
        conn = http.client.HTTPConnection("127.0.0.1", self.cfg.upstream, timeout=60)
        conn.request(verb, self.path, body=data or None, headers=headers)
        resp = conn.getresponse()
        self.send_response(resp.status)
        stream = "event-stream" in (resp.getheader("content-type") or "")
        for k, v in resp.getheaders():
            if k.lower() not in ("transfer-encoding", "connection", "content-length"):
                self.send_header(k, v)
        if resp.status == 401 and path.startswith("/mcp"):
            self.send_header("www-authenticate", 'Bearer resource_metadata="%s/.well-known/'
                             'oauth-protected-resource"' % self.origin())
        self.end_headers()
        out = b""
        while chunk := (resp.read1(65536) if stream else resp.read(1 << 20)):
            self.wfile.write(chunk)
            self.wfile.flush()
            if len(out) < (1 << 20):
                out += chunk
        entry = {"kind": "http", "verb": verb, "path": path.split("?")[0], "status": resp.status}
        if rpc:
            entry["rpc"] = rpc
            if rpc_params:
                entry["rpc_params"] = rpc_params
            try:
                text = out.decode()
                if stream:
                    text = [ln[5:] for ln in text.splitlines() if ln.startswith("data:")][-1]
                reply = json.loads(text)
                reply = reply[0] if isinstance(reply, list) else reply
                # Fail closed: only a JSON-RPC object with a result and no error is an answer.
                entry["reply_ok"] = isinstance(reply, dict) and "result" in reply and "error" not in reply
                entry["error_code"] = (reply.get("error") or {}).get("code")
                entry["result_has_id"] = "id" in (reply.get("result") or {})
                if isinstance((reply.get("result") or {}).get("id"), str):
                    entry["result_id"] = reply["result"]["id"]
            except (ValueError, AttributeError, IndexError) as e:
                entry["parse_error"] = type(e).__name__
        self.evidence(**entry)


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--upstream", type=int, required=True, help="gateway port on 127.0.0.1")
    p.add_argument("--public", required=True, help="public https origin of the tunnel")
    p.add_argument("--api-key", default=os.environ.get("EVENTS8_API_KEY"), help="the access token handed out (or env EVENTS8_API_KEY)")
    p.add_argument("--log", required=True)
    p.add_argument("--redirect-host", action="append", default=["chatgpt.com", "openai.com"])
    a = p.parse_args()
    if not a.api_key:
        sys.exit("--api-key or EVENTS8_API_KEY is required")
    Shim.cfg = argparse.Namespace(upstream=a.upstream, public=a.public.rstrip("/"),
                                  api_key=a.api_key, log=a.log, lock=threading.Lock(),
                                  redirect_hosts=a.redirect_host)
    open(a.log, "a").close()
    ThreadingHTTPServer(("127.0.0.1", a.port), Shim).serve_forever()


if __name__ == "__main__":
    sys.exit(main())

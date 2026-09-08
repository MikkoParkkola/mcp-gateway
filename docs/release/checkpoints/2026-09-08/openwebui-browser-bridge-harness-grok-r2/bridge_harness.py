#!/usr/bin/env python3
"""OWUI browser-identity PROOF HARNESS (not product).

Proves same-origin HTTPS bridge sees the same OWUI user-id as the logged-in
browser. Stolen link, anonymous, CSRF, duplicate cookies, and replay fail.
Does NOT verify canonical gateway principal mapping. No OAuth token exchange
and no account-store changes. Loopback HTTP upstream TLS is out of scope;
browser traffic is HTTPS only.
"""
from __future__ import annotations
import argparse, json, secrets, ssl, threading, urllib.error, urllib.request
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

UPSTREAM, MAX_BODY, TIMEOUT = "http://127.0.0.1:19080", 65536, 8
TOKEN, CHAL, CSRF, SID = "token", "owui_bridge_chal", "owui_bridge_csrf", "owui_bridge_sid"
AUTH_SESSION = "/api/v1/auths/"
AUTH_SIGNIN = "/api/v1/auths/signin"
AUTH_SIGNUP = "/api/v1/auths/signup"
lock = threading.Lock()
bound = started = False
counters = {"bind_ok": 0, "bind_fail": 0, "proxy_ok": 0, "proxy_fail": 0}
csrf_v = chal_v = expected = origin = ""
admin = secrets.token_urlsafe(32)
SYNTH_NAME = "bridge-user"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


OPENER = urllib.request.build_opener(NoRedirect)


def log(m):
    print("[harness]", m, flush=True)


def inc(k):
    with lock:
        counters[k] += 1


def cookies(h):
    """Parse Cookie header pair-by-pair. None = malformed. Lists preserve dups."""
    if not h:
        return {}
    if not isinstance(h, str) or not h.isascii():
        return None
    o = {}
    parts = h.split(";")
    for part in parts:
        raw = part.strip()
        if not raw:
            return None
        if "=" not in raw:
            return None
        k, _, v = raw.partition("=")
        k, v = k.strip(), v.strip()
        if not k or not k.isascii() or not k.isidentifier() and not all(
            c.isalnum() or c in "-_" for c in k
        ):
            return None
        if any(c.isspace() for c in k) or not v.isascii():
            return None
        if any(ord(c) < 32 for c in v):
            return None
        o.setdefault(k, []).append(v)
    return o


def token_of(h):
    ck = cookies(h)
    if ck is None:
        return "__bad__"
    v = ck.get(TOKEN, [])
    if len(v) > 1:
        return "__dup__"
    return v[0] if v else None


def dup_protected(ck):
    if ck is None:
        return True
    return any(len(ck.get(n, [])) > 1 for n in (TOKEN, CHAL, CSRF))


def sc(n, v):
    return f"{n}={v}; Path=/; Secure; HttpOnly; SameSite=Lax"


def html(t, b):
    return f"<!DOCTYPE html><html><head><meta charset='utf-8'><title>{t}</title></head><body>{b}</body></html>".encode()


LOGIN = html("login", """<h1>Login (A)</h1><p>Never echoed.</p>
<form id=f><input name=email type=email required><input name=password type=password required>
<button name=action value=signin>in</button><button name=action value=signup>up</button></form><p id=st></p>
<script>f.addEventListener('submit',async e=>{e.preventDefault();const d=new FormData(f);const a=e.submitter.value;
const r=await fetch('/api/v1/auths/'+a,{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},
body:JSON.stringify({email:d.get('email'),password:d.get('password'),name:'bridge-user'})});st.textContent=r.ok?'ok':'fail';});</script>""")


def origin_ok(got, exp):
    return bool(got) and got == exp


def same_secret(a, b):
    if not isinstance(a, str) or not isinstance(b, str):
        return False
    if not a or not b or not a.isascii() or not b.isascii():
        return False
    return secrets.compare_digest(a.encode("ascii"), b.encode("ascii"))


def csrf_ok(posted, cookie, stored):
    return same_secret(posted, stored) and same_secret(cookie, stored)


def uid_of(raw):
    try:
        o = json.loads(raw.decode())
    except Exception:
        return None
    if not isinstance(o, dict):
        return None
    for k in ("id", "user_id"):
        if isinstance(o.get(k), str) and o[k]:
            return o[k]
    u = o.get("user")
    return u.get("id") if isinstance(u, dict) and isinstance(u.get("id"), str) else None


def content_length(headers):
    raw = headers.get("Content-Length")
    if raw is None or raw == "":
        return 0
    if not isinstance(raw, str) or not raw.isascii() or not raw.isdigit():
        return None
    n = int(raw)
    if n > MAX_BODY:
        return None
    return n


def up(path, method, body, tok):
    hdrs = {"Accept": "application/json"}
    if method == "POST":
        hdrs["Content-Type"] = "application/json"
    if tok:
        hdrs["Cookie"] = f"{TOKEN}={tok}"
    req = urllib.request.Request(UPSTREAM + path, data=body, method=method, headers=hdrs)
    try:
        with OPENER.open(req, timeout=TIMEOUT) as r:
            d = r.read(MAX_BODY + 1)
            if len(d) > MAX_BODY:
                return 502, b"{}", ""
            return r.status, d, r.headers.get("Set-Cookie", "")
    except urllib.error.HTTPError as e:
        return e.code, e.read(MAX_BODY), e.headers.get("Set-Cookie", "")
    except Exception:
        return 502, b"{}", ""


def current(tok):
    c, raw, _ = up(AUTH_SESSION, "GET", None, tok)
    return uid_of(raw) if c == 200 else None


def proxy_allowed(method, path):
    if method == "GET":
        return path in (AUTH_SESSION, "/api/v1/auths")
    if method == "POST":
        return path in (AUTH_SIGNIN, AUTH_SIGNUP)
    return False


class H(BaseHTTPRequestHandler):
    def log_message(self, fmt, *a):
        return

    def sendb(self, code, body, ctype="text/html", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for e in extra or []:
            k, _, v = e.partition(":")
            self.send_header(k.strip(), v.strip())
        self.end_headers()
        self.wfile.write(body)

    def body(self):
        n = content_length(self.headers)
        if n is None:
            return None
        return self.rfile.read(n) if n else b""

    def admin_ok(self):
        return self.client_address[0] in ("127.0.0.1", "::1") and self.headers.get("X-Harness-Admin") == admin

    def do_GET(self):
        p = urlparse(self.path).path
        if p in ("/", "/ui/login"):
            return self.sendb(200, LOGIN)
        if p == "/control/owner" and self.admin_ok():
            global expected
            v = self.headers.get("X-Expected-User")
            if v:
                with lock:
                    expected = v
            return self.sendb(200, b'{"ok":true}', "application/json")
        if p == "/bridge/start":
            return self.start()
        if p == "/status":
            with lock:
                c, b = dict(counters), bound
            return self.sendb(200, html("status", f"<p>bound:{int(b)}</p><p>bind_ok:{c['bind_ok']} bind_fail:{c['bind_fail']} proxy_ok:{c['proxy_ok']} proxy_fail:{c['proxy_fail']}</p>"))
        if proxy_allowed("GET", p):
            return self.proxy("GET")
        self.sendb(404, html("no", "<p>fail</p>"))

    def do_POST(self):
        p = urlparse(self.path).path
        if p == "/bridge/confirm":
            return self.confirm()
        if proxy_allowed("POST", p):
            return self.proxy("POST")
        self.sendb(404, html("no", "<p>fail</p>"))

    def proxy(self, method):
        p = urlparse(self.path).path
        if not proxy_allowed(method, p):
            inc("proxy_fail")
            return self.sendb(404, b'{"ok":false}', "application/json")
        b = self.body()
        tok = token_of(self.headers.get("Cookie"))
        if b is None or tok in ("__dup__", "__bad__"):
            inc("proxy_fail")
            return self.sendb(400 if tok in ("__dup__", "__bad__") else 413, b'{"ok":false}', "application/json")
        lookup = method == "GET" and p.rstrip("/") == "/api/v1/auths"
        if lookup and not tok:
            inc("proxy_fail")
            return self.sendb(401, b'{"ok":false}', "application/json")
        code, raw, setc = up(p if p.endswith("/") or not lookup else AUTH_SESSION, method, None if method == "GET" else b, tok if lookup else None)
        extra = []
        if method == "POST" and p in (AUTH_SIGNIN, AUTH_SIGNUP):
            scook = SimpleCookie()
            try:
                scook.load(setc)
            except Exception:
                pass
            if TOKEN in scook:
                extra.append("Set-Cookie: " + sc(TOKEN, scook[TOKEN].value))
            u = uid_of(raw)
            inc("proxy_ok" if u else "proxy_fail")
            return self.sendb(200 if u else 401, b'{"ok":true}' if u else b'{"ok":false}', "application/json", extra)
        u = uid_of(raw) if lookup else None
        inc("proxy_ok" if (u or (not lookup and code < 400)) else "proxy_fail")
        if lookup:
            return self.sendb(200 if u else 401, b'{"ok":true}' if u else b'{"ok":false}', "application/json")
        self.sendb(code if code < 500 else 502, b'{"ok":true}' if code < 400 else b'{"ok":false}', "application/json")

    def start(self):
        global csrf_v, chal_v, started
        tok = token_of(self.headers.get("Cookie"))
        if not tok or tok in ("__dup__", "__bad__"):
            inc("bind_fail")
            return self.sendb(401, html("start", "<p>fail</p>"))
        uid = current(tok)
        with lock:
            exp, al = expected, bound
        if al or not uid or not exp or uid != exp:
            inc("bind_fail")
            return self.sendb(403, html("start", "<p>fail</p>"))
        with lock:
            csrf_v, chal_v, started = secrets.token_urlsafe(24), secrets.token_urlsafe(24), True
            cv, ch = csrf_v, chal_v
        form = f"<h1>Confirm A</h1><form method=post action=/bridge/confirm><input type=hidden name=csrf value='{cv}'><button>confirm</button></form>"
        self.sendb(200, html("start", form), extra=["Set-Cookie: " + sc(CSRF, cv), "Set-Cookie: " + sc(CHAL, ch), "Set-Cookie: " + sc(SID, secrets.token_urlsafe(16))])

    def confirm(self):
        global bound, csrf_v
        if not origin_ok(self.headers.get("Origin"), origin):
            inc("bind_fail")
            return self.sendb(403, html("confirm", "<p>fail</p>"))
        ck = cookies(self.headers.get("Cookie"))
        if ck is None or dup_protected(ck) or len(ck.get(TOKEN, [])) != 1:
            inc("bind_fail")
            return self.sendb(400, html("confirm", "<p>fail</p>"))
        b = self.body()
        if b is None:
            inc("bind_fail")
            return self.sendb(413, html("confirm", "<p>fail</p>"))
        posted = ""
        if b:
            for part in b.decode("ascii", "strict").split("&") if b.isascii() else []:
                k, _, v = part.partition("=")
                if k == "csrf":
                    posted = v
            if not b.isascii():
                posted = ""
        chal_c = (ck.get(CHAL) or [None])[0]
        csrf_c = (ck.get(CSRF) or [None])[0]
        with lock:
            scsrf, schal, al, st = csrf_v, chal_v, bound, started
        if not st or al or not same_secret(chal_c, schal) or not csrf_ok(posted, csrf_c, scsrf):
            inc("bind_fail")
            return self.sendb(403, html("confirm", "<p>fail</p>"))
        uid = current(ck[TOKEN][0])
        with lock:
            if bound or uid != expected or not uid:
                counters["bind_fail"] += 1
                ok = False
            else:
                bound, csrf_v = True, ""
                counters["bind_ok"] += 1
                ok = True
        self.sendb(200 if ok else 403, html("confirm", "<p>ok</p>" if ok else "<p>fail</p>"))


def main():
    global origin, expected
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--cert", required=True)
    p.add_argument("--key", required=True)
    p.add_argument("--https-origin", required=True)
    p.add_argument("--expected-user-id", default="")
    a = p.parse_args()
    if not a.https_origin.startswith("https://"):
        raise SystemExit("https-origin must be HTTPS")
    origin = a.https_origin.rstrip("/")
    if a.expected_user_id:
        expected = a.expected_user_id
    s = ThreadingHTTPServer(("127.0.0.1", a.port), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(a.cert, a.key)
    s.socket = ctx.wrap_socket(s.socket, server_side=True)
    log(f"listen 127.0.0.1:{a.port} (admin cap not printed)")
    s.serve_forever()


if __name__ == "__main__":
    main()

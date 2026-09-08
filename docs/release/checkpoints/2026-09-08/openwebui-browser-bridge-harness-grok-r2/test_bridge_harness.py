#!/usr/bin/env python3
"""Unit tests: cookie filter/dup, Origin/CSRF, confirm handler, no-redirect."""
import io
import unittest
from unittest.mock import patch
from email.message import Message
import urllib.request
import bridge_harness as h

ORIGIN = "https://127.0.0.1:8443"


class CookieFilter(unittest.TestCase):
    def test_single_token(self):
        self.assertEqual(h.token_of("token=abc"), "abc")

    def test_missing_token(self):
        self.assertIsNone(h.token_of(""))
        self.assertIsNone(h.token_of("other=x"))

    def test_duplicate_token_refused(self):
        self.assertEqual(h.token_of("token=a; token=b"), "__dup__")
        ck = h.cookies("token=a; token=b")
        self.assertEqual(ck[h.TOKEN], ["a", "b"])

    def test_duplicate_challenge_csrf_refused(self):
        ck = h.cookies(f"{h.CHAL}=x; {h.CHAL}=y")
        self.assertTrue(h.dup_protected(ck))
        ck = h.cookies(f"{h.CSRF}=x; {h.CSRF}=y; token=t")
        self.assertTrue(h.dup_protected(ck))

    def test_malformed_cookie_syntax_refused(self):
        self.assertIsNone(h.cookies("token"))
        self.assertIsNone(h.cookies("token=a;; other=b"))
        self.assertIsNone(h.cookies("token=a;"))
        self.assertEqual(h.token_of("not-a-pair"), "__bad__")

    def test_unicode_cookie_refused(self):
        self.assertIsNone(h.cookies("token=café"))
        self.assertIsNone(h.cookies("tokeñ=abc"))
        self.assertEqual(h.token_of("token=\u202eabc"), "__bad__")

    def test_non_token_cookies_ignored_for_lookup(self):
        self.assertEqual(h.token_of("sid=z; token=only"), "only")


class OriginCsrf(unittest.TestCase):
    def test_exact_origin(self):
        self.assertTrue(h.origin_ok("https://127.0.0.1:8443", "https://127.0.0.1:8443"))
        self.assertFalse(h.origin_ok("https://evil.example", "https://127.0.0.1:8443"))
        self.assertFalse(h.origin_ok(None, "https://127.0.0.1:8443"))
        self.assertFalse(h.origin_ok("", "https://127.0.0.1:8443"))

    def test_csrf_must_match_cookie_and_store(self):
        s = "secret"
        self.assertTrue(h.csrf_ok(s, s, s))
        self.assertFalse(h.csrf_ok("x", s, s))
        self.assertFalse(h.csrf_ok(s, "x", s))
        self.assertFalse(h.csrf_ok(s, s, "x"))
        self.assertFalse(h.csrf_ok(None, s, s))
        self.assertFalse(h.csrf_ok(s, None, s))
        self.assertFalse(h.csrf_ok(s, s, None))
        self.assertFalse(h.csrf_ok("", "", ""))
        self.assertFalse(h.csrf_ok("sécret", "sécret", "sécret"))


class ContentLength(unittest.TestCase):
    def test_nonnegative_ascii_digits(self):
        m = Message()
        m["Content-Length"] = "10"
        self.assertEqual(h.content_length(m), 10)
        m = Message()
        m["Content-Length"] = "0"
        self.assertEqual(h.content_length(m), 0)
        m = Message()
        self.assertEqual(h.content_length(m), 0)

    def test_negative_and_non_ascii_rejected(self):
        m = Message()
        m["Content-Length"] = "-1"
        self.assertIsNone(h.content_length(m))
        m = Message()
        m["Content-Length"] = "+3"
        self.assertIsNone(h.content_length(m))
        m = Message()
        m["Content-Length"] = "１"
        self.assertIsNone(h.content_length(m))

    def test_oversized_rejected(self):
        m = Message()
        m["Content-Length"] = str(h.MAX_BODY + 1)
        self.assertIsNone(h.content_length(m))


class NoRedirect(unittest.TestCase):
    def test_redirect_request_returns_none(self):
        req = urllib.request.Request("http://127.0.0.1/from")
        self.assertIsNone(
            h.NoRedirect().redirect_request(req, None, 302, "Found", {}, "http://evil.example/to")
        )

    def test_opener_installs_no_redirect(self):
        kinds = [type(x) for x in h.OPENER.handlers]
        self.assertIn(h.NoRedirect, kinds)


class LoginPayload(unittest.TestCase):
    def test_signup_includes_name_and_json_header(self):
        page = h.LOGIN.decode()
        self.assertIn("name:'bridge-user'", page)
        self.assertIn("application/json", page)
        self.assertEqual(h.SYNTH_NAME, "bridge-user")


class RoutesAndLogging(unittest.TestCase):
    def test_proxy_routes_narrow(self):
        self.assertTrue(h.proxy_allowed("GET", "/api/v1/auths/"))
        self.assertTrue(h.proxy_allowed("POST", "/api/v1/auths/signin"))
        self.assertTrue(h.proxy_allowed("POST", "/api/v1/auths/signup"))
        self.assertFalse(h.proxy_allowed("GET", "/api/v1/auths/signin"))
        self.assertFalse(h.proxy_allowed("POST", "/api/v1/auths/"))
        self.assertFalse(h.proxy_allowed("GET", "/api/v1/auths/admin"))
        self.assertFalse(h.proxy_allowed("POST", "/api/v1/auths/add"))

    def test_log_message_is_noop(self):
        class A(h.H):
            def __init__(self):
                pass
        A().log_message("%s", "token=secret")


class Adapter(h.H):
    def __init__(self, headers, raw=b""):
        self.headers = headers
        self.rfile = io.BytesIO(raw)
        self.wfile = io.BytesIO()
        self.client_address = ("127.0.0.1", 0)
        self.status = None
        self.payload = None

    def send_response(self, code, message=None):
        self.status = code

    def send_header(self, k, v):
        pass

    def end_headers(self):
        pass

    def sendb(self, code, body, ctype="text/html", extra=None):
        self.status = code
        self.payload = body


def hdr(origin=ORIGIN, cookie="", length=None):
    m = Message()
    if origin is not None:
        m["Origin"] = origin
    if cookie:
        m["Cookie"] = cookie
    if length is not None:
        m["Content-Length"] = length
    return m


class ConfirmHandler(unittest.TestCase):
    def setUp(self):
        h.bound = False
        h.started = True
        h.csrf_v = "c"
        h.chal_v = "h"
        h.expected = "owner-a"
        h.origin = ORIGIN
        h.counters["bind_ok"] = 0
        h.counters["bind_fail"] = 0

    def _ck(self, extra=""):
        base = f"token=t; {h.CHAL}=h; {h.CSRF}=c"
        return base if not extra else base + "; " + extra

    @patch("bridge_harness.current", return_value="owner-a")
    def test_success_then_replay(self, _cur):
        body = b"csrf=c"
        a = Adapter(hdr(cookie=self._ck(), length=str(len(body))), body)
        h.H.confirm(a)
        self.assertEqual(a.status, 200)
        self.assertTrue(h.bound)
        self.assertEqual(h.counters["bind_ok"], 1)
        b2 = Adapter(hdr(cookie=self._ck(), length=str(len(body))), body)
        h.H.confirm(b2)
        self.assertEqual(b2.status, 403)
        self.assertEqual(h.counters["bind_fail"], 1)
        self.assertTrue(h.bound)

    @patch("bridge_harness.current", return_value="owner-b")
    def test_wrong_identity_against_a_expectation(self, _cur):
        body = b"csrf=c"
        a = Adapter(hdr(cookie=self._ck(), length=str(len(body))), body)
        h.H.confirm(a)
        self.assertEqual(a.status, 403)
        self.assertFalse(h.bound)
        self.assertEqual(h.counters["bind_fail"], 1)
        self.assertEqual(h.counters["bind_ok"], 0)

    @patch("bridge_harness.current", return_value="owner-a")
    def test_missing_origin(self, _cur):
        body = b"csrf=c"
        a = Adapter(hdr(origin=None, cookie=self._ck(), length=str(len(body))), body)
        h.H.confirm(a)
        self.assertEqual(a.status, 403)
        self.assertEqual(h.counters["bind_fail"], 1)

    @patch("bridge_harness.current", return_value="owner-a")
    def test_wrong_origin(self, _cur):
        body = b"csrf=c"
        a = Adapter(hdr(origin="https://evil.example", cookie=self._ck(), length=str(len(body))), body)
        h.H.confirm(a)
        self.assertEqual(a.status, 403)

    @patch("bridge_harness.current", return_value="owner-a")
    def test_missing_csrf(self, _cur):
        body = b""
        a = Adapter(hdr(cookie=self._ck(), length="0"), body)
        h.H.confirm(a)
        self.assertEqual(a.status, 403)
        self.assertEqual(h.counters["bind_fail"], 1)

    @patch("bridge_harness.current", return_value="owner-a")
    def test_wrong_csrf(self, _cur):
        body = b"csrf=nope"
        a = Adapter(hdr(cookie=self._ck(), length=str(len(body))), body)
        h.H.confirm(a)
        self.assertEqual(a.status, 403)

    @patch("bridge_harness.current", return_value="owner-a")
    def test_duplicate_token_cookies(self, _cur):
        body = b"csrf=c"
        cookie = f"token=a; token=b; {h.CHAL}=h; {h.CSRF}=c"
        a = Adapter(hdr(cookie=cookie, length=str(len(body))), body)
        h.H.confirm(a)
        self.assertEqual(a.status, 400)
        self.assertEqual(h.counters["bind_fail"], 1)
        self.assertFalse(h.bound)

    @patch("bridge_harness.current", return_value="owner-a")
    def test_duplicate_csrf_cookies(self, _cur):
        body = b"csrf=c"
        cookie = f"token=t; {h.CHAL}=h; {h.CSRF}=c; {h.CSRF}=d"
        a = Adapter(hdr(cookie=cookie, length=str(len(body))), body)
        h.H.confirm(a)
        self.assertEqual(a.status, 400)

    @patch("bridge_harness.current", return_value="owner-a")
    def test_oversized_body_rejected(self, _cur):
        a = Adapter(hdr(cookie=self._ck(), length=str(h.MAX_BODY + 1)), b"")
        h.H.confirm(a)
        self.assertEqual(a.status, 413)
        self.assertFalse(h.bound)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Rows for the MCP events OAuth shim (MIK-7893): the token response is not
cached, and a request body is size-bounded before anything reads it."""
import argparse
import http.client
import importlib.util
import os
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer

SPEC = importlib.util.spec_from_file_location(
    "shim", os.path.join(os.path.dirname(os.path.abspath(__file__)), "mcp_events_oauth_shim.py"))
shim = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(shim)


class ShimRows(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.log = tempfile.NamedTemporaryFile(delete=False)
        shim.Shim.cfg = argparse.Namespace(
            upstream=1, public="https://shim.test", api_key="k", log=cls.log.name,
            lock=threading.Lock(), redirect_hosts=["chatgpt.com"])
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), shim.Shim)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        os.unlink(cls.log.name)

    def request(self, method, path, body=b"", headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request(method, path, body=body, headers=headers or {})
        resp = conn.getresponse()
        data = resp.read()
        return resp, data

    def test_token_responses_are_not_cacheable(self):
        # A known refresh token gets a 200 token reply, an unknown one a 400;
        # both are token-endpoint answers and neither may be cached.
        shim.REFRESH.add("r-known")
        for form in (b"grant_type=refresh_token&refresh_token=r-known",
                     b"grant_type=refresh_token&refresh_token=nope"):
            resp, _ = self.request("POST", "/token", form,
                                   {"content-type": "application/x-www-form-urlencoded"})
            self.assertEqual(resp.getheader("cache-control"), "no-store", form)
            self.assertEqual(resp.getheader("pragma"), "no-cache", form)

    def test_an_oversize_body_is_refused_before_it_is_read(self):
        # The declared length is over the bound: the shim answers 413 without
        # waiting for, or buffering, the body.
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.putrequest("POST", "/token")
        conn.putheader("content-length", str(64 * 1024 * 1024))
        conn.putheader("content-type", "application/x-www-form-urlencoded")
        conn.endheaders()
        resp = conn.getresponse()
        self.assertEqual(resp.status, 413)
        resp.read()


if __name__ == "__main__":
    unittest.main()

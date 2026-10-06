#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Rows for the MCP events fail-fast harness: a signed delivery over https
never negotiates below TLS 1.2, whatever the platform's OpenSSL default."""
import base64
import importlib.util
import os
import socket
import ssl
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location(
    "failfast", os.path.join(os.path.dirname(os.path.abspath(__file__)), "mcp_events_failfast.py"))
failfast = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(failfast)


class TlsFloor(unittest.TestCase):
    def test_delivery_pins_tls12_over_a_permissive_platform_default(self):
        # Python 3.13 on a host whose OpenSSL policy allows it leaves
        # minimum_version at MINIMUM_SUPPORTED; stand that platform in here.
        real = ssl.create_default_context

        def permissive(*a, **kw):
            ctx = real(*a, **kw)
            ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
            return ctx

        seen = []

        def capture(ctx, sock, **kw):
            seen.append(ctx.minimum_version)
            raise ssl.SSLError("stop before the handshake")

        with socket.create_server(("127.0.0.1", 0)) as listener, \
                mock.patch.object(ssl, "create_default_context", permissive), \
                mock.patch.object(ssl.SSLContext, "wrap_socket", capture):
            port = listener.getsockname()[1]
            status, err = failfast.post_signed(
                f"https://127.0.0.1:{port}/hook", b"k", "m", "s", b"{}", allow_local=True)

        self.assertEqual((status, err), (None, "tls_error"))
        self.assertEqual(len(seen), 1, "the https path must wrap the socket once")
        self.assertGreaterEqual(seen[0], ssl.TLSVersion.TLSv1_2)


class SubscribeAndServe(unittest.TestCase):
    """MIK-7745: a malformed delivery port is an InvalidParams answer, not a
    dropped connection; `serve` tightens only a directory it created."""

    def subscribe(self, stub, url):
        secret = "whsec_" + base64.b64encode(b"k" * 32).decode()
        msg = {"jsonrpc": "2.0", "id": 1, "method": "events/subscribe",
               "params": {"name": failfast.EVENT["name"], "arguments": {"topic": "a"},
                          "delivery": {"mode": "webhook", "url": url, "secret": secret}}}
        return stub.rpc(msg, {})

    def test_a_malformed_delivery_port_is_invalid_params(self):
        with tempfile.TemporaryDirectory() as d:
            stub = failfast.Stub(os.path.join(d, "subs.json"), os.path.join(d, "log.jsonl"), None, allow_local=False)
            for url in ("https://example.com:abc/hook", "https://example.com:99999/hook"):
                with self.subTest(url=url):
                    out = self.subscribe(stub, url)
                    self.assertEqual(out["error"]["code"], -32602, out)
                    self.assertEqual(out["error"]["data"], {"field": "delivery.url"}, out)

    @unittest.skipIf(os.name == "nt", "POSIX permission bits")
    def test_serve_tightens_only_a_directory_it_creates(self):
        with tempfile.TemporaryDirectory() as d:
            existing = os.path.join(d, "checkout")
            os.mkdir(existing)
            os.chmod(existing, 0o755)
            failfast.prepare_dir(existing)
            self.assertEqual(os.stat(existing).st_mode & 0o777, 0o755, "an existing directory is left as it was")
            fresh = os.path.join(d, "fresh")
            failfast.prepare_dir(fresh)
            self.assertEqual(os.stat(fresh).st_mode & 0o777, 0o700, "a created directory is owner-only")


class ContentLength(unittest.TestCase):
    def test_only_space_and_tab_surround_the_digits(self):
        # MIK-7881.STUB.1: HTTP allows SP/HTAB around a field value; str.strip()
        # also takes vertical tab and form feed.
        for bad in ("\x0b5", "5\x0c", "\x0c5\x0b"):
            self.assertEqual(failfast.body_length({"Content-Length": bad}), (0, 400), repr(bad))
        self.assertEqual(failfast.body_length({"Content-Length": " \t5\t "}), (5, None))


if __name__ == "__main__":
    unittest.main()

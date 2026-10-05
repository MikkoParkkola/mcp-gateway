#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Rows for the MCP events fail-fast harness: a signed delivery over https
never negotiates below TLS 1.2, whatever the platform's OpenSSL default."""
import importlib.util
import os
import socket
import ssl
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


if __name__ == "__main__":
    unittest.main()

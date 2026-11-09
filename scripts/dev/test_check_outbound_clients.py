#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Rows for check-outbound-clients.py: PRIVACY.md lists every place product
code can open an outbound connection, and a new one fails until it is listed.

Each row is a synthetic tree; the resolver and the cfg reader are the orphan
checker's, so test code is excluded exactly as the other gates exclude it.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

SCRIPT = Path(__file__).resolve().parent / "check-outbound-clients.py"
CLIENT = "fn get() { let _c = reqwest::Client::builder(); }\n"


def load(root: Path):
    spec = importlib.util.spec_from_file_location("check_outbound_clients", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.guard.ROOT = root
    module.ROOT = root
    return module


def tree(root: Path, files: dict[str, str]) -> None:
    for rel, body in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")


def listing(rows: dict[str, str]) -> str:
    return "file\tsites\tpurpose\n" + "".join(f"{f}\t{k}\tpurpose of {f}\n" for f, k in rows.items())


def privacy(*files: str) -> str:
    return "# Privacy\n\n| Call site | Purpose |\n|---|---|\n" + "".join(f"| `{f}` | x |\n" for f in files)


BASE = {
    "src/lib.rs": "mod fetch;\n#[cfg(test)]\nmod fetch_tests;\n",
    "src/fetch.rs": CLIENT,
    "src/fetch_tests.rs": CLIENT,
    "scripts/dev/outbound-sites.tsv": listing({"src/fetch.rs": "Client::builder=1"}),
    "docs/PRIVACY.md": privacy("src/fetch.rs"),
}


class Sites(unittest.TestCase):
    def run_check(self, files: dict[str, str]) -> tuple[int, str]:
        with TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            tree(root, files)
            err = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
                code = load(root).main([])
            return code, err.getvalue()

    def test_the_listed_tree_passes(self):
        self.assertEqual(self.run_check(BASE), (0, ""))

    def test_a_new_client_in_an_unlisted_file_fails_naming_it(self):
        code, err = self.run_check({**BASE, "src/lib.rs": BASE["src/lib.rs"] + "mod beacon;\n", "src/beacon.rs": CLIENT})
        self.assertEqual(code, 1)
        self.assertIn("src/beacon.rs", err)

    def test_a_second_client_in_a_listed_file_fails(self):
        code, err = self.run_check({**BASE, "src/fetch.rs": CLIENT + "fn again() { let _ = std::net::TcpStream::connect(\"x:1\"); }\n"})
        self.assertEqual(code, 1)
        self.assertIn("src/fetch.rs: 2 sites, listed 1", err)

    def test_a_removed_client_fails_until_the_list_shrinks(self):
        code, err = self.run_check({**BASE, "src/fetch.rs": "fn get() {}\n"})
        self.assertEqual(code, 1)
        self.assertIn("src/fetch.rs: 0 sites, listed 1", err)

    def test_test_only_files_and_inline_test_modules_do_not_count(self):
        inline = CLIENT + "#[cfg(test)]\nmod tests {\n    fn t() { let _c = reqwest::Client::new(); }\n}\n"
        self.assertEqual(self.run_check({**BASE, "src/fetch.rs": inline}), (0, ""))

    def test_a_comment_does_not_count(self):
        commented = CLIENT + "// reqwest::Client::new() would be wrong here\n"
        self.assertEqual(self.run_check({**BASE, "src/fetch.rs": commented}), (0, ""))

    def test_one_kind_of_client_replacing_another_fails(self):
        # Same count per file, different connection: a TCP connect where the HTTP client was.
        swapped = 'fn get() { let _c = std::net::TcpStream::connect("x:1"); }\n'
        code, err = self.run_check({**BASE, "src/fetch.rs": swapped})
        self.assertEqual(code, 1)
        self.assertIn("src/fetch.rs", err)
        self.assertIn("TcpStream::connect", err)

    def test_a_listed_file_missing_from_privacy_md_fails(self):
        code, err = self.run_check({**BASE, "docs/PRIVACY.md": privacy()})
        self.assertEqual(code, 1)
        self.assertIn("docs/PRIVACY.md does not name src/fetch.rs", err)

    def test_every_constructor_shape_counts(self):
        for shape in (
            "reqwest::Client::new()",
            "reqwest::ClientBuilder::new()",
            "Client::builder()",
            "tokio::net::TcpStream::connect(a)",
            "std::net::UdpSocket::bind(a)",
            "tokio_tungstenite::connect_async(r)",
            "client_async_tls(r, s)",
        ):
            with self.subTest(shape=shape):
                code, err = self.run_check({**BASE, "src/fetch.rs": CLIENT + f"fn more() {{ let _ = {shape}; }}\n"})
                self.assertEqual(code, 1, shape)
                self.assertIn("src/fetch.rs: 2 sites, listed 1", err)


if __name__ == "__main__":
    unittest.main()

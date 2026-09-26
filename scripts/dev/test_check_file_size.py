#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Pin what the file-size ratchet lets through and what it refuses (#609).

The gate exempts a module declaration so that extracting code out of an
over-ceiling file is not scored as growth. Everything that is not a bare
declaration must still count, or the exemption becomes the way to grow a file
with code. Each case runs the real gate over a synthetic tree with its own
baseline.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

SCRIPT = Path(__file__).resolve().parent / "check-file-size.py"
PARENT = "src/big.rs"
BASE = 805


def load_gate(root: Path):
    """Load the gate with ROOT and BASELINE pointed at a synthetic tree."""
    spec = importlib.util.spec_from_file_location("file_size_gate", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.ROOT = root
    module.BASELINE = root / "file-size-baseline.txt"
    return module


def body(lines: int) -> str:
    return "".join(f"fn f{i}() {{}}\n" for i in range(lines))


class FileSizeGate(unittest.TestCase):
    def run_gate(self, added_to_parent: str, extra: dict[str, str] | None = None):
        """Exit status and output for an 805-line baselined parent plus `added_to_parent`."""
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            files = {PARENT: body(BASE) + added_to_parent, **(extra or {})}
            for rel, text in files.items():
                (root / rel).parent.mkdir(parents=True, exist_ok=True)
                (root / rel).write_text(text, encoding="utf-8")
            (root / "file-size-baseline.txt").write_text(f"{BASE} {PARENT}\n", encoding="utf-8")
            gate = load_gate(root)
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                status = gate.main()
            return status, out.getvalue()

    def assert_passes(self, added: str, extra: dict[str, str] | None = None):
        status, out = self.run_gate(added, extra)
        self.assertEqual(status, 0, out)

    def assert_grew(self, added: str, extra: dict[str, str] | None = None):
        status, out = self.run_gate(added, extra)
        self.assertEqual(status, 1, out)
        self.assertIn(f"FAIL {PARENT}: grew {BASE} -> ", out)

    def test_t1_attaching_an_extracted_test_module_is_not_growth(self):
        # The #607 shape: three lines in the parent attach 292 lines that did
        # not land in it.
        self.assert_passes(
            '#[cfg(test)]\n#[path = "child.rs"]\nmod child;\n',
            {"src/child.rs": body(292)},
        )

    def test_t2_ordinary_growth_still_fails_with_the_existing_message(self):
        status, out = self.run_gate("fn a() {}\nfn b() {}\nfn c() {}\n")
        self.assertEqual(status, 1, out)
        self.assertIn(f"FAIL {PARENT}: grew {BASE} -> {BASE + 3} lines", out)

    def test_t3_inert_attributes_without_a_declaration_count(self):
        self.assert_grew("#[allow(dead_code)]\n#[allow(unused)]\n#[allow(clippy::all)]\n")

    def test_t3b_a_macro_attribute_above_a_declaration_counts(self):
        # A macro attribute expands to arbitrary code; only inert ones ride free.
        self.assert_grew("#[my_macro(a, b)]\nmod child;\n", {"src/child.rs": ""})

    def test_t3c_a_cfg_attr_above_a_declaration_counts(self):
        # `cfg_attr` can apply any attribute, a macro included, so it is not inert.
        self.assert_grew("#[cfg_attr(test, my_macro)]\nmod child;\n", {"src/child.rs": ""})

    def test_t4_an_inline_module_is_code_not_a_declaration(self):
        self.assert_grew("mod x { fn a() {} }\n")

    def test_t5_a_restricted_public_declaration_is_exempt(self):
        self.assert_passes("pub(crate) mod child;\n", {"src/child.rs": ""})

    def test_t5b_a_public_declaration_is_exempt(self):
        self.assert_passes("pub mod child;\n", {"src/child.rs": ""})

    def test_t5c_a_path_restricted_declaration_is_exempt(self):
        self.assert_passes("pub(in crate::x) mod child;\n", {"src/child.rs": ""})

    def test_t6_the_attached_file_is_held_to_the_ceiling(self):
        status, out = self.run_gate("mod child;\n", {"src/child.rs": body(801)})
        self.assertEqual(status, 1, out)
        self.assertIn("FAIL src/child.rs: 801 lines, over the 800-line ceiling", out)

    def test_t9_a_multi_line_attribute_above_a_declaration_counts(self):
        # Only single-line attributes are recognised; the rest err toward failing.
        self.assert_grew('#[cfg(all(\n    test,\n    unix\n))]\nmod child;\n', {"src/child.rs": ""})

    def test_t10_a_raw_identifier_declaration_counts(self):
        # `\w+` does not match `r#x`, so the line is counted. Pinned so a regex
        # change that starts exempting it is a decision, not an accident.
        self.assert_grew("mod r#x;\n", {"src/x.rs": ""})

    def test_t8_the_repository_tree_passes(self):
        gate = load_gate(Path(__file__).resolve().parents[2])
        gate.BASELINE = SCRIPT.with_name("file-size-baseline.txt")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            status = gate.main()
        self.assertEqual(status, 0, out.getvalue())


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Pin the false passes that two earlier versions of the orphan guard had.

A guard that reports "all declared" while a file is undeclared is worse than
no guard: it converts an unchecked property into a checked-looking one. Both
historical failure modes are reproduced here against synthetic trees, so a
future simplification of the resolver has to fail these rather than quietly
restore the hole.
"""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

SCRIPT = Path(__file__).resolve().parent / "check-orphan-test-modules.py"


def load_guard(root: Path):
    """Load the guard with its ROOT pointed at a synthetic tree."""
    spec = importlib.util.spec_from_file_location("orphan_guard", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.ROOT = root
    return module


def tree(root: Path, files: dict[str, str]) -> None:
    for rel, body in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")


class OrphanGuard(unittest.TestCase):
    def orphans_of(self, files: dict[str, str]) -> list[str]:
        # A crate root that declares each top-level module, unless the case
        # supplies its own: reachability starts at the root, so a tree
        # without one would report everything.
        if "src/lib.rs" not in files:
            tops = sorted({rel.split("/")[1] for rel in files if rel.count("/") >= 2})
            files = {"src/lib.rs": "".join(f"mod {top};\n" for top in tops), **files}
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            tree(root, files)
            guard = load_guard(root)
            return [str(p.relative_to(root)) for p in guard.orphans()]

    def test_a_declared_twin_does_not_answer_for_an_undeclared_file(self):
        # The defect that shipped: matching on the STEM meant declaring
        # `a/foo_tests.rs` silently satisfied an orphaned `b/foo_tests.rs`.
        # Five stems are duplicated in the real tree, so this is not
        # hypothetical -- it is the live shape of the hole.
        found = self.orphans_of(
            {
                "src/a/mod.rs": '#[cfg(test)]\n#[path = "foo_tests.rs"]\nmod foo_tests;\n',
                "src/a/foo_tests.rs": "",
                "src/b/mod.rs": "// nothing declares the sibling below\n",
                "src/b/foo_tests.rs": "",
            }
        )
        self.assertEqual(found, ["src/b/foo_tests.rs"])

    def test_a_commented_out_declaration_declares_nothing(self):
        # A `mod` line inside a comment is invisible to the compiler. Counting
        # it lets a disabled module keep reading as coverage.
        found = self.orphans_of(
            {
                "src/a/mod.rs": '// #[path = "foo_tests.rs"]\n// mod foo_tests;\n',
                "src/a/foo_tests.rs": "",
            }
        )
        self.assertEqual(found, ["src/a/foo_tests.rs"])

    def test_a_block_commented_declaration_declares_nothing(self):
        found = self.orphans_of(
            {
                "src/a/mod.rs": '/*\n#[path = "foo_tests.rs"]\nmod foo_tests;\n*/\n',
                "src/a/foo_tests.rs": "",
            }
        )
        self.assertEqual(found, ["src/a/foo_tests.rs"])

    def test_an_inline_module_backs_no_file(self):
        # `mod foo_tests { .. }` is an inline module. It compiles, but it is
        # not the file on disk, so the file remains in no compilation unit.
        found = self.orphans_of(
            {
                "src/a/mod.rs": "mod foo_tests {\n    // inline, backs no file\n}\n",
                "src/a/foo_tests.rs": "",
            }
        )
        self.assertEqual(found, ["src/a/foo_tests.rs"])

    def test_a_path_attribute_resolves_against_the_declaring_file(self):
        # `#[path]` is relative to the directory of the file that carries it,
        # which is how a non-`mod.rs` sibling declares a test file beside it.
        found = self.orphans_of(
            {
                "src/a/admission.rs": '#[cfg(test)]\n#[path = "admission_tests.rs"]\nmod admission_tests;\n',
                "src/a/admission_tests.rs": "",
                "src/a/mod.rs": "mod admission;\n",
            }
        )
        self.assertEqual(found, [])

    def test_a_plain_mod_in_a_non_mod_file_resolves_into_its_subdirectory(self):
        # `mod foo;` inside `a/thing.rs` means `a/thing/foo.rs`, NOT
        # `a/foo.rs`. Resolving it to the wrong directory would mark a
        # correctly declared file as an orphan.
        found = self.orphans_of(
            {
                "src/a/thing.rs": "mod inner_tests;\n",
                "src/a/thing/inner_tests.rs": "",
                "src/a/mod.rs": "mod thing;\n",
            }
        )
        self.assertEqual(found, [])

    def test_a_declared_file_is_not_reported(self):
        found = self.orphans_of(
            {
                "src/a/mod.rs": '#[cfg(test)]\n#[path = "foo_tests.rs"]\nmod foo_tests;\n',
                "src/a/foo_tests.rs": "",
            }
        )
        self.assertEqual(found, [])

    def test_a_declaration_inside_an_unreached_file_declares_nothing(self):
        # The MIK-7518 shape: `invoke.rs` lost `mod suggestion;`, and the
        # `#[path]` declaration inside the now-uncompiled `suggestion.rs` kept
        # vouching for its test file. Both are in no compilation unit.
        found = self.orphans_of(
            {
                "src/a/mod.rs": "// `mod suggestion;` was dropped here\n",
                "src/a/suggestion.rs": '#[cfg(test)]\n#[path = "suggestion_tests.rs"]\nmod suggestion_tests;\n',
                "src/a/suggestion_tests.rs": "",
            }
        )
        self.assertEqual(found, ["src/a/suggestion.rs", "src/a/suggestion_tests.rs"])

    def test_an_undeclared_production_module_is_reported(self):
        found = self.orphans_of({"src/a/mod.rs": "", "src/a/helper.rs": ""})
        self.assertEqual(found, ["src/a/helper.rs"])

    def test_a_crate_root_in_src_bin_owns_its_directory(self):
        found = self.orphans_of(
            {"src/bin/tool.rs": "mod helper;\n", "src/bin/helper.rs": ""}
        )
        self.assertEqual(found, [])

    def test_a_raw_identifier_declares_its_file(self):
        found = self.orphans_of(
            {"src/a/mod.rs": "pub mod r#override;\n", "src/a/override.rs": ""}
        )
        self.assertEqual(found, [])

    def test_a_declaration_inside_an_inline_module_resolves_below_it(self):
        found = self.orphans_of(
            {
                "src/a/mod.rs": "#[cfg(test)]\nmod tests {\n    mod fsm;\n}\n",
                "src/a/tests/fsm.rs": "",
            }
        )
        self.assertEqual(found, [])

    def test_the_real_tree_is_clean(self):
        # The guard must pass on the repository it ships in; a guard that is
        # red on arrival gets disabled rather than obeyed.
        guard = load_guard(SCRIPT.resolve().parents[2])
        self.assertEqual(guard.orphans(), [])


if __name__ == "__main__":
    unittest.main()

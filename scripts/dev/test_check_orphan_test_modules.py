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


class TestOnlyFiles(unittest.TestCase):
    """MIK-8405.SPLIT.5: which reachable files compile ONLY under test. The
    one resolver check_inventory_rows.py also uses, so these rows pin both
    gates. The three high-rated holes the #3860 review found in a second,
    since-deleted resolver are pinned here against this one."""

    def only_test_files(self, files: dict[str, str]) -> list[str]:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            tree(root, files)
            guard = load_guard(root)
            return sorted(str(p.relative_to(root.resolve())) for p in guard.test_only_files())

    def test_a_cfg_test_mount_is_test_only_and_a_plain_one_is_not(self):
        found = self.only_test_files(
            {
                "src/lib.rs": "mod a;\n",
                "src/a/mod.rs": '#[cfg(test)]\n#[path = "x_tests.rs"]\nmod x;\nmod y;\n',
                "src/a/x_tests.rs": "",
                "src/a/y.rs": "",
            }
        )
        self.assertEqual(found, ["src/a/x_tests.rs"])

    def test_a_commented_path_attribute_mounts_nothing(self):
        # #3860 review HIGH 1: `// #[path = ..]` above a cfg(test) mod must not
        # point that mod at the commented file.
        found = self.only_test_files(
            {
                "src/lib.rs": "mod a;\n",
                "src/a/mod.rs": '// #[path = "orphan_tests.rs"]\n#[cfg(test)]\nmod real;\n',
                "src/a/real.rs": "",
                "src/a/orphan_tests.rs": "",
            }
        )
        self.assertEqual(found, ["src/a/real.rs"])

    def test_a_test_declaration_inside_an_unreachable_parent_reaches_nothing(self):
        # #3860 review HIGH 2: a cfg(test) mod in a file no root reaches does
        # not make its child test-only: neither is compiled.
        found = self.only_test_files(
            {
                "src/lib.rs": "",
                "src/a/mod.rs": "#[cfg(test)]\nmod child_tests;\n",
                "src/a/child_tests.rs": "",
            }
        )
        self.assertEqual(found, [])

    def test_cfg_test_mode_is_not_test(self):
        # #3860 review HIGH 3: `cfg(all(test_mode))` builds outside tests.
        found = self.only_test_files(
            {
                "src/lib.rs": "#[cfg(all(test_mode))]\nmod m_tests;\n#[cfg(all(feature = \"x\", test))]\nmod n_tests;\n",
                "src/m_tests.rs": "",
                "src/n_tests.rs": "",
            }
        )
        self.assertEqual(found, ["src/n_tests.rs"])

    def test_a_cfg_test_on_a_use_does_not_reach_the_next_mod(self):
        found = self.only_test_files(
            {
                "src/lib.rs": "#[cfg(test)]\nuse std::fmt;\nmod prod;\n",
                "src/prod.rs": "",
            }
        )
        self.assertEqual(found, [])

    def test_an_inline_cfg_test_module_makes_its_children_test_only(self):
        found = self.only_test_files(
            {
                "src/lib.rs": "#[cfg(test)]\nmod tests {\n    mod boot;\n}\nmod live;\n",
                "src/tests/boot.rs": "",
                "src/live.rs": "",
            }
        )
        self.assertEqual(found, ["src/tests/boot.rs"])

    def test_a_file_reached_only_from_an_integration_test_root_is_test_only(self):
        found = self.only_test_files(
            {
                "src/lib.rs": "",
                "tests/it.rs": '#[path = "../src/fixture_support.rs"]\nmod support;\n',
                "src/fixture_support.rs": "",
            }
        )
        # The integration-test root itself compiles only for tests too.
        self.assertEqual(found, ["src/fixture_support.rs", "tests/it.rs"])


    def test_an_inner_cfg_test_gates_its_whole_source_and_children(self):
        # #3860 round 2 (gpt, muse): `#![cfg(test)]` gates the whole source.
        found = self.only_test_files(
            {
                "src/lib.rs": "mod helpers;\nmod live;\n",
                "src/helpers.rs": "#![cfg(test)]\nmod child;\n",
                "src/helpers/child.rs": "",
                "src/live.rs": "#![cfg(unix)]\n",
            }
        )
        self.assertEqual(found, ["src/helpers.rs", "src/helpers/child.rs"])

    def test_braces_in_another_attribute_keep_a_pending_cfg_test(self):
        # #3860 round 2 (gpt): `{` inside `#[doc = concat!{..}]` is no item end.
        found = self.only_test_files(
            {
                "src/lib.rs": '#[cfg(test)]\n#[doc = concat!{"x"}]\nmod t;\n',
                "src/t.rs": "",
            }
        )
        self.assertEqual(found, ["src/t.rs"])

    def test_a_source_reached_by_a_test_and_a_production_chain_is_not_test_only(self):
        # #3860 round 2 (gpt): one plain chain is enough to ship it.
        found = self.only_test_files(
            {
                "src/lib.rs": '#[cfg(test)]\n#[path = "shared.rs"]\nmod a;\n#[path = "shared.rs"]\nmod b;\n',
                "src/shared.rs": "",
            }
        )
        self.assertEqual(found, [])

    def test_a_bracket_in_a_char_literal_does_not_swallow_a_declaration(self):
        # #3860 round 3 (muse HIGH, gpt): '[' and '{' in char literals.
        found = self.only_test_files(
            {
                "src/lib.rs": "#[doc = concat!('[')]\nconst C: char = '{';\n#[cfg(test)]\nmod a;\n",
                "src/a.rs": "",
            }
        )
        self.assertEqual(found, ["src/a.rs"])

class Blank(unittest.TestCase):
    def test_a_c_raw_string_with_an_inner_quote_blanks_only_itself(self):
        # MIK-8691: `cr#"…"#` read as a plain string ran to the end of the
        # file and blanked every later line, hiding them from the guards.
        guard = load_guard(Path("."))
        text = 'let s = cr#"a"b"#;\nx.unwrap();\n'
        out, literals = guard.blank(text)
        self.assertEqual(len(out), len(text))
        self.assertEqual(out.splitlines()[1], "x.unwrap();")
        self.assertIn('a"b', literals.values())


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

    def test_a_directory_binary_root_owns_its_directory(self):
        # `src/bin/tool/main.rs` is a crate root; `helper.rs` beside it is
        # not, so only the root's declaration can reach it.
        found = self.orphans_of(
            {"src/bin/tool/main.rs": "mod helper;\n", "src/bin/tool/helper.rs": ""}
        )
        self.assertEqual(found, [])

    def test_a_path_declaration_does_not_also_claim_the_default_file(self):
        found = self.orphans_of(
            {
                "src/a/mod.rs": '#[path = "actual.rs"]\nmod named;\n',
                "src/a/actual.rs": "",
                "src/a/named.rs": "",
            }
        )
        self.assertEqual(found, ["src/a/named.rs"])

    def test_a_raw_identifier_path_declaration_declares_its_file(self):
        found = self.orphans_of(
            {"src/a/mod.rs": '#[path = "kind.rs"]\nmod r#type;\n', "src/a/kind.rs": ""}
        )
        self.assertEqual(found, [])

    def test_a_declaration_inside_a_string_declares_nothing(self):
        found = self.orphans_of(
            {
                "src/a/mod.rs": 'const DOC: &str = "mod foo;";\nconst RAW: &str = r#"mod bar;"#;\n',
                "src/a/foo.rs": "",
                "src/a/bar.rs": "",
            }
        )
        self.assertEqual(found, ["src/a/bar.rs", "src/a/foo.rs"])

    def test_a_declaration_inside_a_nested_block_comment_declares_nothing(self):
        found = self.orphans_of(
            {"src/a/mod.rs": "/* outer /* inner */ mod foo; */\n", "src/a/foo.rs": ""}
        )
        self.assertEqual(found, ["src/a/foo.rs"])

    def test_an_inline_module_does_not_lend_its_name_to_a_sibling_declaration(self):
        # `mod inner;` sits OUTSIDE `mod tests { }`, so it names `a/inner.rs`,
        # and `a/tests/inner.rs` is in no compilation unit.
        found = self.orphans_of(
            {
                "src/a/mod.rs": "mod tests {\n}\nmod inner;\n",
                "src/a/inner.rs": "",
                "src/a/tests/inner.rs": "",
            }
        )
        self.assertEqual(found, ["src/a/tests/inner.rs"])

    def test_a_quote_char_literal_does_not_open_a_string(self):
        found = self.orphans_of(
            {"src/a/mod.rs": "const Q: char = '\"';\nfn f<'a>(_: &'a str) {}\nmod foo;\n", "src/a/foo.rs": ""}
        )
        self.assertEqual(found, [])

    def test_nested_inline_modules_resolve_through_every_level(self):
        found = self.orphans_of(
            {
                "src/a/mod.rs": "mod x {\n    fn f() {}\n    mod y {\n        mod z;\n    }\n}\n",
                "src/a/x/y/z.rs": "",
            }
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

    def test_a_raw_string_path_declares_its_file(self):
        found = self.orphans_of(
            {
                "src/a/mod.rs": '#[path = r"actual.rs"]\nmod named;\n#[path = r#"other.rs"#]\nmod named2;\n',
                "src/a/actual.rs": "",
                "src/a/other.rs": "",
            }
        )
        self.assertEqual(found, [])

    def test_a_child_of_a_path_loaded_file_resolves_beside_it(self):
        # rustc treats a `#[path]` file as mod-rs: `mod child;` inside
        # `actual.rs` is `child.rs` next to it, not `actual/child.rs`.
        found = self.orphans_of(
            {
                "src/a/mod.rs": '#[path = "actual.rs"]\nmod named;\n',
                "src/a/actual.rs": "mod child;\n",
                "src/a/child.rs": "",
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

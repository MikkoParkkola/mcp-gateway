#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Rows for scripts/dev/test_parts.py, the lib test split's codemod and checker.

Every test function compiles in exactly one part: one `#[cfg(tpK)]` on itself or an ancestor, K from the directory
table. Each row seeds one way to break that (or a table, build.rs or shared-list rule) on a synthetic tree and
asserts the refusal by its code; the tagged base tree is green. Run with the gates' environment (tree-sitter):
scripts/gate-env/.venv/bin/python scripts/dev/test_test_parts.py
"""

from __future__ import annotations

import importlib.util
import unittest
import unittest.mock
from pathlib import Path
from tempfile import TemporaryDirectory

SCRIPT = Path(__file__).resolve().parent / "test_parts.py"
TAG_LINE_PREFIX = "#[cfg(tp"
SHARED = "scripts/dev/test-parts-shared.txt"
TABLE = "scripts/dev/test-parts.tsv"
BUILD = "scripts/dev/test-parts-build.rs"


def load_tool():
    spec = importlib.util.spec_from_file_location("test_parts", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_tree(root: Path, files: dict[str, str]) -> None:
    for rel, body in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")


def read_tree(root: Path) -> dict[str, str]:
    return {
        str(p.relative_to(root)): p.read_text(encoding="utf-8")
        for p in sorted(root.rglob("*"))
        if p.is_file()
    }


CRATE_ALLOW = "#![cfg_attr(tp_partial, allow(dead_code, unused_imports, unused_variables))]\n"

# Two parts: `src` (and src/a) in part 1, src/b in part 2. Tagged and green.
BASE = {
    BUILD: "fn main() {\n    const N: u32 = 2;\n    let _ = N;\n}\n",
    "scripts/dev/test-parts.tsv": "src\t1\nsrc/b\t2\n",
    "scripts/dev/test-parts-shared.txt": "",
    "src/lib.rs": CRATE_ALLOW + "mod a;\nmod b;\n",
    "src/a.rs": "pub fn f() {}\n\n#[cfg(tp1)]\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn t() {}\n}\n",
    "src/b/mod.rs": "pub fn g() {}\n\n#[cfg(tp2)]\n#[cfg(test)]\nmod b_tests;\n",
    "src/b/b_tests.rs": "#[tokio::test]\nasync fn u() {}\n",
}


def with_files(**changes: str) -> dict[str, str]:
    """BASE with files replaced; a key uses `__` for `/` and `_DOT_` for `.` (src__a_DOT_rs is src/a.rs)."""
    files = dict(BASE)
    for key, body in changes.items():
        files[key.replace("__", "/").replace("_DOT_", ".")] = body
    return files


class Rows(unittest.TestCase):
    """Shared helpers: run the checker or the codemod on a synthetic tree."""

    @classmethod
    def setUpClass(cls):
        cls.tool = load_tool()

    def codes(self, files: dict[str, str]) -> list[str]:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_tree(root, files)
            return sorted({f.code for f in self.tool.check(root)})

    def assert_refused(self, files: dict[str, str], code: str) -> None:
        found = self.codes(files)
        self.assertIn(code, found, f"expected a {code!r} refusal, got {found}")

    def assert_green(self, files: dict[str, str]) -> None:
        self.assertEqual(self.codes(files), [])

    def applied(self, files: dict[str, str], runs: int = 1) -> tuple[dict[str, str], dict[str, str]]:
        """(tree after `runs` codemod runs, tree after one more run)."""
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_tree(root, files)
            for _ in range(runs):
                self.tool.apply(root)
            first = read_tree(root)
            self.tool.apply(root)
            return first, read_tree(root)


class Base(Rows):
    def test_the_tagged_base_tree_is_green(self):
        self.assert_green(BASE)


A_UNTAGGED = "pub fn f() {}\n\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn t() {}\n}\n"


class Invariant(Rows):
    """R-PART: every test function has exactly one part tag, on itself or an ancestor, equal to its table part."""

    def test_an_untagged_test_root_is_refused(self):
        self.assert_refused(with_files(src__a_DOT_rs=A_UNTAGGED), "untagged")

    def test_a_tag_that_disagrees_with_the_table_is_refused(self):
        self.assert_refused(with_files(src__a_DOT_rs=A_UNTAGGED.replace("#[cfg(test)]", "#[cfg(tp2)]\n#[cfg(test)]")), "wrong-part")

    def test_a_test_under_two_tags_is_refused(self):
        body = "#[cfg(tp1)]\n#[cfg(test)]\nmod tests {\n    #[cfg(tp1)]\n    #[test]\n    fn t() {}\n}\n"
        self.assert_refused(with_files(src__a_DOT_rs=body), "two-tags")

    def test_a_stray_untagged_test_in_a_production_module_is_refused(self):
        self.assert_refused(with_files(src__b__mod_DOT_rs=BASE["src/b/mod.rs"] + "\n#[test]\nfn stray() {}\n"), "untagged")

    def test_an_untagged_paused_tokio_test_is_refused(self):
        body = "#[cfg(test)]\nmod tests {\n    #[tokio::test(start_paused = true)]\n    async fn t() {}\n}\n"
        self.assert_refused(with_files(src__a_DOT_rs=body), "untagged")

    def test_a_doc_comment_between_the_test_cfg_and_mod_still_reads_as_a_test_root(self):
        # Round 12: a `///` line here hid the cfg from the prototype's line scan, and 10 tests ran in every part.
        body = "#[cfg(test)]\n/// Reload cases.\nmod reload_tests {\n    #[test]\n    fn t() {}\n}\n"
        self.assert_refused(with_files(src__a_DOT_rs=body), "untagged")

    def test_a_raw_identifier_module_is_walked(self):
        # Round 12: `mod r#override;` was never walked, and its 5 tests ran in every part.
        files = with_files(src__lib_DOT_rs=BASE["src/lib.rs"] + "mod r#override;\n")
        files["src/override.rs"] = A_UNTAGGED
        self.assert_refused(files, "untagged")

    def test_an_out_of_line_tagged_root_is_green_and_untagged_is_refused(self):
        self.assert_green(BASE)  # src/b/mod.rs tags `mod b_tests;`, whose tests sit in the child file
        self.assert_refused(with_files(src__b__mod_DOT_rs="pub fn g() {}\n\n#[cfg(test)]\nmod b_tests;\n"), "untagged")

    def test_a_tag_sharing_a_line_with_its_item_is_refused(self):
        body = "pub fn f() {}\n\n#[cfg(test)]\n#[cfg(tp1)] mod tests {\n    #[test]\n    fn t() {}\n}\n"
        self.assert_refused(with_files(src__a_DOT_rs=body), "same-line")

    def test_tp_partial_outside_the_crate_root_allow_is_refused(self):
        self.assert_refused(with_files(src__a_DOT_rs="#[cfg(tp_partial)]\npub fn f() {}\n" + BASE["src/a.rs"]), "stray-cfg")

    def test_a_malformed_part_tag_is_refused(self):
        # A cfg nobody sets compiles its item out of every part (a mutant rewrote a tag to tpNone and passed).
        for bad in ("tpNone", "tpx", "tp_1"):
            with self.subTest(bad=bad):
                self.assert_refused(with_files(src__a_DOT_rs=BASE["src/a.rs"].replace("tp1", bad)), "stray-cfg")

    def test_a_comment_naming_tp1_is_not_code(self):
        # Review-round labels in comments ("gpt tp1 F3") are common in this tree.
        self.assert_green(with_files(src__a_DOT_rs="/// Pinned after the gpt tp1 F3 finding.\n" + BASE["src/a.rs"]))

    def test_a_crate_root_without_the_partial_build_allow_is_refused(self):
        self.assert_refused(with_files(src__lib_DOT_rs="mod a;\nmod b;\n"), "crate-allow")

    def test_a_test_attribute_the_walk_does_not_know_is_refused(self):
        body = BASE["src/a.rs"].replace("    #[test]\n    fn t() {}\n", "    #[test]\n    fn t() {}\n    #[rstest]\n    fn r() {}\n")
        self.assert_refused(with_files(src__a_DOT_rs=body), "test-attr")


# A container: a cfg(test) module not named tests / *_tests. Its own code is in every part; its test functions carry
# their own tag. src/a.rs declares it, but its file sits in src/a, which the table puts in part 2.
CONTAINER = {
    "scripts/dev/test-parts.tsv": "src\t1\nsrc/a\t2\nsrc/b\t2\n",
    "src/a.rs": BASE["src/a.rs"] + "\n#[cfg(test)]\nmod x_support;\n",
    "src/a/x_support.rs": "pub fn helper() -> u8 {\n    1\n}\n\n#[cfg(tp2)]\n#[test]\nfn helper_is_one() {\n    assert_eq!(helper(), 1);\n}\n",
}


def container(**changes: str) -> dict[str, str]:
    files = dict(BASE)
    files.update(CONTAINER)
    for key, body in changes.items():
        files[key.replace("__", "/").replace("_DOT_", ".")] = body
    return files


GEN_MACRO = "macro_rules! gen_tests {\n    ($n:ident) => {\n        #[test]\n        fn $n() {}\n    };\n}\n"


class SharedAndContainers(Rows):
    def test_a_container_test_takes_the_part_of_its_own_files_directory(self):
        self.assert_green(container())
        self.assert_refused(container(src__a__x_support_DOT_rs=CONTAINER["src/a/x_support.rs"].replace("tp2", "tp1")), "wrong-part")

    def test_an_untagged_test_in_a_container_is_refused(self):
        self.assert_refused(container(src__a__x_support_DOT_rs=CONTAINER["src/a/x_support.rs"].replace("#[cfg(tp2)]\n", "")), "untagged")

    def test_a_tagged_shared_module_is_refused(self):
        files = with_files(**{SHARED: "a::tests\n"})
        self.assert_refused(files, "shared-tagged")

    def test_a_shared_module_untagged_with_tagged_tests_is_green(self):
        body = "pub fn f() {}\n\n#[cfg(test)]\nmod tests {\n    #[cfg(tp1)]\n    #[test]\n    fn t() {}\n}\n"
        self.assert_green(with_files(src__a_DOT_rs=body, **{SHARED: "a::tests\n"}))

    def test_a_shared_entry_that_names_no_module_is_refused(self):
        self.assert_refused(with_files(**{SHARED: "a::gone_tests\n"}), "shared-entry")

    def test_a_test_generating_macro_inside_a_tagged_module_is_green(self):
        body = BASE["src/a.rs"].replace("    #[test]\n    fn t() {}\n", "    #[test]\n    fn t() {}\n    gen_tests!(made);\n")
        self.assert_green(with_files(src__a_DOT_rs=GEN_MACRO + body))

    def test_a_test_generating_macro_in_a_container_is_refused(self):
        helper = CONTAINER["src/a/x_support.rs"] + "gen_tests!(made);\n"
        self.assert_refused(container(src__a_DOT_rs=GEN_MACRO + CONTAINER["src/a.rs"], src__a__x_support_DOT_rs=helper), "test-macro")

    def test_a_path_qualified_test_generating_macro_in_a_container_is_refused(self):
        helper = CONTAINER["src/a/x_support.rs"] + "crate::a::gen_tests!(made);\n"
        self.assert_refused(container(src__a_DOT_rs=GEN_MACRO + CONTAINER["src/a.rs"], src__a__x_support_DOT_rs=helper), "test-macro")


class TableAndBuildRs(Rows):
    """The table against build.rs's `const N`: both ways, no empty part, no stale row."""

    def test_n_above_the_table_leaves_an_empty_part_and_is_refused(self):
        self.assert_refused(with_files(**{BUILD: BASE[BUILD].replace("N: u32 = 2", "N: u32 = 3")}), "empty-part")

    def test_a_row_above_n_is_refused(self):
        self.assert_refused(with_files(**{TABLE: BASE[TABLE] + "src/b/deep\t3\n"}), "table-range")

    def test_a_row_for_a_directory_with_no_unit_is_refused(self):
        self.assert_refused(with_files(**{TABLE: BASE[TABLE] + "src/gone\t2\n"}), "stale-row")

    def test_a_part_with_units_but_no_test_is_refused(self):
        self.assert_refused(with_files(src__b__b_tests_DOT_rs="pub fn not_a_test() {}\n"), "empty-part")


class ParseSafety(Rows):
    """A walk that silently drops an item would put its tests in every part: both failure paths fail closed."""

    def test_a_file_that_does_not_parse_is_refused(self):
        self.assert_refused(with_files(src__a_DOT_rs=BASE["src/a.rs"] + "\nfn broken( {\n"), "parse")

    def test_a_listed_grammar_gap_in_production_code_is_not_refused(self):
        # src/gateway/authz.rs: the pinned grammar cannot parse `raw @ Value::String(_)` in a production fn.
        body = "pub fn f(v: Option<u8>) -> u8 {\n    match v {\n        Some(raw @ 1) => raw,\n        _ => 0,\n    }\n}\n"
        files = with_files(src__a_DOT_rs=body + BASE["src/a.rs"].replace("pub fn f() {}\n", ""))
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_tree(root, files)
            walk = self.tool.walk_file("src/a.rs", files["src/a.rs"])
            if not walk.errors:
                self.skipTest("the pinned grammar parses this form; the gap row has nothing to pin")
            known = self.tool.gate()._error_signature(self.tool.gate()._errors(
                self.tool.gate()._rust_parser().parse(files["src/a.rs"].encode()).root_node, files["src/a.rs"].encode()))
            with unittest.mock.patch.dict(self.tool.gate().KNOWN_GAPS, {"src/a.rs": known}):
                self.assertNotIn("parse", sorted({f.code for f in self.tool.check(root)}))

    def test_a_walk_that_disagrees_with_the_token_scan_is_refused(self):
        real = self.tool.token_inventory

        def one_extra_module(path, text):
            found = dict(real(path, text))
            found[("phantom_tests",)] = 0
            return found

        with unittest.mock.patch.object(self.tool, "token_inventory", one_extra_module):
            self.assert_refused(BASE, "cross-check")


def untagged(files: dict[str, str]) -> dict[str, str]:
    """The tree with every tag line removed: what the codemod starts from."""
    return {
        rel: "".join(line for line in body.splitlines(keepends=True) if not line.strip().startswith(TAG_LINE_PREFIX))
        for rel, body in files.items()
    }


class Codemod(Rows):
    def test_apply_adds_exactly_the_tag_lines_and_a_second_run_changes_nothing(self):
        # R-IDEM and the T5 rule: the result equals the tagged tree, which differs from the input only by tag lines
        # and the crate root's one allow line.
        start = untagged(BASE)
        start["src/lib.rs"] = start["src/lib.rs"].replace(CRATE_ALLOW, "")
        first, second = self.applied(start)
        self.assertEqual(first, BASE)
        self.assertEqual(second, first)

    def test_a_table_change_rewrites_the_tag_in_place_and_then_holds(self):
        first, _ = self.applied(untagged(container()))
        self.assertIn("#[cfg(tp2)]\n#[test]\nfn helper_is_one", first["src/a/x_support.rs"])
        moved = dict(first)
        moved[TABLE] = "src\t1\nsrc/a\t1\nsrc/b\t2\n"
        again, steady = self.applied(moved)
        self.assertIn("#[cfg(tp1)]\n#[test]\nfn helper_is_one", again["src/a/x_support.rs"])
        self.assertEqual(steady, again)
        self.assert_green(again)

    def test_a_module_moved_to_the_shared_list_loses_its_tag_and_its_tests_gain_theirs(self):
        files = with_files(**{SHARED: "a::tests\n"})
        first, _ = self.applied(files)
        self.assertNotIn("#[cfg(tp1)]\n#[cfg(test)]\nmod tests", first["src/a.rs"])
        self.assertIn("    #[cfg(tp1)]\n    #[test]\n    fn t()", first["src/a.rs"])
        self.assert_green(first)

    def test_a_module_declared_in_a_container_is_one_unit_with_one_tag(self):
        # Its whole body compiles in one part (helpers included); its tests carry no tag of their own.
        nested = CONTAINER["src/a/x_support.rs"] + "\nmod deep {\n    fn helper() {}\n    #[test]\n    fn d() {}\n}\n"
        first, _ = self.applied(untagged(container(src__a__x_support_DOT_rs=nested)))
        self.assertIn("#[cfg(tp2)]\nmod deep {\n    fn helper() {}\n    #[test]\n    fn d()", first["src/a/x_support.rs"])
        self.assert_green(first)

    def test_a_shared_listed_helper_nested_in_a_container_loses_its_tag(self):
        nested = CONTAINER["src/a/x_support.rs"] + "\n#[cfg(tp2)]\nmod fixtures {\n    pub fn make() {}\n}\n"
        files = container(src__a__x_support_DOT_rs=nested, **{SHARED: "a::x_support::fixtures\n"})
        first, _ = self.applied(files)
        self.assertIn("\nmod fixtures {", first["src/a/x_support.rs"])
        self.assertNotIn("#[cfg(tp2)]\nmod fixtures", first["src/a/x_support.rs"])
        self.assert_green(first)

    def compound(self, attrs: str) -> str:
        """src/a.rs after `apply`, starting from a test module carrying `attrs` instead of `#[cfg(test)]`."""
        body = f"pub fn f() {{}}\n\n{attrs}\nmod tests {{\n    #[test]\n    fn t() {{}}\n}}\n"
        first, second = self.applied(untagged(with_files(src__a_DOT_rs=body)))
        self.assertEqual(second, first)
        self.assert_green(first)
        for attr in attrs.split("\n"):
            self.assertIn(f"\n{attr}\n", first["src/a.rs"], "every original attribute line is kept byte for byte")
        return first["src/a.rs"]

    def test_r_compound_a_compound_test_predicate_keeps_its_text_and_gains_a_separate_tag(self):
        # Separate cfg attributes AND together, so the tag never changes what the predicate means.
        self.assertIn("#[cfg(tp1)]\n#[cfg(all(test, unix))]\nmod tests", self.compound("#[cfg(all(test, unix))]"))

    def test_r_compound_several_cfg_attributes_get_the_tag_above_the_test_one(self):
        out = self.compound("#[cfg(unix)]\n#[cfg(test)]")
        self.assertIn("#[cfg(unix)]\n#[cfg(tp1)]\n#[cfg(test)]\nmod tests", out)

    def test_r_compound_a_cfg_attr_beside_the_test_cfg_is_kept(self):
        out = self.compound("#[cfg(test)]\n#[cfg_attr(unix, allow(dead_code))]")
        self.assertIn("#[cfg(tp1)]\n#[cfg(test)]\n#[cfg_attr(unix, allow(dead_code))]\nmod tests", out)

    def test_r_compound_an_any_predicate_is_not_test_only_so_its_test_carries_its_own_tag(self):
        # any(test, unix) also builds outside tests: the module is production code, its test function is tagged.
        out = self.compound("#[cfg(any(test, unix))]")
        self.assertIn("#[cfg(any(test, unix))]\nmod tests {\n    #[cfg(tp1)]\n    #[test]", out)

    def test_r_compound_a_not_test_module_is_left_alone(self):
        out = self.compound("#[cfg(not(test))]")
        self.assertIn("#[cfg(not(test))]\nmod tests {\n    #[cfg(tp1)]\n    #[test]", out)

    def test_the_crate_allow_joins_the_inner_attributes_past_comments_and_blank_lines(self):
        # rustfmt refuses a blank line inside the run of inner attributes (the first real-tree run put one there).
        start = untagged(BASE)
        start["src/lib.rs"] = "// SPDX line\n//! Crate docs.\n\n#![deny(unsafe_code)]\nmod a;\nmod b;\n"
        first, _ = self.applied(start)
        self.assertEqual(first["src/lib.rs"], "// SPDX line\n//! Crate docs.\n\n" + CRATE_ALLOW + "#![deny(unsafe_code)]\nmod a;\nmod b;\n")

    def assert_apply_refuses_and_leaves_the_tree(self, files: dict[str, str]) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_tree(root, files)
            with self.assertRaises(self.tool.Refusal):
                self.tool.apply(root)
            self.assertEqual(read_tree(root), files)

    def test_a_refusal_in_one_file_leaves_every_file_untouched(self):
        broken = untagged(BASE)
        broken["src/b/b_tests.rs"] = broken["src/b/b_tests.rs"] + "\nfn broken( {\n"
        self.assert_apply_refuses_and_leaves_the_tree(broken)

    def test_apply_refuses_a_tag_that_shares_a_line_with_code(self):
        body = "pub fn f() {}\n\n#[cfg(test)]\n#[cfg(tp2)] mod tests {\n    #[test]\n    fn t() {}\n}\n"
        self.assert_apply_refuses_and_leaves_the_tree(with_files(src__a_DOT_rs=body))


if __name__ == "__main__":
    unittest.main()

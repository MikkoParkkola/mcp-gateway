#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Rows for `test_parts.py expect`: the exact lib test names each part's binary must list on one CI target.

The union job compares every part binary's `--list` with these sets, with no tolerance, so `expect` must name exactly
what rustc compiles: other cfgs evaluated for the target, generated tests named, raw identifiers kept, and every shape
it cannot name refused at the source instead of guessed."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("test_test_parts", HERE / "test_test_parts.py")
_rows = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_rows)
BASE, write_tree, load_tool = _rows.BASE, _rows.write_tree, _rows.load_tool

# `rustc --print cfg` for each CI target, as the tool reads it (the Linux one from the job's own toolchain in CI).
LINUX = (
    'debug_assertions\npanic="unwind"\ntarget_arch="x86_64"\ntarget_endian="little"\ntarget_env="gnu"\n'
    'target_family="unix"\ntarget_os="linux"\ntarget_pointer_width="64"\ntarget_vendor="unknown"\nunix\n'
)
WINDOWS = (
    'debug_assertions\npanic="unwind"\ntarget_arch="x86_64"\ntarget_endian="little"\ntarget_env="msvc"\n'
    'target_family="windows"\ntarget_os="windows"\ntarget_pointer_width="64"\ntarget_vendor="pc"\nwindows\n'
)
MACOS = (
    'debug_assertions\npanic="unwind"\ntarget_arch="aarch64"\ntarget_endian="little"\ntarget_env=""\n'
    'target_family="unix"\ntarget_os="macos"\ntarget_pointer_width="64"\ntarget_vendor="apple"\nunix\n'
)
TARGETS = {"linux": LINUX, "windows": WINDOWS, "macos": MACOS}
# The CI configurations X9 evaluates over: (target cfg text, feature set), "all" or "default" as the workflows pass them.
CONFIGS = [(LINUX, "all"), (LINUX, "default"), (WINDOWS, "all"), (MACOS, "all")]

# BASE plus a feature table and the repo's custom cfg list, as Cargo.toml carries them.
CARGO = (
    BASE["Cargo.toml"]
    + '\n[features]\ndefault = []\nfirewall = []\n\n[lints.rust]\n'
    + "unexpected_cfgs = { level = \"warn\", check-cfg = ['cfg(kani)', 'cfg(coverage)', 'cfg(mutants)', 'cfg(reads_token_probe)'] }\n"
)


def tree(**changes: str) -> dict[str, str]:
    """BASE with the feature table, then files replaced (`__` is `/`, `_DOT_` is `.`, as in test_test_parts)."""
    files = dict(BASE)
    files["Cargo.toml"] = CARGO
    for key, body in changes.items():
        files[key.replace("__", "/").replace("_DOT_", ".")] = body
    return files


def part1_module(body: str) -> str:
    """src/a.rs with `body` inside its part 1 test module."""
    return "pub fn f() {}\n\n#[cfg(tp1)]\n#[cfg(test)]\nmod tests {\n" + body + "}\n"


class ExpectRows(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = load_tool()

    def expected(self, files: dict[str, str], target: str = "linux") -> dict[int, list[str]]:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_tree(root, files)
            return self.tool.expect(root, TARGETS[target])

    def codes(self, files: dict[str, str]) -> list[str]:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_tree(root, files)
            return sorted({f.code for f in self.tool.check(root, configs=CONFIGS)})

    def assert_refused(self, files: dict[str, str], code: str) -> None:
        found = self.codes(files)
        self.assertIn(code, found, f"expected a {code!r} refusal, got {found}")


class Base(ExpectRows):
    def test_the_base_tree_expects_each_part_s_tests(self):
        self.assertEqual(self.expected(tree()), {1: ["a::tests::t"], 2: ["b::b_tests::u"]})


class CfgEvaluation(ExpectRows):
    """X1: each test fn's effective cfg, from its own attributes up through every enclosing module, its `mod`
    declaration and a file's inner `#![cfg]`, evaluated for the target."""

    def test_a_cfg_on_the_test_fn(self):
        body = (
            "    #[test]\n    fn plain() {}\n"
            "    #[cfg(windows)]\n    #[test]\n    fn win() {}\n"
            "    #[cfg(unix)]\n    #[test]\n    fn nix() {}\n"
            "    #[cfg(all(test, unix))]\n    #[test]\n    fn both() {}\n"
            '    #[cfg(target_os = "macos")]\n    #[test]\n    fn mac() {}\n'
        )
        got = self.expected(tree(src__a_DOT_rs=part1_module(body)))[1]
        self.assertEqual(got, ["a::tests::both", "a::tests::nix", "a::tests::plain"])
        self.assertEqual(self.expected(tree(src__a_DOT_rs=part1_module(body)), "windows")[1],
                         ["a::tests::plain", "a::tests::win"])

    def test_the_macos_target_expects_its_own_names(self):
        """U1: the macOS union's expected lists. A test the Linux configuration has and macOS's cfg excludes is not
        expected on macOS; a macOS-only test is, so a macOS list missing it fails the union."""
        body = (
            "    #[test]\n    fn plain() {}\n"
            '    #[cfg(target_os = "linux")]\n    #[test]\n    fn linux_only() {}\n'
            '    #[cfg(target_os = "macos")]\n    #[test]\n    fn mac() {}\n'
        )
        table = "config\tx86_64-unknown-linux-gnu\t--all-features\t\nconfig\taarch64-apple-darwin\t--all-features\t\n"
        files = tree(**{"src__a_DOT_rs": part1_module(body), "scripts__dev__test-parts-ci_DOT_tsv": table})
        # Through `expect TARGET OUTDIR`, as the union job runs it: the target picks the compiler's cfg text.
        expect_module = self.tool._expect_module()
        expect_module.print_cfg = {"x86_64-unknown-linux-gnu": LINUX, "aarch64-apple-darwin": MACOS}.__getitem__
        saved = self.tool._expect_module
        self.tool._expect_module = lambda: expect_module
        try:
            for target, want in (("x86_64-unknown-linux-gnu", "a::tests::linux_only\na::tests::plain\n"),
                                 ("aarch64-apple-darwin", "a::tests::mac\na::tests::plain\n")):
                with self.subTest(target), TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    write_tree(root, files)
                    out = root / "expected"
                    self.assertEqual(self.tool.main(["test_parts.py", "expect", target, str(out)], root=root), 0)
                    self.assertEqual((out / "p1.txt").read_text(), want)
        finally:
            self.tool._expect_module = saved

    def test_features_are_all_on_and_custom_cfgs_off(self):
        body = (
            '    #[cfg(feature = "firewall")]\n    #[test]\n    fn with_fw() {}\n'
            '    #[cfg(not(feature = "firewall"))]\n    #[test]\n    fn without_fw() {}\n'
            "    #[cfg(mutants)]\n    #[test]\n    fn mutant_only() {}\n"
            "    #[cfg(not(kani))]\n    #[test]\n    fn not_kani() {}\n"
        )
        got = self.expected(tree(src__a_DOT_rs=part1_module(body)))[1]
        self.assertEqual(got, ["a::tests::not_kani", "a::tests::with_fw"])

    def test_a_cfg_on_an_enclosing_inline_module(self):
        body = "    #[cfg(not(unix))]\n    mod inner {\n        #[test]\n        fn t() {}\n    }\n    #[test]\n    fn kept() {}\n"
        self.assertEqual(self.expected(tree(src__a_DOT_rs=part1_module(body)))[1], ["a::tests::kept"])

    def test_a_cfg_on_a_mod_declaration(self):
        b = 'pub fn g() {}\n\n#[cfg(tp2)]\n#[cfg(test)]\n#[cfg(target_os = "macos")]\nmod b_tests;\n'
        self.assertEqual(self.expected(tree(src__b__mod_DOT_rs=b)).get(2, []), [])
        self.assertEqual(self.expected(tree(src__b__mod_DOT_rs=b), "macos")[2], ["b::b_tests::u"])

    def test_a_file_s_inner_cfg(self):
        inner = "#![cfg(windows)]\n#[tokio::test]\nasync fn u() {}\n"
        self.assertEqual(self.expected(tree(src__b__b_tests_DOT_rs=inner)).get(2, []), [])
        self.assertEqual(self.expected(tree(src__b__b_tests_DOT_rs=inner), "windows")[2], ["b::b_tests::u"])

    def test_target_cfgs_come_from_the_print_cfg_text(self):
        """X6: predicates rustc prints are read from it, not from a hand list."""
        body = (
            '    #[cfg(target_arch = "aarch64")]\n    #[test]\n    fn arm() {}\n'
            '    #[cfg(target_pointer_width = "64")]\n    #[test]\n    fn wide() {}\n'
            '    #[cfg(panic = "abort")]\n    #[test]\n    fn aborts() {}\n'
            '    #[cfg(target_env = "gnu")]\n    #[test]\n    fn gnu() {}\n'
        )
        files = tree(src__a_DOT_rs=part1_module(body))
        self.assertEqual(self.expected(files)[1], ["a::tests::gnu", "a::tests::wide"])
        self.assertEqual(self.expected(files, "macos")[1], ["a::tests::arm", "a::tests::wide"])


class Undecidable(ExpectRows):
    """X2: a predicate on a name neither rustc prints, nor a feature, nor the check-cfg list, nor tpK is refused."""

    def test_a_cfg_outside_every_known_source_is_refused(self):
        body = "    #[cfg(made_up)]\n    #[test]\n    fn t2() {}\n"
        self.assert_refused(tree(src__a_DOT_rs=part1_module(body)), "cfg-undecidable")

    def test_a_key_value_cfg_outside_every_known_source_is_refused(self):
        body = '    #[cfg(made_up = "x")]\n    #[test]\n    fn t2() {}\n'
        self.assert_refused(tree(src__a_DOT_rs=part1_module(body)), "cfg-undecidable")

    def test_a_listed_custom_cfg_is_decided(self):
        body = "    #[cfg(reads_token_probe)]\n    #[test]\n    fn t2() {}\n"
        self.assertNotIn("cfg-undecidable", self.codes(tree(src__a_DOT_rs=part1_module(body))))


GENERATOR = "    macro_rules! row {\n        ($name:ident, $v:expr) => {\n            #[test]\n            fn $name() { assert!($v); }\n        };\n    }\n"


class Generators(ExpectRows):
    """X3 and X8: a test-generating macro names one test per item-level invocation, from its first fragment."""

    def test_each_invocation_names_its_test(self):
        body = GENERATOR + "    row!(first, true);\n    row!(second, true);\n"
        got = self.expected(tree(src__a_DOT_rs=part1_module(body)))[1]
        self.assertEqual(got, ["a::tests::first", "a::tests::second"])

    def test_a_cfg_on_an_invocation_is_evaluated(self):
        body = GENERATOR + "    row!(first, true);\n    #[cfg(windows)]\n    row!(win_only, true);\n"
        files = tree(src__a_DOT_rs=part1_module(body))
        self.assertEqual(self.expected(files)[1], ["a::tests::first"])
        self.assertEqual(self.expected(files, "windows")[1], ["a::tests::first", "a::tests::win_only"])

    def test_a_generator_of_another_shape_is_refused(self):
        two_fns = "    macro_rules! row {\n        ($a:ident, $b:ident) => {\n            #[test]\n            fn $a() {}\n            #[test]\n            fn $b() {}\n        };\n    }\n    row!(x, y);\n"
        fixed_name = "    macro_rules! row {\n        ($a:ident) => {\n            #[test]\n            fn fixed() {}\n        };\n    }\n    row!(x);\n"
        cfg_inside = "    macro_rules! row {\n        ($a:ident) => {\n            #[cfg(unix)]\n            #[test]\n            fn $a() {}\n        };\n    }\n    row!(x);\n"
        for body in (two_fns, fixed_name, cfg_inside):
            with self.subTest(body=body):
                self.assert_refused(tree(src__a_DOT_rs=part1_module(body)), "generator-shape")


class Names(ExpectRows):
    """X4: names as libtest prints them."""

    def test_a_raw_identifier_keeps_its_prefix(self):
        body = "    mod r#override {\n        #[test]\n        fn t2() {}\n    }\n"
        self.assertIn("a::tests::r#override::t2", self.expected(tree(src__a_DOT_rs=part1_module(body)))[1])

    def test_a_path_redirect_uses_the_declared_name(self):
        b = 'pub fn g() {}\n\n#[cfg(tp2)]\n#[cfg(test)]\n#[path = "elsewhere_tests.rs"]\nmod checks;\n'
        files = tree(src__b__mod_DOT_rs=b, src__b__elsewhere_tests_DOT_rs="#[test]\nfn w() {}\n")
        del files["src/b/b_tests.rs"]
        self.assertEqual(self.expected(files)[2], ["b::checks::w"])


class Refusals(ExpectRows):
    """Shapes `expect` cannot name are refused at the source (X7, X9 and the opaque-macro rules)."""

    def test_include_of_rust_source_in_test_code(self):
        body = '    include!("more_tests.rs");\n'
        self.assert_refused(tree(src__a_DOT_rs=part1_module(body)), "include-source")

    def test_a_test_compiled_on_no_ci_target(self):
        """X9: target predicates false on Linux, Windows and macOS alike."""
        body = "    #[cfg(any())]\n    mod gone {\n        #[test]\n        fn t2() {}\n    }\n"
        self.assert_refused(tree(src__a_DOT_rs=part1_module(body)), "test-nowhere")
        both = '    #[cfg(all(windows, target_os = "macos"))]\n    #[test]\n    fn t3() {}\n'
        self.assert_refused(tree(src__a_DOT_rs=part1_module(both)), "test-nowhere")

    def test_expect_refuses_before_it_writes_lists(self):
        """The union job's `expect` runs the refusals over the CI table's configurations first (only CI has the
        compiler they need): a shape expect cannot name fails the job and writes no list. `check`, which pre-push
        runs with the compiler blocked, stays without them."""
        body = "    #[cfg(made_up)]\n    #[test]\n    fn t2() {}\n"
        table = "config\tx86_64-unknown-linux-gnu\t--all-features\t\n"
        files = tree(**{"src__a_DOT_rs": part1_module(body), "scripts__dev__test-parts-ci_DOT_tsv": table})
        expect_module = self.tool._expect_module()
        expect_module.print_cfg = lambda target: LINUX
        saved = self.tool._expect_module
        self.tool._expect_module = lambda: expect_module
        try:
            with TemporaryDirectory() as tmp:
                root = Path(tmp)
                write_tree(root, files)
                out = root / "expected"
                rc = self.tool.main(["test_parts.py", "expect", "x86_64-unknown-linux-gnu", str(out)], root=root)
                self.assertEqual(rc, 1, "expect wrote lists over a shape it cannot name")
                self.assertFalse(out.exists(), "expect wrote lists before refusing")
                expect_module.print_cfg = lambda target: self.fail("check ran the compiler")
                self.assertEqual(self.tool.main(["test_parts.py", "check"], root=root), 0)
        finally:
            self.tool._expect_module = saved

    def test_expect_fails_without_a_recorded_configuration(self):
        """With no CI configuration to evaluate, the refusals cannot run: a missing table, an empty one and one with
        only a `nowhere` row each fail `expect` before it writes a list, instead of passing unchecked."""
        nowhere_only = "nowhere\ta::tests::t1\twritten for a platform CI does not have\n"
        for label, table in (("missing", None), ("empty", ""), ("no config row", nowhere_only)):
            with self.subTest(label), TemporaryDirectory() as tmp:
                # One real test, so nothing but the missing configuration can fail the run.
                files = tree(src__a_DOT_rs=part1_module("    #[test]\n    fn t1() {}\n"))
                if table is not None:
                    files["scripts/dev/test-parts-ci.tsv"] = table
                else:
                    files.pop("scripts/dev/test-parts-ci.tsv", None)
                root = Path(tmp)
                write_tree(root, files)
                out = root / "expected"
                rc = self.tool.main(["test_parts.py", "expect", "x86_64-unknown-linux-gnu", str(out)], root=root)
                self.assertEqual(rc, 1, f"expect ran with a {label} CI table")
                self.assertFalse(out.exists(), f"expect wrote lists with a {label} CI table")

    def test_a_nowhere_row_lets_only_its_own_test_pass(self):
        """X9's shrink-only allowance: the test a `nowhere` row of the CI table names is not refused; its neighbour,
        compiled nowhere too, still is."""
        body = "    #[cfg(any())]\n    mod gone {\n        #[test]\n        fn t2() {}\n        #[test]\n        fn t3() {}\n    }\n"
        table = "nowhere\ta::tests::gone::t2\twritten for a platform CI does not have\n"
        files = tree(**{"src__a_DOT_rs": part1_module(body), "scripts__dev__test-parts-ci_DOT_tsv": table})
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_tree(root, files)
            nowhere = [f.message for f in self.tool.check(root, configs=CONFIGS) if f.code == "test-nowhere"]
        self.assertEqual([m.split()[0] for m in nowhere], ["a::tests::gone::t3"], nowhere)

    def test_feature_and_single_os_gates_stay_legal(self):
        """X9 treats feature atoms as free: default-feature builds compile `not(feature = ..)` tests."""
        body = (
            '    #[cfg(not(feature = "firewall"))]\n    #[test]\n    fn no_fw() {}\n'
            "    #[cfg(windows)]\n    #[test]\n    fn win() {}\n"
        )
        self.assertNotIn("test-nowhere", self.codes(tree(src__a_DOT_rs=part1_module(body))))

    def test_a_feature_on_in_every_configuration(self):
        """X9 against the recorded configurations: `always` is a default feature, so every build enables it."""
        cargo = CARGO.replace("default = []", 'default = ["always"]').replace("firewall = []", "firewall = []\nalways = []")
        body = '    #[cfg(not(feature = "always"))]\n    #[test]\n    fn never() {}\n'
        self.assert_refused(tree(Cargo_DOT_toml=cargo, src__a_DOT_rs=part1_module(body)), "test-nowhere")

    def test_item_level_macros_outside_the_allowlist(self):
        for body in ("    cfg_if::cfg_if! { if #[cfg(unix)] { #[test] fn t2() {} } }\n",
                     "    paste::paste! { #[test] fn [<t _ 2>]() {} }\n",
                     "    other_crate::make_tests!();\n"):
            with self.subTest(body=body):
                self.assert_refused(tree(src__a_DOT_rs=part1_module(body)), "item-macro")

    def test_thread_local_and_local_generators_pass(self):
        body = ("    thread_local! { static X: u8 = 0; }\n" + GENERATOR + "    row!(g1, true);\n")
        self.assertNotIn("item-macro", self.codes(tree(src__a_DOT_rs=part1_module(body))))

    def test_an_attribute_macro_at_module_position(self):
        body = "    #[some_crate::generate_tests]\n    mod gen {\n    }\n"
        self.assert_refused(tree(src__a_DOT_rs=part1_module(body)), "attr-position")
        wrapped = "    #[cfg_attr(unix, some_crate::generate_tests)]\n    mod gen {\n    }\n"
        self.assert_refused(tree(src__a_DOT_rs=part1_module(wrapped)), "attr-position")

    def test_lint_and_doc_attributes_at_module_position_pass(self):
        body = '    /// Docs.\n    #[allow(dead_code)]\n    #[expect(unused)]\n    mod helpers {\n    }\n'
        self.assertNotIn("attr-position", self.codes(tree(src__a_DOT_rs=part1_module(body))))

    def test_an_import_that_shadows_the_test_attributes(self):
        for body in ("    use some_crate::test;\n", "    use other as tokio;\n",
                     "    extern crate other as tokio;\n", "    mod tokio {\n    }\n", "    mod test {\n    }\n",
                     "    pub use other::generate as test;\n"):
            with self.subTest(body=body):
                self.assert_refused(tree(src__a_DOT_rs=part1_module(body)), "test-import")

    def test_a_dependency_renamed_to_tokio(self):
        cargo = CARGO + '\n[dependencies]\ntokio = { package = "not-tokio", version = "1" }\n'
        self.assert_refused(tree(Cargo_DOT_toml=cargo), "test-import")

    def test_a_rebound_allowlisted_macro(self):
        for body in ("    macro_rules! thread_local { () => {} }\n", "    use other::thread_local;\n"):
            with self.subTest(body=body):
                self.assert_refused(tree(src__a_DOT_rs=part1_module(body)), "item-macro")


if __name__ == "__main__":
    unittest.main()

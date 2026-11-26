#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Tests for c6_resolve.py (MIK-8245): each case is a throwaway git repository holding a
ranking, a replacements file, patches and Rust sources, and the resolver must reach the stated
verdict. The resolver reads the committed tree, so every fixture is committed first."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("c6_resolve", HERE / "c6_resolve.py")
c6 = importlib.util.module_from_spec(spec)
sys.modules["c6_resolve"] = c6
spec.loader.exec_module(c6)

RANK_HEAD = "rank\tstatus\tnamed_path\tfile\tqualified\toccurrence\treason\n"
REPL_HEAD = "named_path\tslot_rank\trule\tunderstudy_rank\tfile\tqualified\toccurrence\tevidence\n"
GAP_TABLE = "docs/release/c6-gap/v4.0.0-c6-gap-table.tsv"
GAP_HEAD = "rank\tpath\tfile\tfunction\tmutant\tdeclared_killer_args\n"
# The killer the gap row names, at the module path its filter spells.
KILLER = "#[test]\nfn guard_admits_only_its_host() {}\n"
GUARD = """impl Guard {
    fn admits(&self, host: &str) -> bool {
        let allowed = host == self.host;
        allowed
    }
}
"""
# Fail-open: the check is replaced by `true`.
PATCH = """diff --git a/src/guard.rs b/src/guard.rs
--- a/src/guard.rs
+++ b/src/guard.rs
@@ -1,5 +1,5 @@
 impl Guard {
     fn admits(&self, host: &str) -> bool {
-        let allowed = host == self.host;
+        let allowed = true;
         allowed
     }
"""


class Repo:
    """A committed fixture tree with one HTTP SAMPLE obligation, `Guard::admits` in src/guard.rs."""

    def __init__(self) -> None:
        self.dir = tempfile.TemporaryDirectory()
        self.root = Path(self.dir.name)
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.email", "t@example.invalid")
        self.git("config", "user.name", "t")
        self.files: dict[str, str] = {
            c6.RANKING: RANK_HEAD + "1\tSAMPLE\tHTTP dispatch\tsrc/guard.rs\tGuard::admits\t1\tAdmits only its host.\n",
            c6.REPLACEMENTS: REPL_HEAD,
            f"{c6.PATCHES}/http/1_admits.patch": PATCH,
            "src/guard.rs": GUARD,
            GAP_TABLE: GAP_HEAD + "1\tHTTP dispatch\tsrc/guard.rs\tGuard::admits\t1_admits.patch\t--lib checks::guard_admits_only_its_host\n",
            "src/lib.rs": "mod checks;\n",
            "src/checks.rs": KILLER,
        }

    def git(self, *args: str) -> str:
        return subprocess.run(["git", "-c", "gc.auto=0", "-c", "maintenance.auto=false", *args], cwd=self.root, check=True, capture_output=True, text=True).stdout

    def commit(self) -> None:
        for path, text in self.files.items():
            target = self.root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text)
        for stale in self.git("ls-files").split():
            if stale not in self.files:
                self.git("rm", "-q", stale)
        self.git("add", "-A")
        self.git("commit", "-qm", "fixture", "--allow-empty")

    def run(self) -> tuple[int, str]:
        self.commit()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = c6.main(["--root", str(self.root), "--tree", "HEAD"])
        return code, out.getvalue()

    def close(self) -> None:
        self.dir.cleanup()


class Resolution(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = Repo()

    def tearDown(self) -> None:
        self.repo.close()

    def verdict(self) -> tuple[int, str]:
        code, out = self.repo.run()
        return code, out

    def test_a_function_where_it_was_drawn_resolves_in_place(self) -> None:
        code, out = self.verdict()
        self.assertEqual(code, 0, out)
        self.assertIn("in-place\tHTTP dispatch rank 1 Guard::admits", out)
        self.assertIn("1 framed obligations, 0 framed items unresolved", out)

    def test_a_moved_function_resolves_and_its_patch_follows_it(self) -> None:
        self.repo.files.pop("src/guard.rs")
        self.repo.files["src/guards/host.rs"] = "// moved here\n" + GUARD
        code, out = self.verdict()
        self.assertEqual(code, 0, out)
        self.assertIn("moved\tHTTP dispatch rank 1 Guard::admits\tsrc/guard.rs -> src/guards/host.rs", out)

    def test_a_changed_body_fails_the_run_naming_the_obligation(self) -> None:
        self.repo.files["src/guard.rs"] = GUARD.replace("host == self.host", "self.host.eq(host)")
        code, out = self.verdict()
        self.assertEqual(code, 1)
        self.assertIn("unresolved\tHTTP dispatch rank 1 Guard::admits", out)
        self.assertIn("1 framed obligations, 1 framed items unresolved", out)

    def test_a_deleted_or_renamed_function_fails_the_run(self) -> None:
        self.repo.files["src/guard.rs"] = GUARD.replace("fn admits", "fn permits")
        code, out = self.verdict()
        self.assertEqual(code, 1)
        self.assertIn("Guard::admits not found in src/", out)

    def test_the_same_function_in_two_files_is_ambiguous_never_picked(self) -> None:
        self.repo.files.pop("src/guard.rs")
        self.repo.files["src/a.rs"] = GUARD
        self.repo.files["src/b.rs"] = GUARD
        code, out = self.verdict()
        self.assertEqual(code, 1)
        self.assertIn("Guard::admits is ambiguous: src/a.rs:2, src/b.rs:2", out)

    def test_a_patch_that_applies_to_a_neighbouring_function_is_refused(self) -> None:
        # The ranked function moved away; a neighbour kept the exact lines the patch edits, so
        # `git apply` would succeed against the wrong function.
        self.repo.files["src/guard.rs"] = GUARD.replace("impl Guard", "impl Other").replace("fn admits", "fn neighbour")
        self.repo.files["src/real.rs"] = "impl Guard {\n    fn admits(&self, host: &str) -> bool {\n        self.check(host)\n    }\n}\n"
        code, out = self.verdict()
        self.assertEqual(code, 1)
        self.assertIn("patch does not mutate Guard::admits", out)

    def test_a_hunk_whose_lines_occur_twice_is_refused(self) -> None:
        # A second `impl Guard` block repeating the same lines: the patch could land on either.
        self.repo.files["src/guard.rs"] = GUARD + GUARD
        code, out = self.verdict()
        self.assertEqual(code, 1)
        self.assertIn("hunk 1 matches 2 places in the file", out)

    def test_fn_text_in_comments_and_raw_strings_is_not_a_declaration(self) -> None:
        self.repo.files["src/guard.rs"] = (
            "// impl Guard { fn admits(&self) { } }\n"
            'const S: &str = r#"a " } impl Guard { fn admits() { "#;\n' + GUARD
        )
        self.repo.files[f"{c6.PATCHES}/http/1_admits.patch"] = PATCH.replace("@@ -1,5 +1,5 @@", "@@ -3,5 +3,5 @@")
        code, out = self.verdict()
        self.assertEqual(code, 0, out)
        self.assertIn("in-place", out)

    def test_a_block_comment_does_not_extend_a_function_over_its_neighbour(self) -> None:
        source = (
            "impl Guard {\n    fn admits(&self, host: &str) -> bool { true /* } */ }\n"
            "    fn next(&self) {\n        let x = 1;\n    }\n}\n"
        )
        decls = {d.name: d for d in c6.declarations(source)}
        self.assertEqual((decls["admits"].start, decls["admits"].end), (2, 2))
        self.assertEqual((decls["next"].start, decls["next"].end), (3, 5))

    def test_a_trait_method_and_a_free_function_resolve_by_their_owner(self) -> None:
        decls = c6.declarations("trait T { fn m(&self) { } }\nimpl T for S { fn m(&self) { } }\nfn free() { }\n")
        self.assertEqual([(d.name, d.owner) for d in decls], [("m", "T"), ("m", "S"), ("free", None)])

    def test_a_g11_replacement_binds_the_slot_to_its_understudy(self) -> None:
        self.repo.files[c6.RANKING] += "2\tunderstudy\tHTTP dispatch\tsrc/other.rs\tOther::check\t1\tChecks.\n"
        self.repo.files["src/other.rs"] = GUARD.replace("impl Guard", "impl Other").replace("fn admits", "fn check")
        self.repo.files[f"{c6.PATCHES}/http/2_check.patch"] = (
            PATCH.replace("src/guard.rs", "src/other.rs").replace("impl Guard", "impl Other").replace("fn admits", "fn check"))
        self.repo.files["src/guard.rs"] = "// the ranked function is gone\n"
        self.repo.files[c6.REPLACEMENTS] += "HTTP dispatch\t1\tG11\t2\t\t\t\ttwo seats\n"
        code, out = self.verdict()
        self.assertEqual(code, 0, out)
        self.assertIn("in-place\tHTTP dispatch rank 1 Other::check\tsrc/other.rs", out)
        self.assertIn("1 framed obligations, 0 framed items unresolved", out)

    def test_a_g4_successor_binds_the_slot_to_the_function_that_kept_the_decision(self) -> None:
        self.repo.files["src/guard.rs"] = GUARD.replace("fn admits", "fn admits_host")
        self.repo.files[f"{c6.PATCHES}/http/1_admits.patch"] = PATCH.replace("fn admits", "fn admits_host")
        self.repo.files[c6.REPLACEMENTS] += "HTTP dispatch\t1\tG4-successor\t\tsrc/guard.rs\tGuard::admits_host\t1\ttwo seats\n"
        code, out = self.verdict()
        self.assertEqual(code, 0, out)
        self.assertIn("in-place\tHTTP dispatch rank 1 Guard::admits_host", out)

    def test_a_replacement_with_an_unrecognised_rule_refuses_to_resolve(self) -> None:
        self.repo.files[c6.REPLACEMENTS] += "HTTP dispatch\t1\tWAIVED\t\t\t\t\tnobody\n"
        with self.assertRaisesRegex(LookupError, "rule 'WAIVED'"):
            self.verdict()

    # -- the code review's adversarial cases (MIK-8245) -----------------------------------

    def test_a_mode_only_or_rename_patch_is_not_a_mutation(self) -> None:
        for patch in (
            "diff --git a/src/guard.rs b/src/guard.rs\nold mode 100644\nnew mode 100755\n",
            "diff --git a/src/guard.rs b/src/guard.rs\nsimilarity index 100%\nrename from src/guard.rs\nrename to src/guard.rs\n",
        ):
            self.repo.files[f"{c6.PATCHES}/http/1_admits.patch"] = patch
            code, out = self.verdict()
            self.assertEqual(code, 1, patch)
            self.assertIn("patch is not a plain text edit", out)

    def test_a_patch_whose_paths_differ_is_refused(self) -> None:
        self.repo.files[f"{c6.PATCHES}/http/1_admits.patch"] = PATCH.replace("+++ b/src/guard.rs", "+++ b/src/other.rs")
        code, out = self.verdict()
        self.assertEqual(code, 1)
        self.assertIn("patch source and destination paths differ", out)

    def test_a_fn_nested_in_a_body_or_a_macro_template_belongs_to_no_type(self) -> None:
        source = (
            "impl G {\n    fn outer(&self) { fn admits() {} }\n}\n"
            "macro_rules! m { () => { impl G { fn admits() {} } }; }\n"
        )
        owners = {(d.name, d.owner) for d in c6.declarations(source)}
        self.assertIn(("admits", None), owners)
        self.assertNotIn(("admits", "G"), owners)

    def test_an_arrow_inside_generics_does_not_close_them(self) -> None:
        decls = c6.declarations("fn f(x: Box<dyn Fn(u8) -> u8>) -> u8 { 1 }\nfn g() {}\n")
        self.assertEqual([(d.name, d.start, d.end) for d in decls], [("f", 1, 1), ("g", 2, 2)])
        # In an impl header the `>` of `->` must not end the generics, or the owner is misread.
        held = c6.declarations("impl<F: Fn() -> u8> Holder<F> {\n    fn m(&self) {}\n}\n")
        self.assertEqual([(d.name, d.owner) for d in held], [("m", "Holder")])

    def test_a_change_on_a_line_a_neighbouring_function_shares_is_refused(self) -> None:
        self.repo.files["src/guard.rs"] = (
            "impl Guard {\n    fn admits(&self, host: &str) -> bool {\n        host == self.host\n"
            "    } fn spare(&self) -> bool { true }\n}\n")
        self.repo.files[f"{c6.PATCHES}/http/1_admits.patch"] = (
            "diff --git a/src/guard.rs b/src/guard.rs\n--- a/src/guard.rs\n+++ b/src/guard.rs\n"
            "@@ -3,3 +3,3 @@\n         host == self.host\n"
            "-    } fn spare(&self) -> bool { true }\n+    } fn spare(&self) -> bool { false }\n }\n")
        code, out = self.verdict()
        self.assertEqual(code, 1)
        self.assertIn("it changes text after admits", out)

    def test_replacing_a_functions_closing_line_counts_as_inside_it(self) -> None:
        self.repo.files["src/guard.rs"] = (
            "impl Guard {\n    fn admits(&self, host: &str) -> bool {\n        host == self.host }\n}\n")
        self.repo.files[f"{c6.PATCHES}/http/1_admits.patch"] = (
            "diff --git a/src/guard.rs b/src/guard.rs\n--- a/src/guard.rs\n+++ b/src/guard.rs\n"
            "@@ -2,3 +2,3 @@\n     fn admits(&self, host: &str) -> bool {\n"
            "-        host == self.host }\n+        true }\n }\n")
        code, out = self.verdict()
        self.assertEqual(code, 0, out)

    def test_two_slots_may_not_share_one_understudy(self) -> None:
        self.repo.files[c6.RANKING] += (
            "2\tSAMPLE\tHTTP dispatch\tsrc/two.rs\tTwo::check\t1\tChecks.\n"
            "3\tunderstudy\tHTTP dispatch\tsrc/other.rs\tOther::check\t1\tChecks.\n")
        self.repo.files[f"{c6.PATCHES}/http/2_two.patch"] = PATCH
        self.repo.files[f"{c6.PATCHES}/http/3_check.patch"] = PATCH
        self.repo.files[c6.REPLACEMENTS] += ("HTTP dispatch\t1\tG9\t3\t\t\t\tone\n"
                                             "HTTP dispatch\t2\tG9\t3\t\t\t\ttwo\n")
        with self.assertRaisesRegex(LookupError, "bind the same function"):
            self.verdict()

    def test_a_slot_replaced_twice_is_refused(self) -> None:
        self.repo.files[c6.REPLACEMENTS] += ("HTTP dispatch\t1\tG4-successor\t\tsrc/guard.rs\tGuard::admits\t1\tone\n"
                                             "HTTP dispatch\t1\tG4-successor\t\tsrc/guard.rs\tGuard::admits\t1\ttwo\n")
        with self.assertRaisesRegex(LookupError, "replaced twice"):
            self.verdict()

    # -- the second review round's counterexamples -----------------------------------------

    def test_an_arrow_in_an_impl_headers_generics_does_not_change_the_owner(self) -> None:
        decls = c6.declarations("impl Guard<fn() -> Other> {\n    fn admits(&self) {}\n}\n")
        self.assertEqual([(d.name, d.owner) for d in decls], [("admits", "Guard")])

    def test_a_fn_inside_a_macro_invocation_is_not_a_declaration(self) -> None:
        # `ignore!` could discard its input: the obligation must not resolve to that text.
        self.repo.files["src/guard.rs"] = "ignore! {\n" + GUARD + "}\n"
        code, out = self.verdict()
        self.assertEqual(code, 1)
        self.assertIn("Guard::admits not found in src/", out)

    def test_a_moved_free_function_never_resolves_to_a_same_named_method(self) -> None:
        self.repo.files[c6.RANKING] = RANK_HEAD + "1\tSAMPLE\tHTTP dispatch\tsrc/guard.rs\tadmits\t1\tAdmits only its host.\n"
        self.repo.files.pop("src/guard.rs")
        self.repo.files["src/other.rs"] = GUARD  # only a method `Guard::admits` exists now
        code, out = self.verdict()
        self.assertEqual(code, 1)
        self.assertIn("admits not found in src/", out)

    def test_two_slots_resolving_to_one_function_are_both_unresolved(self) -> None:
        self.repo.files[c6.RANKING] += "2\tSAMPLE\tHTTP dispatch\tsrc/old.rs\tGuard::admits\t1\tSame decision.\n"
        self.repo.files[f"{c6.PATCHES}/http/2_admits.patch"] = PATCH
        code, out = self.verdict()
        self.assertEqual(code, 1)
        self.assertIn("rank 1 and HTTP dispatch rank 2 resolve to one function", out)
        self.assertIn("2 framed items unresolved", out)

    def test_an_item_sharing_the_closing_line_cannot_be_the_mutation(self) -> None:
        self.repo.files["src/guard.rs"] = (
            "impl Guard {\n    fn admits(&self, host: &str) -> bool {\n        FLAG\n"
            "    } const FLAG: bool = true;\n}\n")
        self.repo.files[f"{c6.PATCHES}/http/1_admits.patch"] = (
            "diff --git a/src/guard.rs b/src/guard.rs\n--- a/src/guard.rs\n+++ b/src/guard.rs\n"
            "@@ -3,3 +3,3 @@\n         FLAG\n"
            "-    } const FLAG: bool = true;\n+    } const FLAG: bool = false;\n }\n")
        code, out = self.verdict()
        self.assertEqual(code, 1)
        self.assertIn("it changes text after admits", out)

    def test_c_string_literals_are_blanked(self) -> None:
        source = 'const S: &CStr = c"a \\" } fn evil() {";\nconst R: &CStr = cr#"a " } fn evil2() {"#;\nimpl G { fn ok() {} }\n'
        self.assertEqual([(d.name, d.owner) for d in c6.declarations(source)], [("ok", "G")])

    def test_comments_only_mode_keeps_every_literal_and_blanks_every_comment(self) -> None:
        source = 'a /* x /* y */ z */ b // c\nlet s = "q"; let r = cr#"w"#; let ch = \'"\'; let l: &\'a u8;\n'
        out = c6.blank(source, c6.Wipe.COMMENTS)
        self.assertEqual(len(out), len(source))
        self.assertEqual(out.split()[:2], ["a", "b"])
        for kept in ('"q"', 'cr#"w"#', "'\"'", "&'a"):
            self.assertIn(kept, out)
        for gone in ("x", "y", "z", "// c"):
            self.assertNotIn(gone, out.split("\n")[0].replace("a ", "", 1).replace(" b", "", 1))
        self.assertEqual(c6.blank(source), c6.blank(source, c6.Wipe.COMMENTS_AND_LITERALS))
        self.assertNotIn('"q"', c6.blank(source))

    def test_a_brace_inside_an_impl_header_does_not_open_its_body(self) -> None:
        decls = c6.declarations("impl Foo<[u8; { 1 }]> {\n    fn m(&self) {}\n}\n")
        self.assertEqual([(d.name, d.owner) for d in decls], [("m", "Foo")])

    def test_a_removed_line_that_starts_with_dashes_is_part_of_the_hunk(self) -> None:
        # A file line `--x;` is removed as `---x;`, which reads like a file header.
        self.repo.files["src/guard.rs"] = GUARD.replace("        allowed\n", "--x;\n        allowed\n")
        self.repo.files[f"{c6.PATCHES}/http/1_admits.patch"] = (
            "diff --git a/src/guard.rs b/src/guard.rs\n--- a/src/guard.rs\n+++ b/src/guard.rs\n"
            "@@ -3,3 +3,2 @@\n         let allowed = host == self.host;\n"
            "---x;\n         allowed\n")
        code, out = self.verdict()
        self.assertEqual(code, 0, out)


class RoundThree(unittest.TestCase):
    """The last review round's counterexamples (MIK-8245), each an input that resolved wrongly."""

    def setUp(self) -> None:
        self.repo = Repo()

    def tearDown(self) -> None:
        self.repo.close()

    def test_code_added_after_the_closing_brace_is_refused(self) -> None:
        self.repo.files[f"{c6.PATCHES}/http/1_admits.patch"] = (
            "diff --git a/src/guard.rs b/src/guard.rs\n--- a/src/guard.rs\n+++ b/src/guard.rs\n"
            "@@ -3,4 +3,4 @@\n         let allowed = host == self.host;\n         allowed\n"
            "-    }\n+    } const C6_REVIEW_EXTRA: bool = true;\n }\n")
        code, out = self.repo.run()
        self.assertEqual(code, 1)
        self.assertIn("it changes text after admits", out)

    def test_a_line_added_after_the_closing_brace_is_refused(self) -> None:
        self.repo.files[f"{c6.PATCHES}/http/1_admits.patch"] = (
            "diff --git a/src/guard.rs b/src/guard.rs\n--- a/src/guard.rs\n+++ b/src/guard.rs\n"
            "@@ -3,4 +3,5 @@\n         let allowed = host == self.host;\n         allowed\n"
            "-    }\n+    }\n+    const X: bool = true;\n }\n")
        code, out = self.repo.run()
        self.assertEqual(code, 1)
        self.assertIn("it changes text after admits", out)

    def test_a_same_length_edit_before_the_function_is_refused(self) -> None:
        # Only the text before `fn` differs; the function itself is unchanged in length and place.
        self.repo.files["src/guard.rs"] = "const BEFORE: bool = true;\n" + GUARD
        self.repo.files[f"{c6.PATCHES}/http/1_admits.patch"] = (
            "diff --git a/src/guard.rs b/src/guard.rs\n--- a/src/guard.rs\n+++ b/src/guard.rs\n"
            "@@ -1,3 +1,3 @@\n-const BEFORE: bool = true;\n+const BEFORE: bool = fals;\n impl Guard {\n"
            "     fn admits(&self, host: &str) -> bool {\n")
        code, out = self.repo.run()
        self.assertEqual(code, 1, out)
        self.assertIn("it changes text before admits", out)

    def test_a_same_length_edit_after_the_function_is_refused(self) -> None:
        self.repo.files["src/guard.rs"] = GUARD + "const AFTER: bool = true;\n"
        self.repo.files[f"{c6.PATCHES}/http/1_admits.patch"] = (
            "diff --git a/src/guard.rs b/src/guard.rs\n--- a/src/guard.rs\n+++ b/src/guard.rs\n"
            "@@ -5,3 +5,3 @@\n     }\n }\n-const AFTER: bool = true;\n+const AFTER: bool = fals;\n")
        code, out = self.repo.run()
        self.assertEqual(code, 1, out)
        self.assertIn("it changes text after admits", out)

    def test_a_macro_invocation_spelled_with_spaces_is_skipped(self) -> None:
        source = "macro_rules ! ignore { ($($tt:tt)*) => {} }\nignore ! { impl Guard { fn admits() {} } }\nimpl G { fn real() {} }\n"
        self.assertEqual([(d.name, d.owner) for d in c6.declarations(source)], [("real", "G")])

    def test_a_bare_name_never_binds_a_method_left_in_the_recorded_file(self) -> None:
        # The free fn moved away; a method of the same name stays where the row points.
        self.repo.files[c6.RANKING] = RANK_HEAD + "1\tSAMPLE\tHTTP dispatch\tsrc/guard.rs\tadmits\t1\tAdmits.\n"
        self.repo.files["src/real.rs"] = "fn admits(host: &str) -> bool {\n    host.is_empty()\n}\n"
        code, out = self.repo.run()
        self.assertEqual(code, 1, out)
        self.assertNotIn("in-place", out)

    def test_qualify_adds_an_owner_but_never_renames(self) -> None:
        self.repo.files[c6.RANKING] = RANK_HEAD + "1\tSAMPLE\tHTTP dispatch\tsrc/guard.rs\tadmits\t1\tAdmits.\n"
        self.repo.files[c6.REPLACEMENTS] += "HTTP dispatch\t1\tqualify\t\tsrc/guard.rs\tGuard::admits\t1\tidentity\n"
        code, out = self.repo.run()
        self.assertEqual(code, 0, out)
        for bad in ("Guard::permits", "Other::Guard::admits", "::admits"):
            self.repo.files[c6.REPLACEMENTS] = REPL_HEAD + f"HTTP dispatch\t1\tqualify\t\tsrc/guard.rs\t{bad}\t1\tx\n"
            with self.assertRaisesRegex(LookupError, "only turn a bare name"):
                self.repo.run()
        # An owner already given cannot be swapped for another.
        self.repo.files[c6.RANKING] = RANK_HEAD + "1\tSAMPLE\tHTTP dispatch\tsrc/guard.rs\tGuard::admits\t1\tAdmits.\n"
        self.repo.files[c6.REPLACEMENTS] = REPL_HEAD + "HTTP dispatch\t1\tqualify\t\tsrc/guard.rs\tOther::admits\t1\tx\n"
        with self.assertRaisesRegex(LookupError, "only turn a bare name"):
            self.repo.run()


class KillerFilters(unittest.TestCase):
    """The gap row's test filter must name exactly one test in the crate's module tree."""

    def setUp(self) -> None:
        self.repo = Repo()

    def tearDown(self) -> None:
        self.repo.close()

    def filter(self, args: str) -> None:
        table = self.repo.files[GAP_TABLE]
        self.repo.files[GAP_TABLE] = table.replace("--lib checks::guard_admits_only_its_host", args)

    def test_a_test_moved_to_another_module_is_refused_naming_where_it_is(self) -> None:
        self.repo.files["src/checks.rs"] = "mod host;\n"
        self.repo.files["src/checks/host.rs"] = KILLER
        code, out = self.repo.run()
        self.assertEqual(code, 1, out)
        self.assertIn("test filter checks::guard_admits_only_its_host does not match the module tree: "
                      "fn guard_admits_only_its_host is checks::host::guard_admits_only_its_host at src/checks/host.rs:2", out)

    def test_a_bare_name_defined_twice_is_refused_naming_both(self) -> None:
        self.filter("--lib guard_admits_only_its_host")
        self.repo.files["src/checks.rs"] = "mod host;\n" + KILLER
        self.repo.files["src/checks/host.rs"] = KILLER
        code, out = self.repo.run()
        self.assertEqual(code, 1, out)
        self.assertIn("fn guard_admits_only_its_host is defined 2 times: ", out)
        self.assertIn("checks::guard_admits_only_its_host at src/checks.rs:3", out)
        self.assertIn("checks::host::guard_admits_only_its_host at src/checks/host.rs:2", out)

    def test_a_filter_naming_no_fn_is_refused(self) -> None:
        self.filter("--lib checks::guard_refuses_a_foreign_host")
        code, out = self.repo.run()
        self.assertEqual(code, 1, out)
        self.assertIn("no fn guard_refuses_a_foreign_host in the crate rooted at src/lib.rs", out)

    def test_a_path_mounted_module_resolves_to_its_declared_name(self) -> None:
        self.repo.files["src/lib.rs"] = '#[cfg(test)]\n#[path = "guard_checks.rs"]\nmod checks;\n'
        self.repo.files.pop("src/checks.rs")
        self.repo.files["src/guard_checks.rs"] = KILLER
        code, out = self.repo.run()
        self.assertEqual(code, 0, out)

    def test_inline_modules_add_their_names_and_their_directories(self) -> None:
        self.filter("--lib checks::inner::deep::guard_admits_only_its_host")
        self.repo.files["src/checks.rs"] = "mod inner {\n    mod deep;\n}\n"
        self.repo.files["src/checks/inner/deep.rs"] = KILLER
        code, out = self.repo.run()
        self.assertEqual(code, 0, out)

    def test_an_unmounted_copy_does_not_count(self) -> None:
        self.filter("--lib guard_admits_only_its_host")
        self.repo.files["src/old/checks.rs"] = KILLER  # no `mod` loads it: not part of the crate
        code, out = self.repo.run()
        self.assertEqual(code, 0, out)

    def test_an_integration_test_target_is_its_own_crate(self) -> None:
        self.filter("--test acs issuer::guard_admits_only_its_host")
        self.repo.files["tests/acs.rs"] = "mod issuer;\n"
        self.repo.files["tests/issuer.rs"] = KILLER
        code, out = self.repo.run()
        self.assertEqual(code, 0, out)

    def test_a_test_target_with_a_declared_path_is_read_from_that_path(self) -> None:
        self.filter("--test acs guard_admits_only_its_host")
        self.repo.files["Cargo.toml"] = ('[package]\nname = "x"\n\n[[test]]\nname = "acs"\n'
                                         'path = "tests/suites/acs_main.rs"\n\n[features]\n')
        self.repo.files["tests/suites/acs_main.rs"] = KILLER
        self.repo.files["tests/acs.rs"] = "// not the target: cargo reads the declared path\n"
        code, out = self.repo.run()
        self.assertEqual(code, 0, out)

    def test_a_filter_that_is_part_of_a_second_tests_path_is_refused(self) -> None:
        # Cargo matches the filter as a substring of each test path: both would run.
        self.filter("--lib guard_admits_only_its_host")
        self.repo.files["src/checks.rs"] = KILLER + "#[tokio::test]\nasync fn guard_admits_only_its_host_twice() {}\n"
        code, out = self.repo.run()
        self.assertEqual(code, 1, out)
        self.assertIn("test filter guard_admits_only_its_host matches 2 tests: checks::guard_admits_only_its_host, "
                      "checks::guard_admits_only_its_host_twice", out)

    def test_a_filter_inside_a_module_name_counts_that_modules_tests(self) -> None:
        self.filter("--lib guard_admits_only_its_host")
        self.repo.files["src/checks.rs"] = KILLER + "mod guard_admits_only_its_host_cases {\n    #[test]\n    fn first() {}\n}\n"
        code, out = self.repo.run()
        self.assertEqual(code, 1, out)
        self.assertIn("checks::guard_admits_only_its_host_cases::first", out)

    def test_a_helper_whose_name_contains_the_filter_is_not_a_test(self) -> None:
        self.filter("--lib guard_admits_only_its_host")
        self.repo.files["src/checks.rs"] = KILLER + "fn guard_admits_only_its_host_fixture() {}\n"
        code, out = self.repo.run()
        self.assertEqual(code, 0, out)

    def test_a_spaced_path_attribute_is_still_the_modules_file(self) -> None:
        # rustc reads `#[ path = ... ]` too: src/checks.rs is then not part of the crate.
        self.repo.files["src/lib.rs"] = '#[ path = "guard_checks.rs" ]\nmod checks;\n'
        self.repo.files["src/guard_checks.rs"] = "// the killer moved away\n"
        code, out = self.repo.run()
        self.assertEqual(code, 1, out)
        self.assertIn("no fn guard_admits_only_its_host in the crate rooted at src/lib.rs", out)

    def test_a_comment_between_fn_and_its_name_still_declares_it(self) -> None:
        self.filter("--lib guard_admits_only_its_host")
        self.repo.files["src/lib.rs"] = "mod checks;\nmod more;\n"
        self.repo.files["src/more.rs"] = "#[test]\nfn /* moved */ guard_admits_only_its_host() {}\n"
        code, out = self.repo.run()
        self.assertEqual(code, 1, out)
        self.assertIn("fn guard_admits_only_its_host is defined 2 times", out)

    def test_a_mod_inside_a_macro_definition_is_not_a_module(self) -> None:
        self.repo.files["src/lib.rs"] = "mod checks;\nmacro_rules! wrap {\n    () => {\n        mod gone;\n    };\n}\n"
        code, out = self.repo.run()
        self.assertEqual(code, 0, out)

    def test_a_declared_module_with_no_file_is_unreadable_not_skipped(self) -> None:
        self.repo.files["src/lib.rs"] = "mod checks;\nmod gone;\n"
        code, out = self.repo.run()
        self.assertEqual(code, 1, out)
        self.assertIn("mod gone in src/lib.rs: none of src/gone.rs, src/gone/mod.rs", out)


class TheReleaseLine(unittest.TestCase):
    """The resolver on this repository's own tree: the 68 obligations, their manifest ids in
    killer-gap order, and the six freeze-day batches the procedure documents."""

    def test_every_obligation_resolves_and_the_batches_are_the_documented_ones(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = c6.main(["--tree", "HEAD", "--manifest", scratch])
            self.assertEqual(code, 0, out.getvalue())
            self.assertIn("68 framed obligations, 0 framed items unresolved", out.getvalue())
            rows = (Path(scratch) / "manifest.tsv").read_text().splitlines()[1:]
        ids = [row.split("\t")[0] for row in rows]
        self.assertEqual(len(ids), 68)
        # The procedure's six hosted batches: the manifest's rows dealt round robin.
        batches = [[i for k, i in enumerate(ids) if k % 6 == b] for b in range(6)]
        self.assertEqual([len(b) for b in batches], [12, 12, 11, 11, 11, 11])
        self.assertEqual(sorted(i for b in batches for i in b), sorted(ids))
        self.assertEqual(batches[4][:6], ["HTTP_05", "HTTP_11", "ACCT_01", "ACCT_07", "ACCT_13", "OAUTH_03"])
        # Batch 5 carries the three rows whose patches once had a tracker id in their context.
        self.assertTrue({"HTTP_11", "OAUTH_03", "STARTUP_03"} <= set(batches[4]))
        self.assertIn("STARTUP_09", ids)
        self.assertNotIn("STARTUP_01", ids)  # replaced under G11



if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)

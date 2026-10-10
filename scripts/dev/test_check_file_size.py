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
import subprocess
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

    def test_t11_a_workspace_crate_file_is_held_to_the_ceiling(self):
        # MIK-8163: crates/ is production source too (gateway-core).
        status, out = self.run_gate("", {"crates/core/src/lib.rs": body(801)})
        self.assertEqual(status, 1, out)
        self.assertIn("FAIL crates/core/src/lib.rs: 801 lines, over the 800-line ceiling", out)

    def test_t8_the_repository_tree_passes(self):
        gate = load_gate(Path(__file__).resolve().parents[2])
        gate.BASELINE = SCRIPT.with_name("file-size-baseline.txt")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            status = gate.main()
        self.assertEqual(status, 0, out.getvalue())


def run_main(root: Path, argv: list[str]) -> tuple[int, str]:
    gate = load_gate(root)
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        status = gate.main(argv)
    return status, out.getvalue()


class OneRule(unittest.TestCase):
    """MIK-8210: the two cases the retired shell gate counted differently are
    counted one way, by this gate alone."""

    def tree(self, files: dict[str, str]) -> tuple[int, str]:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            for rel, text in files.items():
                (root / rel).parent.mkdir(parents=True, exist_ok=True)
                (root / rel).write_text(text, encoding="utf-8")
            (root / "file-size-baseline.txt").write_text("", encoding="utf-8")
            return run_main(root, [])

    def test_d1_mod_declarations_are_not_counted(self):
        # 801 raw lines (the shell's `wc -l` breach), 798 counted.
        status, out = self.tree({"src/mods.rs": body(798) + "mod a;\nmod b;\nmod c;\n"})
        self.assertEqual(status, 0, out)

    def test_d2_test_file_names_are_held_to_the_ceiling(self):
        # The shell skipped `*_tests.rs` and `tests.rs`; one gate holds every file.
        status, out = self.tree({"src/big_tests.rs": body(801), "src/x/tests.rs": body(801)})
        self.assertEqual(status, 1, out)
        self.assertIn("FAIL src/big_tests.rs: 801 lines, over the 800-line ceiling", out)
        self.assertIn("FAIL src/x/tests.rs: 801 lines, over the 800-line ceiling", out)


class Ratchet(unittest.TestCase):
    """MIK-8210: the baseline is the count ratchet. Rows may shrink or leave;
    a PR may not add a row or raise an allowance, even through --update."""

    def gate(self):
        return load_gate(Path("/nonexistent"))

    def test_r1_a_new_row_is_refused(self):
        errors = self.gate().check_ratchet({"src/a.rs": 805}, {"src/a.rs": 805, "src/b.rs": 801})
        self.assertTrue(any("src/b.rs" in e for e in errors), errors)

    def test_r2_an_equal_count_replacement_is_refused(self):
        errors = self.gate().check_ratchet({"src/a.rs": 805}, {"src/b.rs": 805})
        self.assertTrue(any("src/b.rs" in e for e in errors), errors)

    def test_r3_a_raised_allowance_is_refused(self):
        errors = self.gate().check_ratchet({"src/a.rs": 805}, {"src/a.rs": 806})
        self.assertTrue(any("src/a.rs" in e and "805" in e and "806" in e for e in errors), errors)

    def test_r4_shrinking_and_leaving_pass(self):  # green control
        self.assertEqual(self.gate().check_ratchet({"src/a.rs": 805, "src/b.rs": 900}, {"src/a.rs": 801}), [])

    def test_r5_an_unreadable_base_fails_naming_the_ref(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "file-size-baseline.txt").write_text("", encoding="utf-8")
            status, out = run_main(root, ["--base", "nosuchref"])
        self.assertEqual(status, 1, out)
        self.assertIn("nosuchref", out)

    def test_r6_base_is_read_through_git(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            git = lambda *a: subprocess.run(["git", *a], cwd=root, check=True, capture_output=True)
            git("init", "-q")
            git("config", "user.email", "t@t")
            git("config", "user.name", "t")
            (root / "src").mkdir()
            (root / "src/a.rs").write_text(body(805), encoding="utf-8")
            (root / "scripts/dev").mkdir(parents=True)
            baseline = root / "scripts/dev/file-size-baseline.txt"
            baseline.write_text("805 src/a.rs\n", encoding="utf-8")
            git("add", "-A")
            git("commit", "-qm", "base")
            (root / "src/b.rs").write_text(body(801), encoding="utf-8")
            baseline.write_text("805 src/a.rs\n801 src/b.rs\n", encoding="utf-8")
            gate = load_gate(root)
            gate.BASELINE = baseline
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
                status = gate.main(["--base", "HEAD"])
        self.assertEqual(status, 1, out.getvalue())
        self.assertIn("src/b.rs", out.getvalue())


class RatchetThroughGit(unittest.TestCase):
    def test_r7_a_raised_allowance_through_base_is_refused(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            git = lambda *a: subprocess.run(["git", *a], cwd=root, check=True, capture_output=True)
            git("init", "-q")
            git("config", "user.email", "t@t")
            git("config", "user.name", "t")
            (root / "src").mkdir()
            (root / "src/a.rs").write_text(body(805), encoding="utf-8")
            (root / "scripts/dev").mkdir(parents=True)
            baseline = root / "scripts/dev/file-size-baseline.txt"
            baseline.write_text("805 src/a.rs\n", encoding="utf-8")
            git("add", "-A")
            git("commit", "-qm", "base")
            (root / "src/a.rs").write_text(body(806), encoding="utf-8")
            baseline.write_text("806 src/a.rs\n", encoding="utf-8")
            gate = load_gate(root)
            gate.BASELINE = baseline
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
                status = gate.main(["--base", "HEAD"])
        self.assertEqual(status, 1, out.getvalue())
        self.assertIn("src/a.rs", out.getvalue())
        self.assertIn("806", out.getvalue())


    def renamed(self, annotation: str) -> tuple[int, str]:
        """`src/a.rs` (805 lines, baselined) renamed to `src/b.rs`, its new
        row preceded by `annotation`, judged through main() against the base."""
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            git = lambda *a: subprocess.run(["git", *a], cwd=root, check=True, capture_output=True)
            git("init", "-q")
            git("config", "user.email", "t@t")
            git("config", "user.name", "t")
            (root / "src").mkdir()
            (root / "src/a.rs").write_text(body(805), encoding="utf-8")
            (root / "scripts/dev").mkdir(parents=True)
            baseline = root / "scripts/dev/file-size-baseline.txt"
            baseline.write_text("805 src/a.rs\n", encoding="utf-8")
            git("add", "-A")
            git("commit", "-qm", "base")
            (root / "src/a.rs").unlink()
            (root / "src/b.rs").write_text(body(805), encoding="utf-8")
            baseline.write_text(f"{annotation}805 src/b.rs\n", encoding="utf-8")
            gate = load_gate(root)
            gate.BASELINE = baseline
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
                status = gate.main(["--base", "HEAD"])
        return status, out.getvalue()

    def test_r8_an_annotated_rename_through_main_passes(self):  # MIK-8291
        status, out = self.renamed("# moved-from src/a.rs\n")
        self.assertEqual(status, 0, out)

    def test_r9_an_unannotated_rename_through_main_fails(self):  # MIK-8291
        status, out = self.renamed("")
        self.assertEqual(status, 1, out)
        self.assertIn("src/b.rs", out)

class Modes(unittest.TestCase):
    def test_update_and_base_cannot_combine(self):
        # --update with --base would rewrite the baseline and skip the ratchet.
        with self.assertRaises(SystemExit) as raised, contextlib.redirect_stderr(io.StringIO()):
            load_gate(Path("/nonexistent")).main(["--update", "--base", "HEAD"])
        self.assertNotEqual(raised.exception.code, 0)

    def test_a_misspelled_option_is_refused(self):
        with self.assertRaises(SystemExit) as raised, contextlib.redirect_stderr(io.StringIO()):
            load_gate(Path("/nonexistent")).main(["--bse", "HEAD"])
        self.assertNotEqual(raised.exception.code, 0)


class Wiring(unittest.TestCase):
    """MIK-8210: one gate runs in CI, against an explicit base."""

    REPO = Path(__file__).resolve().parents[2]

    def test_w1_the_shell_gate_is_gone_and_ci_passes_a_base(self):
        self.assertFalse((self.REPO / "scripts/ci/check-loc-ceiling.sh").exists())
        ci = (self.REPO / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertNotIn("check-loc-ceiling", ci)
        step = ci[ci.index("- name: Check the 800-line ceiling") :]
        step = step[: step.find("\n      - ", 1) if "\n      - " in step[1:] else len(step)]
        self.assertIn("check-file-size.py --base", step)
        self.assertIn("git fetch", step)
        self.assertIn("0000000000000000000000000000000000000000", step)
        # The base: the PR's base on a pull request, the previous tip on a
        # push, and the parent commit when a push has no previous tip.
        self.assertIn("github.event.pull_request.base.sha || github.event.before", step)
        self.assertIn("HEAD^", step)



class MovedRows(unittest.TestCase):
    """MIK-8291 (split-baselines): a new row is a move when `# moved-from`
    names a donor row that shrank or left in the same change. The total
    excess may not rise and a listed row may not grow."""

    def ratchet(self, base, head, moved=None):
        return load_gate(Path("/nonexistent")).check_ratchet(base, head, moved)

    def test_m1_an_annotated_rename_passes(self):
        self.assertEqual(self.ratchet({"src/a.rs": 1000}, {"src/b.rs": 1000}, {"src/b.rs": ["src/a.rs"]}), [])

    def test_m1b_an_unannotated_rename_fails(self):
        errors = self.ratchet({"src/a.rs": 1000}, {"src/b.rs": 1000})
        self.assertTrue(any("src/b.rs" in e and "moved-from" in e for e in errors), errors)

    def test_m2_an_annotated_split_leaving_one_part_over_the_ceiling_passes(self):
        # 1000 -> 150 left in place (row leaves) + 850 moved to b.
        self.assertEqual(self.ratchet({"src/a.rs": 1000}, {"src/b.rs": 850}, {"src/b.rs": ["src/a.rs"]}), [])

    def test_m2b_a_three_way_split_may_name_one_donor_for_each_part(self):
        moved = {p: ["src/a.rs"] for p in ("src/b.rs", "src/c.rs", "src/d.rs")}
        head = {"src/b.rs": 850, "src/c.rs": 850, "src/d.rs": 850}
        self.assertEqual(self.ratchet({"src/a.rs": 2550}, head, moved), [])

    def test_m3_a_new_oversized_file_with_no_annotation_fails(self):
        errors = self.ratchet({"src/a.rs": 1000}, {"src/a.rs": 1000, "src/c.rs": 850})
        self.assertTrue(any("src/c.rs" in e for e in errors), errors)

    def test_m3b_a_donor_that_did_not_shrink_fails(self):
        errors = self.ratchet({"src/a.rs": 1000}, {"src/a.rs": 1000, "src/c.rs": 850}, {"src/c.rs": ["src/a.rs"]})
        self.assertTrue(any("src/c.rs" in e and "src/a.rs" in e for e in errors), errors)

    def test_m3c_a_donor_that_is_not_a_baseline_row_fails(self):
        errors = self.ratchet({"src/a.rs": 1000}, {"src/a.rs": 900, "src/c.rs": 850}, {"src/c.rs": ["src/small.rs"]})
        self.assertTrue(any("src/c.rs" in e and "src/small.rs" in e for e in errors), errors)

    def test_m4_a_listed_row_that_grows_fails(self):
        errors = self.ratchet({"src/a.rs": 1000}, {"src/a.rs": 1001})
        self.assertTrue(any("src/a.rs" in e and "1001" in e for e in errors), errors)

    def test_m5_a_new_row_bigger_than_what_moved_fails(self):
        # The donor gave up 50 lines but the "moved" file is 900 lines over:
        # excess 200 -> 150 + 100. Only the total rule stops it.
        errors = self.ratchet({"src/a.rs": 1000}, {"src/a.rs": 950, "src/b.rs": 900}, {"src/b.rs": ["src/a.rs"]})
        self.assertTrue(any("total" in e for e in errors), errors)

    def test_m6_a_total_excess_that_rises_fails(self):
        errors = self.ratchet({"src/a.rs": 801}, {"src/b.rs": 841}, {"src/b.rs": ["src/a.rs"]})
        self.assertTrue(any("total" in e for e in errors), errors)

    def test_m9_a_row_under_the_ceiling_cannot_cancel_a_rising_total(self):
        # A hand-edited 5-line row would be -795 lines of "excess"; each row's
        # excess counts from 0. (The 5-line row needs no annotation to sink
        # the total, so the test pins the total, not the annotation.)
        errors = self.ratchet(
            {"src/a.rs": 801},
            {"src/b.rs": 841, "src/z.rs": 5},
            {"src/b.rs": ["src/a.rs"], "src/z.rs": ["src/a.rs"]},
        )
        self.assertTrue(any("total" in e for e in errors), errors)


class MovedAnnotations(unittest.TestCase):
    """The `# moved-from` lines: which row they name, and that --update keeps them."""

    def test_annotations_attach_to_the_row_directly_below(self):
        gate = load_gate(Path("/nonexistent"))
        text = "# header\n# moved-from src/a.rs\n# moved-from src/x.rs\n850 src/b.rs\n900 src/c.rs\n"
        self.assertEqual(gate.parse_moved(text), {"src/b.rs": ["src/a.rs", "src/x.rs"]})

    def test_a_blank_line_or_other_comment_detaches_an_annotation(self):
        gate = load_gate(Path("/nonexistent"))
        self.assertEqual(gate.parse_moved("# moved-from src/a.rs\n\n850 src/b.rs\n"), {})
        self.assertEqual(gate.parse_moved("# moved-from src/a.rs\n# note\n850 src/b.rs\n"), {})

    def test_update_keeps_the_annotations_of_surviving_rows(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            gate = load_gate(root)
            gate.write_baseline({"src/b.rs": 850, "src/c.rs": 900}, {"src/b.rs": ["src/a.rs"], "src/gone.rs": ["src/a.rs"]})
            text = gate.BASELINE.read_text(encoding="utf-8")
        self.assertEqual(gate.parse_moved(text), {"src/b.rs": ["src/a.rs"]})
        self.assertEqual(gate.parse_baseline(text), {"src/b.rs": 850, "src/c.rs": 900})


if __name__ == "__main__":
    unittest.main()

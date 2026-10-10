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


    def renamed(self, head_text: str) -> tuple[int, str]:
        """`src/a.rs` (805 lines, baselined) renamed to `src/b.rs` holding
        `head_text`, judged through main() against the base commit."""
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
            (root / "src/b.rs").write_text(head_text, encoding="utf-8")
            baseline.write_text(f"{head_text.count(chr(10))} src/b.rs\n", encoding="utf-8")
            gate = load_gate(root)
            gate.BASELINE = baseline
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
                status = gate.main(["--base", "HEAD"])
        return status, out.getvalue()

    def test_r8_a_rename_through_main_carries_its_row(self):  # MIK-8291
        status, out = self.renamed(body(805))
        self.assertEqual(status, 0, out)

    def test_r9_a_rename_that_changes_the_text_fails_through_main(self):  # MIK-8291
        status, out = self.renamed(body(805).replace("fn f", "pub fn f"))
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



def code(start: int, count: int) -> list[str]:
    """`count` distinct, non-trivial source lines."""
    return [f"    let v{i} = {i};" for i in range(start, start + count)]


def text(lines: list[str]) -> str:
    return "".join(f"{line}\n" for line in lines)


class MovedRows(unittest.TestCase):
    """MIK-8291 (split-baselines): a new row may carry lines moved from a row
    that shrank or left. The total excess may not rise, a listed row may not
    grow, and a new row's excess over the ceiling must be covered by moved
    lines; changed text does not match and fails safe."""

    HEADER = ["// SPDX-FileCopyrightText: 2026 Mikko Parkkola", "use super::*;"]

    def ratchet(self, base, head, base_texts, head_texts):
        return load_gate(Path("/nonexistent")).check_ratchet(base, head, base_texts, head_texts)

    def test_m1_a_whole_file_rename_passes(self):
        lines = code(0, 1000)
        errors = self.ratchet({"src/a.rs": 1000}, {"src/b.rs": 1000}, {"src/a.rs": text(lines)}, {"src/b.rs": text(lines)})
        self.assertEqual(errors, [])

    def test_m2_a_split_leaving_one_part_over_the_ceiling_passes(self):
        lines = code(0, 1000)
        moved, kept = lines[:848], lines[848:]
        part = self.HEADER + moved
        errors = self.ratchet(
            {"src/a.rs": 1000},
            {"src/b.rs": len(part)},
            {"src/a.rs": text(lines)},
            {"src/a.rs": text(kept), "src/b.rs": text(part)},
        )
        self.assertEqual(errors, [])

    def test_m3_a_new_oversized_file_with_nothing_moved_fails(self):
        lines = code(0, 1000)
        errors = self.ratchet(
            {"src/a.rs": 1000},
            {"src/a.rs": 1000, "src/c.rs": 850},
            {"src/a.rs": text(lines)},
            {"src/a.rs": text(lines), "src/c.rs": text(code(5000, 850))},
        )
        self.assertTrue(any("src/c.rs" in e for e in errors), errors)

    def test_m4_a_listed_row_that_grows_fails(self):
        lines = code(0, 1000)
        errors = self.ratchet({"src/a.rs": 1000}, {"src/a.rs": 1001}, {"src/a.rs": text(lines)}, {"src/a.rs": text(lines + code(9000, 1))})
        self.assertTrue(any("src/a.rs" in e for e in errors), errors)

    def test_m5_a_new_row_bigger_than_what_moved_fails(self):
        lines = code(0, 1000)
        part = lines[:50] + code(5000, 850)
        errors = self.ratchet(
            {"src/a.rs": 1000},
            {"src/a.rs": 950, "src/b.rs": 900},
            {"src/a.rs": text(lines)},
            {"src/a.rs": text(lines[50:]), "src/b.rs": text(part)},
        )
        self.assertTrue(any("src/b.rs" in e for e in errors), errors)

    def test_m6_a_total_excess_that_rises_fails(self):
        # A full rename of an 801-line file plus a 40-line header: the new row
        # is within the header allowance, so only the total rule refuses the
        # excess rising 1 -> 41.
        lines = code(0, 801)
        part = code(5000, 40) + lines
        errors = self.ratchet({"src/a.rs": 801}, {"src/b.rs": 841}, {"src/a.rs": text(lines)}, {"src/b.rs": text(part)})
        self.assertTrue(any("total" in e for e in errors), errors)

    def test_m7_text_changed_in_the_move_fails_safe(self):
        lines = code(0, 1000)
        renamed = [line.replace("let", "let mut") for line in lines]
        errors = self.ratchet({"src/a.rs": 1000}, {"src/b.rs": 1000}, {"src/a.rs": text(lines)}, {"src/b.rs": text(renamed)})
        self.assertTrue(any("src/b.rs" in e for e in errors), errors)

    def test_m8_closing_braces_freed_by_deletion_carry_nothing(self):
        # Trivial lines do not match: deleting code from a listed file frees
        # its `}` lines, which a fabricated file may not claim.
        source = [x for i in range(500) for x in (f"    fn f{i}() {{", "    }")]
        fake = ["}"] * 900
        errors = self.ratchet(
            {"src/a.rs": 1000},
            {"src/c.rs": 900},
            {"src/a.rs": text(source)},
            {"src/a.rs": "", "src/c.rs": text(fake)},
        )
        self.assertTrue(any("src/c.rs" in e for e in errors), errors)

    def test_m9_a_row_under_the_ceiling_cannot_cancel_a_rising_total(self):
        # A hand-edited 5-line row would be -795 lines of "excess" and hide
        # m6's rise from the total rule; each row's excess counts from 0.
        lines = code(0, 801)
        part = code(5000, 40) + lines
        errors = self.ratchet(
            {"src/a.rs": 801},
            {"src/b.rs": 841, "src/z.rs": 5},
            {"src/a.rs": text(lines)},
            {"src/b.rs": text(part), "src/z.rs": text(code(7000, 5))},
        )
        self.assertTrue(any("total" in e for e in errors), errors)

    def test_m10_a_new_file_carrying_a_handful_of_moved_lines_fails(self):
        # Excess 1, but 796 of its 801 lines are new: a move carries nearly
        # the whole file, not just its excess.
        lines = code(0, 1000)
        fresh = lines[:5] + code(5000, 796)
        errors = self.ratchet(
            {"src/a.rs": 1000},
            {"src/a.rs": 995, "src/c.rs": 801},
            {"src/a.rs": text(lines)},
            {"src/a.rs": text(lines[5:]), "src/c.rs": text(fresh)},
        )
        self.assertTrue(any("src/c.rs" in e for e in errors), errors)

    def test_m11_an_unchanged_rename_of_a_brace_heavy_file_passes(self):
        # Half its lines are trivial; carried with the code they close.
        lines = [x for i in range(1000) for x in (f"    fn f{i}() {{", "    }")]
        errors = self.ratchet({"src/a.rs": 2000}, {"src/b.rs": 2000}, {"src/a.rs": text(lines)}, {"src/b.rs": text(lines)})
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()

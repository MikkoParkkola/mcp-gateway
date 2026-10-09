#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Tests for upgrading_fragments.py: fragment shape, numbering, assembly order
independence, the frozen ceiling and the deletion guard (MIK-8185)."""

import importlib.util
import os
import pathlib
import subprocess
import tempfile
import unittest

_SPEC = importlib.util.spec_from_file_location(
    "upgrading_fragments", pathlib.Path(__file__).with_name("upgrading_fragments.py")
)
uf = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(uf)

DOC = """# Upgrading to 4.0

Intro.

## What changed

| # | Change | Action needed |
|---|---|---|
| 1 | One | Do one |
| 2 | Never assigned | None |
| 3 | Three | Do three |

Pending entries live in `upgrading.d/` until release preparation numbers them.

## 1. One

**Startup:** prints a notice

Body one.

## 3. Three

**Startup:** no notice

Body three.

## Upgrading from 3.5.x: a walkthrough

Steps.
"""


def frag(title, change="C", action="A", marker="no notice", notice=None, body="Body.", extra=""):
    head = f"---\nchange: {change}\naction: {action}\n"
    if notice is not None:
        head += f"notice: {notice}\n"
    return f"{head}{extra}---\n## {title}\n\n**Startup:** {marker}\n\n{body}\n"


def errors_of(name, text):
    fragment, errors = uf.parse(name, text)
    return fragment, errors


class Parse(unittest.TestCase):
    def test_a_valid_fragment_parses(self):  # green control
        f, errors = errors_of("3700.md", frag("Cap search takes -C", change="cap search -C", action="None"))
        self.assertEqual(errors, [])
        self.assertIsNotNone(f)
        self.assertEqual((f.title, f.change, f.action, f.notice), ("Cap search takes -C", "cap search -C", "None", None))

    def test_crlf_parses_like_lf(self):
        text = frag("T", notice="re-login", marker="prints a notice")
        lf, _ = errors_of("1.md", text)
        crlf, errors = errors_of("1.md", text.replace("\n", "\r\n"))
        self.assertEqual(errors, [])
        self.assertIsNotNone(crlf)
        self.assertEqual((crlf.title, crlf.body, crlf.notice), (lf.title, lf.body, lf.notice))

    def assertRefused(self, text, needle):
        _, errors = errors_of("3701.md", text)
        self.assertTrue(errors, f"accepted: {text!r}")
        self.assertTrue(all("upgrading.d/3701.md" in e for e in errors), errors)
        self.assertTrue(any(needle in e for e in errors), errors)

    def test_unknown_key(self):
        self.assertRefused(frag("T", extra="number: 7\n"), "unknown key")

    def test_missing_key(self):
        self.assertRefused(frag("T").replace("action: A\n", ""), "missing `action`")

    def test_empty_value(self):
        self.assertRefused(frag("T", change=""), "empty `change`")

    def test_pipe_in_a_cell(self):
        self.assertRefused(frag("T", change="a | b"), "`|`")
        self.assertRefused(frag("T", action="a | b"), "`|`")

    def test_no_title(self):
        self.assertRefused(frag("T").replace("## T\n", ""), "one `## ` title")

    def test_two_titles(self):
        self.assertRefused(frag("T", body="## Another\n\nx"), "one `## ` title")

    def test_marker_not_first(self):
        self.assertRefused(frag("T").replace("**Startup:**", "Prose.\n\n**Startup:**"), "first line after the title")

    def test_notice_without_a_notice_marker(self):
        self.assertRefused(frag("T", notice="x", marker="no notice"), "`notice:`")

    def test_notice_marker_without_a_phrase(self):
        self.assertRefused(frag("T", marker="prints a notice"), "`notice:`")

    def test_a_numbered_title_is_refused(self):
        self.assertRefused(frag("12. Twelve"), "number")


class Names(unittest.TestCase):
    def test_order_is_pr_then_suffix_then_name(self):
        names = ["3700-2.md", "3544.md", "3700.md", "3544-0.md", "3700-10.md"]
        self.assertEqual(
            sorted(names, key=uf.sort_key),
            ["3544-0.md", "3544.md", "3700.md", "3700-2.md", "3700-10.md"],
        )

    def test_name_errors(self):
        self.assertEqual(uf.name_errors(["3700.md", "3700-1.md", ".gitkeep", ".frozen-max"]), [])
        bad = uf.name_errors(["notes.md", "3700.txt", "-1.md"])
        self.assertEqual(len(bad), 3, bad)
        self.assertTrue(all(e.startswith("upgrading.d/") for e in bad), bad)


A = frag("Alpha", change="alpha change", action="do alpha", marker="prints a notice", notice="alpha phrase")
B = frag("Beta", change="beta change", action="do beta")


class Assemble(unittest.TestCase):
    def test_no_fragments_is_the_committed_doc(self):  # green control
        self.assertEqual(uf.assemble(DOC, 3, {}), (DOC, 3))

    def test_rows_sections_numbers_and_notice(self):
        out, top = uf.assemble(DOC, 3, {"3700.md": A, "3701.md": B})
        self.assertEqual(top, 5)
        self.assertIn("| 3 | Three | Do three |\n| 4 | alpha change | do alpha |\n| 5 | beta change | do beta |\n", out)
        self.assertIn(
            "## 4. Alpha\n\n**Startup:** prints a notice\n<!-- notice: alpha phrase -->\n\nBody.\n\n## 5. Beta\n",
            out,
        )
        self.assertLess(out.index("## 5. Beta"), out.index(uf.WALKTHROUGH))
        self.assertGreater(out.index("## 4. Alpha"), out.index("## 3. Three"))

    def test_order_comes_from_file_names_not_input_order(self):
        one, _ = uf.assemble(DOC, 3, {"3700.md": A, "3701.md": B})
        two, _ = uf.assemble(DOC, 3, {"3701.md": B, "3700.md": A})
        self.assertEqual(one, two)
        self.assertIn("## 4. Alpha", one)
        self.assertLess(one.index("## 4. Alpha"), one.index("## 5. Beta"))

    def test_crlf_doc_and_fragment(self):
        out, _ = uf.assemble(DOC.replace("\n", "\r\n"), 3, {"3700.md": A.replace("\n", "\r\n")})
        self.assertIn("## 4. Alpha", out)
        self.assertNotIn("\r", out)


class AssembleExact(unittest.TestCase):
    def test_the_whole_assembled_document(self):
        expected = DOC.replace(
            "| 3 | Three | Do three |\n",
            "| 3 | Three | Do three |\n| 4 | alpha change | do alpha |\n| 5 | beta change | do beta |\n",
        ).replace(
            uf.WALKTHROUGH,
            "## 4. Alpha\n\n**Startup:** prints a notice\n<!-- notice: alpha phrase -->\n\nBody.\n\n"
            "## 5. Beta\n\n**Startup:** no notice\n\nBody.\n\n" + uf.WALKTHROUGH,
        )
        self.assertEqual(uf.assemble(DOC, 3, {"3701.md": B, "3700.md": A}), (expected, 5))

    def test_file_names_bind_to_numbers(self):
        out, _ = uf.assemble(DOC, 3, {"3600.md": B, "3544.md": A})
        self.assertIn("## 4. Alpha", out)
        self.assertIn("## 5. Beta", out)

    def test_a_body_with_a_colon_line_is_body(self):
        text = frag("T", body="name: value\nmore: prose")
        f, errors = uf.parse("3705.md", text)
        self.assertEqual(errors, [])
        self.assertIsNotNone(f)
        self.assertIn("name: value", f.body)


class CheckDoc(unittest.TestCase):
    def parsed(self, files):
        return [uf.parse(n, t)[0] for n, t in files.items()]

    def test_a_clean_tree_passes(self):  # green control
        self.assertEqual(uf.check_doc(DOC, 3, self.parsed({"3700.md": A, "3701.md": B})), [])

    def test_a_number_above_the_ceiling_says_how_to_convert(self):
        doc = DOC.replace("| 3 | Three | Do three |\n", "| 3 | Three | Do three |\n| 4 | New | Act |\n").replace(
            uf.WALKTHROUGH, "## 4. New\n\n**Startup:** no notice\n\n" + uf.WALKTHROUGH
        )
        errors = uf.check_doc(doc, 3, [])
        self.assertTrue(any("item 4" in e and "upgrading.d/<pr>.md" in e for e in errors), errors)

    def test_frozen_max_must_equal_the_highest_number(self):
        errors = uf.check_doc(DOC, 2, [])
        self.assertTrue(any(".frozen-max" in e and "3" in e for e in errors), errors)
        errors = uf.check_doc(DOC, 4, [])
        self.assertTrue(any(".frozen-max" in e and "4" in e for e in errors), errors)

    def test_a_title_used_twice_is_refused(self):
        twin = frag("Alpha", change="x", action="y")
        errors = uf.check_doc(DOC, 3, self.parsed({"3700.md": A, "3702.md": twin}))
        self.assertTrue(any("Alpha" in e and "3702.md" in e for e in errors), errors)

    def test_a_title_equal_to_a_numbered_item_is_refused(self):
        errors = uf.check_doc(DOC, 3, self.parsed({"3703.md": frag("Three")}))
        self.assertTrue(any("Three" in e and "item 3" in e for e in errors), errors)


class OrderIndependence(unittest.TestCase):
    """The lead's acceptance: two PRs each adding a fragment merge in either
    order with no edit, and the release output does not depend on the order."""

    def test_two_fragment_only_diffs_apply_in_either_order(self):
        results = []
        for first, second in ((("3700.md", A), ("3701.md", B)), (("3701.md", B), ("3700.md", A))):
            with tempfile.TemporaryDirectory() as tmp:
                repo = pathlib.Path(tmp)
                git = lambda *a: subprocess.run(["git", *a], cwd=repo, check=True, capture_output=True, text=True)
                git("init", "-q")
                git("config", "user.email", "t@t")
                git("config", "user.name", "t")
                (repo / "upgrading.d").mkdir()
                (repo / "upgrading.d/.frozen-max").write_text("3\n")
                (repo / "doc.md").write_text(DOC)
                git("add", "-A")
                git("commit", "-qm", "base")
                base = git("rev-parse", "HEAD").stdout.strip()
                for branch, (name, text) in (("one", first), ("two", second)):
                    git("checkout", "-q", "-b", branch, base)
                    (repo / "upgrading.d" / name).write_text(text)
                    git("add", "-A")
                    git("commit", "-qm", branch)
                git("checkout", "-q", "one")
                git("merge", "-q", "--no-edit", "two")  # must merge with no conflict
                files = {p.name: p.read_text() for p in (repo / "upgrading.d").glob("*.md")}
                results.append(uf.assemble((repo / "doc.md").read_text(), 3, files))
        self.assertEqual(results[0], results[1])
        self.assertIn("## 4. Alpha", results[0][0])


def tree(tmp, files):
    root = pathlib.Path(tmp)
    (root / "docs").mkdir()
    (root / "docs/UPGRADING-4.0.md").write_text(DOC)
    (root / "upgrading.d").mkdir()
    (root / "upgrading.d/.gitkeep").write_text("")
    (root / "upgrading.d/.frozen-max").write_text("3\n")
    for name, text in files.items():
        (root / "upgrading.d" / name).write_text(text)
    return root


def snapshot(root):
    return {str(p.relative_to(root)): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}


def run_main(root, *argv):
    old = uf.ROOT
    uf.ROOT = root
    try:
        import contextlib
        import io

        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = uf.main(list(argv))
        return code, out.getvalue(), err.getvalue()
    finally:
        uf.ROOT = old


class Lifecycle(unittest.TestCase):
    def test_dry_run_changes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = tree(tmp, {"3700.md": A, "3701.md": B})
            before = snapshot(root)
            code, out, _ = run_main(root, "assemble", "--dry-run")
            self.assertEqual(code, 0)
            self.assertIn("## 5. Beta", out)
            self.assertEqual(snapshot(root), before)

    def test_assemble_consumes_raises_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = tree(tmp, {"3700.md": A, "3701.md": B})
            self.assertEqual(run_main(root, "assemble")[0], 0)
            self.assertEqual(sorted(p.name for p in (root / "upgrading.d").iterdir()), [".frozen-max", ".gitkeep"])
            self.assertEqual((root / "upgrading.d/.frozen-max").read_text().strip(), "5")
            first = snapshot(root)
            self.assertIn(b"## 5. Beta", first["docs/UPGRADING-4.0.md"])
            self.assertEqual(run_main(root, "assemble")[0], 0)
            self.assertEqual(snapshot(root), first)
            self.assertEqual(run_main(root, "check")[0], 0)

    def test_the_next_fragment_numbers_after_the_release(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = tree(tmp, {"3700.md": A, "3701.md": B})
            run_main(root, "assemble")
            gamma = frag("Gamma", change="gamma", action="do gamma", marker="prints a notice", notice="gamma phrase")
            (root / "upgrading.d/3800.md").write_text(gamma)
            code, out, _ = run_main(root, "assemble", "--dry-run")
            self.assertEqual(code, 0)
            self.assertIn("| 6 | gamma | do gamma |", out)
            self.assertIn("## 6. Gamma\n\n**Startup:** prints a notice\n<!-- notice: gamma phrase -->", out)

    def test_check_names_a_malformed_fragment(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = tree(tmp, {"3700.md": frag("T", change="a | b")})
            code, _, err = run_main(root, "check")
            self.assertEqual(code, 1)
            self.assertIn("upgrading.d/3700.md", err)


FOLDED = DOC.replace("| 3 | Three | Do three |\n", "| 3 | Three | Do three |\n| 4 | alpha change | do alpha |\n").replace(
    uf.WALKTHROUGH, "## 4. Alpha\n\n**Startup:** prints a notice\n<!-- notice: alpha phrase -->\n\nBody.\n\n" + uf.WALKTHROUGH
)


class Deletions(unittest.TestCase):
    BASE = {"3700.md": A, "3701.md": B}

    def test_an_unrelated_change_passes(self):  # green control
        self.assertEqual(uf.check_deletions([("M", "src/x.rs")], DOC, self.BASE), [])

    def test_a_folded_deletion_passes(self):
        self.assertEqual(uf.check_deletions([("D", "upgrading.d/3700.md")], FOLDED, self.BASE), [])

    def test_a_fold_of_a_no_notice_fragment_needs_no_comment(self):
        doc = FOLDED.replace("| 4 | alpha change | do alpha |\n", "| 4 | alpha change | do alpha |\n| 5 | beta change | do beta |\n").replace(
            uf.WALKTHROUGH, "## 5. Beta\n\n**Startup:** no notice\n\nBody.\n\n" + uf.WALKTHROUGH
        )
        self.assertEqual(uf.check_deletions([("D", "upgrading.d/3701.md")], doc, self.BASE), [])

    def test_a_deletion_with_no_fold_is_refused(self):
        errors = uf.check_deletions([("D", "upgrading.d/3700.md")], DOC, self.BASE)
        self.assertTrue(any("upgrading.d/3700.md" in e for e in errors), errors)

    def test_each_fold_part_is_required(self):
        for missing, doc in (
            ("section", FOLDED.replace("## 4. Alpha", "## 4. Renamed")),
            ("row", FOLDED.replace("| 4 | alpha change | do alpha |\n", "")),
            ("notice", FOLDED.replace("<!-- notice: alpha phrase -->\n", "")),
        ):
            with self.subTest(missing=missing):
                errors = uf.check_deletions([("D", "upgrading.d/3700.md")], doc, self.BASE)
                self.assertTrue(any("upgrading.d/3700.md" in e for e in errors), errors)

    def test_a_fold_that_drops_the_body_is_refused(self):
        errors = uf.check_deletions([("D", "upgrading.d/3700.md")], FOLDED.replace("Body.\n\n" + uf.WALKTHROUGH, uf.WALKTHROUGH), self.BASE)
        self.assertTrue(any("upgrading.d/3700.md" in e and "section" in e for e in errors), errors)

    def test_two_deleted_one_folded_names_the_other(self):
        errors = uf.check_deletions([("D", "upgrading.d/3700.md"), ("D", "upgrading.d/3701.md")], FOLDED, self.BASE)
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("upgrading.d/3701.md", errors[0])



class Ceiling(unittest.TestCase):
    def test_unchanged_or_cutover_passes(self):  # green controls
        self.assertEqual(uf.check_ceiling(173, 173, set()), [])
        self.assertEqual(uf.check_ceiling(None, 175, set()), [])

    def test_a_rise_held_by_folded_fragments_passes(self):
        self.assertEqual(uf.check_ceiling(173, 175, {174, 175}), [])

    def test_a_rise_beside_a_hand_numbered_item_is_refused(self):
        errors = uf.check_ceiling(173, 174, set())
        self.assertTrue(any("173" in e and "174" in e and "upgrading.d/<pr>.md" in e for e in errors), errors)

    def test_a_fold_into_an_old_gap_does_not_cover_a_new_number(self):
        # The fragment landed on gap number 2; the new 174 is hand-numbered.
        errors = uf.check_ceiling(173, 174, {2})
        self.assertTrue(any("[174]" in e for e in errors), errors)

    def test_folded_numbers_come_from_the_guide(self):
        self.assertEqual(uf.folded_numbers([("D", "upgrading.d/3700.md")], FOLDED, Deletions.BASE), {4})
        self.assertEqual(uf.folded_numbers([("M", "upgrading.d/3700.md")], FOLDED, Deletions.BASE), set())


class CeilingFromBase(unittest.TestCase):
    """MIK-8214: with --base, the ceiling comes from the base. A PR changes it
    only on the release-preparation path: raised onto numbers its folded
    fragments hold."""

    def test_missing_at_head_passes_against_the_base(self):
        self.assertEqual(uf.ceiling_against_base(175, None, set()), (175, []))

    def test_unchanged_at_head_passes(self):  # green control
        self.assertEqual(uf.ceiling_against_base(175, 175, set()), (175, []))

    def test_raised_at_head_without_a_fold_is_refused(self):
        ceiling, errors = uf.ceiling_against_base(175, 176, set())
        self.assertEqual(ceiling, 175)
        self.assertTrue(any("175" in e and "176" in e for e in errors), errors)

    def test_lowered_at_head_is_refused(self):
        ceiling, errors = uf.ceiling_against_base(175, 174, set())
        self.assertEqual(ceiling, 175)
        self.assertTrue(any("174" in e for e in errors), errors)

    def test_the_release_fold_raises_it(self):
        self.assertEqual(uf.ceiling_against_base(175, 177, {176, 177}), (177, []))

    def test_a_head_branched_before_the_ceiling_existed_passes(self):
        """The #3631 shape: the PR head has no upgrading.d/ at all; the
        checkout (the merge with the base) and the base both do."""
        with tempfile.TemporaryDirectory() as tmp:
            repo = pathlib.Path(tmp)
            git = lambda *a: subprocess.run(["git", *a], cwd=repo, check=True, capture_output=True, text=True).stdout.strip()
            git("init", "-q")
            git("config", "user.email", "t@t")
            git("config", "user.name", "t")
            (repo / "docs").mkdir()
            (repo / "docs/UPGRADING-4.0.md").write_text(DOC)
            git("add", "-A")
            git("commit", "-qm", "before the ceiling")
            head = git("rev-parse", "HEAD")
            (repo / "upgrading.d").mkdir()
            (repo / "upgrading.d/.frozen-max").write_text("3\n")
            (repo / "upgrading.d/.gitkeep").write_text("")
            git("add", "-A")
            git("commit", "-qm", "the ceiling lands on the base")
            base = git("rev-parse", "HEAD")
            try:
                code, _, err = run_main(repo, "check", "--base", base, "--head", head)
            except subprocess.CalledProcessError as crash:
                self.fail(f"check crashed reading the PR head instead of judging it against the base: {crash}")
        self.assertEqual(code, 0, err)


    def test_a_stale_head_cannot_slip_in_a_numbered_item(self):
        """A head without the ceiling that adds item 4 by hand: the merged
        checkout is held to the base ceiling (3), so item 4 is refused."""
        with tempfile.TemporaryDirectory() as tmp:
            repo = pathlib.Path(tmp)
            git = lambda *a: subprocess.run(["git", *a], cwd=repo, check=True, capture_output=True, text=True).stdout.strip()
            git("init", "-q")
            git("config", "user.email", "t@t")
            git("config", "user.name", "t")
            (repo / "docs").mkdir()
            (repo / "docs/UPGRADING-4.0.md").write_text(DOC)
            git("add", "-A")
            git("commit", "-qm", "before the ceiling")
            git("branch", "-q", "stale")
            (repo / "upgrading.d").mkdir()
            (repo / "upgrading.d/.frozen-max").write_text("3\n")
            git("add", "-A")
            git("commit", "-qm", "the ceiling lands on the base")
            base = git("rev-parse", "HEAD")
            git("checkout", "-q", "stale")
            numbered = DOC.replace("| 3 | Three | Do three |\n", "| 3 | Three | Do three |\n| 4 | Four | Do four |\n").replace(
                uf.WALKTHROUGH, "## 4. Four\n\n**Startup:** no notice\n\nBody.\n\n" + uf.WALKTHROUGH
            )
            (repo / "docs/UPGRADING-4.0.md").write_text(numbered)
            git("commit", "-qam", "a hand-numbered item")
            head = git("rev-parse", "HEAD")
            git("checkout", "-q", base)
            git("merge", "-q", "--no-edit", head)  # the checkout CI judges
            code, _, err = run_main(repo, "check", "--base", base, "--head", head)
        self.assertEqual(code, 1, err)
        self.assertIn("item 4", err)

class Wiring(unittest.TestCase):
    """The CI step that re-runs the guide checks on the assembled guide: if it
    were dropped or pointed at no test, a fragment that breaks a check would
    pass its PR and fail only at release."""

    def test_the_assembled_guide_step_runs_both_targets(self):
        ci = (uf.ROOT / ".github/workflows/ci.yml").read_text()
        step = ci[ci.index("UPGRADING checks on the assembled guide") :]
        step = step[: step.index("\n      - ") if "\n      - " in step else len(step)]
        for needle in (
            "upgrading_fragments.py assemble --dry-run",
            "UPGRADING_DOC=",
            "--test upgrading_summary_rows",
            "--bin mcp-gateway upgrade_notice_tests",
            "running [1-9]",
        ):
            self.assertIn(needle, step)
        release = ci[ci.index("release-script-tests:") :]
        self.assertIn("upgrading_fragments.py check", release)
        changelog = (uf.ROOT / ".github/workflows/changelog.yml").read_text()
        self.assertIn('upgrading_fragments.py check --base "$BASE_SHA" --head "$HEAD_SHA"', changelog)

if __name__ == "__main__":
    unittest.main()

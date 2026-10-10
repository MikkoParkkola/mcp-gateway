# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""critical_function_coverage.py grades each Critical function on its own lines.

A fixture crate with two same-named functions (the second picked by
occurrence), a fully covered one, one below the floor, one compiled out
(no DA records) and one that no longer exists.
"""

import contextlib
import importlib.util
import io
import pathlib
import re
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("cfc", HERE / "critical_function_coverage.py")
cfc = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cfc)

SOURCE = """\
fn guard(x: u8) -> bool {
    let s = "}";
    x > 1
}

#[cfg(unix)]
fn check(x: u8) -> bool {
    if x == 0 {
        return false;
    }
    true
}

#[cfg(windows)]
fn check(x: u8) -> bool {
    x != 0
}

fn helper() {}
"""

# guard 1-4 all hit; unix check 7-12: line 9 never hit; windows check absent.
LCOV = """\
SF:/build/repo/src/lib.rs
DA:1,3
DA:2,3
DA:3,3
DA:4,3
DA:7,2
DA:8,2
DA:9,0
DA:11,2
DA:12,2
DA:19,1
end_of_record
"""

HEADER = "# fixture\npath\tfn\toccurrence\ttier\tcategory\tqualified\treason\n"


class CriticalFunctionCoverage(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        root = pathlib.Path(self.dir.name)
        (root / "src").mkdir()
        (root / "src/lib.rs").write_text(SOURCE)
        self.lcov = root / "cov.lcov"
        self.lcov.write_text(LCOV)
        self.root = root

    def tearDown(self):
        self.dir.cleanup()

    def run_rows(self, rows, lcovs=None):
        inventory = self.root / "inv.tsv"
        inventory.write_text(HEADER + "".join(r + "\n" for r in rows))
        args = ["--inventory", str(inventory), "--root", str(self.root)]
        for lcov in lcovs or [self.lcov]:
            args += ["--lcov", str(lcov)]
        return cfc.main(args)

    def statuses(self, rows):
        inventory = self.root / "inv.tsv"
        inventory.write_text(HEADER + "".join(r + "\n" for r in rows))
        return [r[0] for r in cfc.grade(self.root, inventory, [self.lcov])]

    def test_a_fully_covered_function_passes_despite_a_brace_in_a_string(self):
        row = "src/lib.rs\tguard\t1\tcritical\td\tguard\tr"
        self.assertEqual(self.statuses([row]), ["ok"])
        self.assertEqual(self.run_rows([row]), 0)

    def test_one_missed_line_of_five_is_below_the_floor(self):
        row = "src/lib.rs\tcheck\t1\tcritical\td\tcheck\tr"
        self.assertEqual(self.statuses([row]), ["BELOW"])
        self.assertEqual(self.run_rows([row]), 1)

    def test_a_variant_no_report_measured_fails(self):
        row = "src/lib.rs\tcheck\t2\tcritical\td\tcheck\tr"
        self.assertEqual(self.statuses([row]), ["UNMEASURED"])
        self.assertEqual(self.run_rows([row]), 1)

    def test_the_other_platforms_report_grades_its_variant(self):
        # The Windows run's report measures lines 15-17; the union passes.
        windows = self.root / "windows.lcov"
        windows.write_text("SF:C:\\build\\repo\\src\\lib.rs\nDA:15,1\nDA:16,1\nDA:17,1\nend_of_record\n")
        row = "src/lib.rs\tcheck\t2\tcritical\td\tcheck\tr"
        self.assertEqual(self.run_rows([row], lcovs=[self.lcov, windows]), 0)

    def test_a_missing_report_is_named_and_is_not_a_graded_fail(self):
        # MIK-8265: a run whose Windows job uploaded no report. The grade is
        # refused, naming the input, with its own exit status; it never prints
        # a row count that would read as a graded FAIL, and never a traceback.
        missing = self.root / "coverage-windows" / "windows.lcov"
        inventory = self.root / "inv.tsv"
        inventory.write_text(HEADER + "src/lib.rs\tcheck\t2\tcritical\td\tcheck\tr\n")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cfc.main(["--inventory", str(inventory), "--root", str(self.root),
                             "--lcov", str(self.lcov), "--lcov", str(missing)])
        self.assertEqual(code, cfc.INPUT_MISSING)
        self.assertNotIn(code, (0, 1))
        self.assertIn(f"input missing: {missing}", out.getvalue())
        self.assertNotIn("critical rows failing", out.getvalue())

    def test_an_empty_or_unreadable_report_counts_as_missing(self):
        # An empty windows.lcov would otherwise grade as Linux alone (MIK-8265).
        empty = self.root / "empty.lcov"
        empty.write_text("")
        folder = self.root / "a-directory.lcov"
        folder.mkdir()
        for bad in (empty, folder):
            with self.subTest(bad=bad.name):
                with self.assertRaises(cfc.MissingInput):
                    cfc.read_lcov([self.lcov, bad], self.root)

    def test_an_unparseable_report_counts_as_missing(self):
        # A truncated or corrupt lcov: present, but a DA line is not numbers.
        corrupt = self.root / "corrupt.lcov"
        corrupt.write_text("SF:src/lib.rs\nDA:1\nDA:not,a-number\n")
        with self.assertRaises(cfc.MissingInput):
            cfc.read_lcov([self.lcov, corrupt], self.root)

    def test_the_wrapper_maps_the_same_status(self):
        # coverage_grade.sh turns a grader's INPUT_MISSING into NOT GRADED.
        wrapper = (pathlib.Path(__file__).resolve().parent / "coverage_grade.sh").read_text()
        self.assertIn(f"INPUT_MISSING={cfc.INPUT_MISSING}\n", wrapper)

    def test_the_report_reader_names_the_missing_report(self):
        missing = self.root / "absent.lcov"
        with self.assertRaises(cfc.MissingInput) as raised:
            cfc.read_lcov([self.lcov, missing], self.root)
        self.assertEqual(raised.exception.path, str(missing))

    def run_scoped(self, rows, scope):
        inventory = self.root / "inv.tsv"
        inventory.write_text(HEADER + "".join(r + "\n" for r in rows))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cfc.main(["--inventory", str(inventory), "--root", str(self.root),
                             "--lcov", str(self.lcov), "--scope", scope])
        return code, out.getvalue()

    def test_a_linux_only_grade_lists_an_unmeasured_variant_without_failing(self):
        # A pull request's grade has the Linux report alone (MIK-8217): a variant
        # compiled only elsewhere is listed and counted, and graded on the push.
        row = "src/lib.rs\tcheck\t2\tcritical\td\tcheck\tr"
        code, out = self.run_scoped([row], "linux-only")
        self.assertEqual(code, 0)
        self.assertIn("UNMEASURED-HERE\t-\t-\tsrc/lib.rs:check#2", out)
        self.assertIn("critical rows not measured in this scope: 1", out)
        self.assertIn("critical rows failing: 0", out)
        self.assertEqual(self.run_scoped([row], "all-platforms")[0], 1)

    def test_a_linux_only_grade_still_fails_a_row_below_or_missing(self):
        for row in ("src/lib.rs\tcheck\t1\tcritical\td\tcheck\tr",
                    "src/lib.rs\tgone\t1\tcritical\td\tgone\tr"):
            code, out = self.run_scoped([row], "linux-only")
            self.assertEqual(code, 1, row)
            self.assertIn("critical rows failing: 1", out)

    def test_a_checkout_under_a_directory_named_src_still_resolves(self):
        nested = self.root / "nested.lcov"
        nested.write_text(LCOV.replace("SF:/build/repo/src/lib.rs", "SF:/src/mcp-gateway/src/lib.rs"))
        row = "src/lib.rs\tguard\t1\tcritical\td\tguard\tr"
        self.assertEqual(self.run_rows([row], lcovs=[nested]), 0)

    def test_a_vanished_function_always_fails(self):
        row = "src/lib.rs\tgone\t1\tcritical\td\tgone\tr"
        self.assertEqual(self.statuses([row]), ["MISSING"])
        self.assertEqual(self.run_rows([row]), 1)

    def test_standard_rows_are_not_graded(self):
        row = "src/lib.rs\tcheck\t1\tstandard\tborderline\tcheck\tr"
        self.assertEqual(self.statuses([row]), [])
        self.assertEqual(self.run_rows([row]), 0)



TRACED = """\
fn logs(x: u8) -> bool {
    tracing::debug!(
        value = x,
        "seen"
    );
    x > 0
}
"""


class TracingArgumentLines(unittest.TestCase):
    """A reached macro's zero-count argument lines are excluded (and listed);
    an unreached macro's are not, so an untested log call still fails."""

    def grade(self, head_count):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            (root / "src/lib.rs").write_text(TRACED)
            lcov = root / "cov.lcov"
            lcov.write_text(
                f"SF:/repo/src/lib.rs\nDA:1,1\nDA:2,{head_count}\nDA:3,0\nDA:6,1\nDA:7,1\nend_of_record\n"
            )
            inventory = root / "inv.tsv"
            inventory.write_text(HEADER + "src/lib.rs\tlogs\t1\tcritical\td\tlogs\tr\n")
            return cfc.grade(root, inventory, [lcov])[0]

    def test_a_reached_macro_has_its_argument_lines_excluded_and_listed(self):
        result = self.grade(head_count=1)
        self.assertEqual(result[0], "ok")
        self.assertEqual((result[5], result[6]), (4, 4))
        self.assertEqual(result[8], ["src/lib.rs:3 (head 2=1)"])

    def test_logic_nested_in_an_argument_stays_graded(self):
        nested = """\
fn logs(x: u8) -> bool {
    tracing::debug!(
        value = if x > 1 {
            enforce(x)
        } else {
            0
        },
        "seen"
    );
    x > 0
}
"""
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            (root / "src/lib.rs").write_text(nested)
            lcov = root / "cov.lcov"
            lcov.write_text(
                "SF:/repo/src/lib.rs\nDA:1,1\nDA:2,1\nDA:3,1\nDA:4,0\nDA:10,1\nDA:11,1\nend_of_record\n"
            )
            inventory = root / "inv.tsv"
            inventory.write_text(HEADER + "src/lib.rs\tlogs\t1\tcritical\td\tlogs\tr\n")
            result = cfc.grade(root, inventory, [lcov])[0]
        self.assertEqual(result[4], [4], "the branch body inside the argument is still graded")
        self.assertEqual(result[8], [])

    def test_a_call_nested_in_an_argument_stays_graded(self):
        nested = """\
fn logs(x: u8) -> bool {
    tracing::debug!(
        value = Some(
            enforce(x)
        ),
        "seen"
    );
    x > 0
}
"""
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            (root / "src/lib.rs").write_text(nested)
            lcov = root / "cov.lcov"
            lcov.write_text(
                "SF:/repo/src/lib.rs\nDA:1,1\nDA:2,1\nDA:3,0\nDA:4,0\nDA:8,1\nDA:9,1\nend_of_record\n"
            )
            inventory = root / "inv.tsv"
            inventory.write_text(HEADER + "src/lib.rs\tlogs\t1\tcritical\td\tlogs\tr\n")
            result = cfc.grade(root, inventory, [lcov])[0]
        self.assertEqual(result[4], [3, 4], "an argument spanning lines is graded whole")
        self.assertEqual(result[8], [])

    def test_a_continued_expression_in_an_argument_stays_graded(self):
        continued = """\
fn logs(x: u8) -> bool {
    tracing::debug!(
        allowed = x > 1
            && enforce(x),
        count = x,
        "seen"
    );
    x > 0
}
"""
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            (root / "src/lib.rs").write_text(continued)
            lcov = root / "cov.lcov"
            lcov.write_text(
                "SF:/repo/src/lib.rs\nDA:1,1\nDA:2,1\nDA:3,0\nDA:4,0\nDA:5,0\nDA:8,1\nDA:9,1\nend_of_record\n"
            )
            inventory = root / "inv.tsv"
            inventory.write_text(HEADER + "src/lib.rs\tlogs\t1\tcritical\td\tlogs\tr\n")
            result = cfc.grade(root, inventory, [lcov])[0]
        self.assertEqual(result[4], [3, 4], "both halves of the continued field stay graded")
        self.assertEqual(result[8], ["src/lib.rs:5 (head 2=1)"], "the whole field line is excluded")

    def test_a_comment_between_fields_keeps_the_next_field_whole(self):
        commented = """\
fn logs(x: u8) -> bool {
    tracing::debug!(
        event = "seen",
        // the count is the field the instrument mis-attributes
        count = x,
        "seen"
    );
    x > 0
}
"""
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            (root / "src/lib.rs").write_text(commented)
            lcov = root / "cov.lcov"
            lcov.write_text(
                "SF:/repo/src/lib.rs\nDA:1,1\nDA:2,1\nDA:5,0\nDA:8,1\nDA:9,1\nend_of_record\n"
            )
            inventory = root / "inv.tsv"
            inventory.write_text(HEADER + "src/lib.rs\tlogs\t1\tcritical\td\tlogs\tr\n")
            result = cfc.grade(root, inventory, [lcov])[0]
        self.assertEqual(result[4], [])
        self.assertEqual(result[8], ["src/lib.rs:5 (head 2=1)"])

    def test_a_try_operator_in_a_field_stays_graded_and_a_debug_sigil_does_not(self):
        tried = """\
fn logs(x: u8) -> Result<bool, u8> {
    tracing::debug!(
        value = enforce(x)?,
        shown = ?x,
        "seen"
    );
    Ok(x > 0)
}
"""
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            (root / "src/lib.rs").write_text(tried)
            lcov = root / "cov.lcov"
            lcov.write_text(
                "SF:/repo/src/lib.rs\nDA:1,1\nDA:2,1\nDA:3,0\nDA:4,0\nDA:7,1\nDA:8,1\nend_of_record\n"
            )
            inventory = root / "inv.tsv"
            inventory.write_text(HEADER + "src/lib.rs\tlogs\t1\tcritical\td\tlogs\tr\n")
            result = cfc.grade(root, inventory, [lcov])[0]
        self.assertEqual(result[4], [3], "the early return through ? stays graded")
        self.assertEqual(result[8], ["src/lib.rs:4 (head 2=1)"])

    def test_an_unreached_macro_keeps_its_argument_lines(self):
        result = self.grade(head_count=0)
        self.assertEqual(result[0], "BELOW")
        self.assertEqual(result[4], [2, 3])
        self.assertEqual(result[8], [])


class SelectHeadLines(unittest.TestCase):
    """MIK-8327: a line that is only an optional `let <pattern> =` and a
    `[::]tokio::select! {` head holds no call, so its count is graded like any
    line, while nothing in the crate can rebind the name. Anything more on the
    line, a bare `select!`, or a crate that could rebind it keeps the MIK-7725
    rule: unverifiable."""

    ARMS = "        () = ready() => 1,\n    };\n"

    def grade(self, head, count, extra=None, cargo=None):
        source = "fn waits(x: u8) -> bool {\n" + head + self.ARMS + "    x > 0\n}\n"
        last = source.count("\n")
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            (root / "src/lib.rs").write_text(source)
            if extra is not None:
                (root / "src/other.rs").write_text(extra)
            if cargo is not None:
                (root / "Cargo.toml").write_text(cargo)
            counts = {1: 1, 2: count, 3: 1, 4: 1, last - 1: 1, last: 1}
            records = "".join(f"DA:{n},{c}\n" for n, c in sorted(counts.items()))
            lcov = root / "cov.lcov"
            lcov.write_text(f"SF:/repo/src/lib.rs\n{records}end_of_record\n")
            inventory = root / "inv.tsv"
            inventory.write_text(HEADER + "src/lib.rs\twaits\t1\tcritical\td\twaits\tr\n")
            return cfc.grade(root, inventory, [lcov])[0]

    def assert_hit(self, head, **crate):
        result = self.grade(head, 3, **crate)
        self.assertEqual(result[4], [], head)
        self.assertEqual(result[9], [], head)

    def assert_unverifiable(self, head, **crate):
        result = self.grade(head, 3, **crate)
        self.assertEqual(result[4], [2], (head, crate))
        self.assertEqual(result[9], ["src/lib.rs:2 (head count 3)"], (head, crate))

    def test_a_reached_bare_tokio_select_head_is_graded_by_its_count(self):
        self.assert_hit("    let unanswered = tokio::select! {\n")
        self.assert_hit("    tokio::select! {\n")
        self.assert_hit("    let (a, mut b) = ::tokio::select! {\n")
        self.assert_hit("    let _ = tokio::select! {\n", cargo='[dependencies]\ntokio = { version = "1" }\n')

    def test_a_call_on_the_select_head_is_still_unverifiable(self):
        self.assert_unverifiable("    let x = tokio::select! { foo() => 1,\n")
        self.assert_unverifiable("    tokio::select! { biased; () = ready() => 1,\n")
        self.assert_unverifiable("    let x = pick(tokio::select! {\n")

    def test_anything_else_on_the_select_head_keeps_it_unverifiable(self):
        self.assert_unverifiable("    tokio::select! { biased;\n")
        self.assert_unverifiable("    let x: u8 = tokio::select! {\n")
        self.assert_unverifiable("    tokio::select! { // why\n")
        self.assert_unverifiable("    other::select! {\n")
        self.assert_unverifiable("    let x = select! {\n")

    def test_a_crate_that_could_rebind_the_name_is_not_exempt(self):
        head = "    let x = tokio::select! {\n"
        for extra in (
            "mod tokio { pub use crate::logs as select; }\n",
            "use crate::logs as tokio;\n",
            "use crate::logs as select;\n",
            "macro_rules! select { ($($t:tt)*) => {} }\n",
        ):
            with self.subTest(extra=extra):
                self.assert_unverifiable(head, extra=extra)
        for cargo in (
            '[dependencies]\ntokio = { package = "other", version = "1" }\n',
            '[dependencies.tokio]\npackage = "other"\n',
        ):
            with self.subTest(cargo=cargo):
                self.assert_unverifiable(head, cargo=cargo)

    def test_an_unreached_select_head_is_still_missed(self):
        result = self.grade("    let unanswered = tokio::select! {\n", 0)
        self.assertEqual(result[0], "BELOW")
        self.assertIn(2, result[4])
        self.assertEqual(result[9], [], "a count-0 head is missed, not unverifiable")


class HeadLineCalls(unittest.TestCase):
    """A call on a tracing macro's head line rides that line's hit count, so the
    count cannot show the call ran: the line is graded as missed and listed as
    unverifiable, whatever its count (MIK-7725). It can fail spuriously; it can
    never pass an unrun call."""

    def grade(self, body, counts):
        source = "fn logs(x: u8) -> bool {\n" + body + "    x > 0\n}\n"
        last = source.count("\n")
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            (root / "src/lib.rs").write_text(source)
            records = "".join(f"DA:{n},{c}\n" for n, c in sorted({1: 1, **counts, last - 1: 1, last: 1}.items()))
            lcov = root / "cov.lcov"
            lcov.write_text(f"SF:/repo/src/lib.rs\n{records}end_of_record\n")
            inventory = root / "inv.tsv"
            inventory.write_text(HEADER + "src/lib.rs\tlogs\t1\tcritical\td\tlogs\tr\n")
            return cfc.grade(root, inventory, [lcov])[0]

    def test_a_reached_one_line_macro_with_a_call_is_missed_and_listed(self):
        result = self.grade('    debug!(url = %clean(x), "seen");\n', {2: 5})
        self.assertEqual(result[0], "BELOW")
        self.assertEqual(result[4], [2])
        self.assertEqual(result[9], ["src/lib.rs:2 (head count 5)"])

    def test_a_method_call_on_the_head_line_is_unverifiable(self):
        result = self.grade('    tracing::warn!(path = %p.display(), "seen");\n', {2: 1})
        self.assertEqual(result[4], [2])
        self.assertEqual(result[9], ["src/lib.rs:2 (head count 1)"])

    def test_a_nested_macro_on_the_head_line_is_unverifiable(self):
        result = self.grade('    info!(msg = %format!("{x}"), "seen");\n', {2: 1})
        self.assertEqual(result[4], [2])

    def test_a_multi_line_macro_with_a_call_on_its_head_line_is_unverifiable(self):
        body = '    debug!(url = %clean(x),\n        "seen"\n    );\n'
        result = self.grade(body, {2: 1, 3: 1})
        self.assertEqual(result[4], [2], "the head is unverifiable whatever its count")
        self.assertEqual(result[9], ["src/lib.rs:2 (head count 1)"])

    def test_an_unverifiable_head_still_excludes_its_reached_plain_field_lines(self):
        # The head's count still proves the macro was reached, so a plain field
        # on a later line that reads zero is excluded as before.
        body = '    debug!(url = %clean(x),\n        n = y,\n    );\n'
        result = self.grade(body, {2: 1, 3: 0})
        self.assertEqual(result[4], [2])
        self.assertEqual(result[8], ["src/lib.rs:3 (head 2=1)"])

    def test_shapes_a_call_list_would_miss_are_unverifiable(self):
        # A head line is verifiable only when every argument on it is plain, so
        # call shapes no pattern lists stay graded missed (a whitelist).
        shapes = [
            '    debug!(v = %clean::<Vec<u8>>(x), "seen");\n',
            '    debug!(v = %(clean)(x), "seen");\n',
            '    debug!(v = %x[0], "seen");\n',
            '    debug!(v = %x + y, "seen");\n',
            '    debug!(v = %|| x, "seen");\n',
            '    ::tracing::warn!(v = %clean(x), "seen");\n',
            '    tracing :: warn ! (v = %clean(x), "seen");\n',
            '    debug!{v = %x, "seen"};\n',
            '    debug![v = %x, "seen"];\n',
            '    debug!(r#"a "quoted" {}"#, clean(x));\n',
            "    debug!(c = ?'\"', v = %clean(x));\n",
            '    debug!(v = %x /* note */, "seen");\n',
            '    debug!("first"); debug!(v = %clean(x));\n',
            "    let q = '\"'; debug!(v = %clean(x), \"seen\");\n",
            '    let q = r"\\"; debug!(v = %clean(x), "seen");\n',
            '    /* " */ debug!(v = %clean(x), "seen");\n',
            '    debug!(v = %x, "seen"); // clean(x)\n',
            '    Err(e) => debug!(%e, "seen"),\n',
            '    span!(Level::INFO, "work");\n',
            '    debug!("a \\" b", clean(x));\n',
            '    debug!("a", clean(x), "b");\n',
            '    debug!(v = wrapper.value, "seen");\n',
            '    debug!(v = %self.name, "seen");\n',
            '    debug!(n = 1.max, "seen");\n',
            '    debug /* note */ !(v = %clean(x));\n',
        ]
        for body in shapes:
            with self.subTest(body=body.strip()):
                result = self.grade(body, {2: 1})
                self.assertEqual(result[4], [2])
                self.assertEqual(result[9], ["src/lib.rs:2 (head count 1)"])

    def test_any_way_to_run_a_tracing_macro_under_another_name_refuses_the_grade(self):
        # Fail closed: a renamed or wrapped level macro would hide from the
        # head-line rule, so its mere presence anywhere in src/ fails the grade.
        refused = [
            "use tracing::debug as d;\n",
            "use tracing::debug as r#emit;\n",
            "use tracing::{info, debug as d};\n",
            "use tracing::{\n    // logging\n    debug as d,\n};\n",
            "pub use ::tracing::warn as w;\n",
            "use tracing as t;\n",
        ]
        allowed = [
            "use tracing::{debug, info};\n",
            "use tracing::instrument::WithSubscriber as _;\n",
            "macro_rules! twice {\n    ($e:expr) => { $e + $e };\n}\n",
            "macro_rules! emit {\n    ($($t:tt)*) => { tracing::debug!($($t)*) };\n}\n",
        ]
        for header, expect in [(h, True) for h in refused] + [(h, False) for h in allowed]:
            with self.subTest(header=header):
                with tempfile.TemporaryDirectory() as tmp:
                    root = pathlib.Path(tmp)
                    (root / "src").mkdir()
                    (root / "src/lib.rs").write_text(header + "fn logs(x: u8) -> bool {\n    x > 0\n}\n")
                    (root / "src/other.rs").write_text("fn quiet() {}\n")
                    lines = header.count("\n")
                    lcov = root / "cov.lcov"
                    lcov.write_text(f"SF:/repo/src/lib.rs\nDA:{lines + 1},1\nDA:{lines + 2},1\nDA:{lines + 3},1\nend_of_record\n")
                    inventory = root / "inv.tsv"
                    inventory.write_text(HEADER + "src/lib.rs\tlogs\t1\tcritical\td\tlogs\tr\n")
                    statuses = [r[0] for r in cfc.grade(root, inventory, [lcov])]
                    out = io.StringIO()
                    with contextlib.redirect_stdout(out):
                        code = cfc.main(["--root", str(root), "--inventory", str(inventory), "--lcov", str(lcov)])
                self.assertEqual("INDIRECT" in statuses, expect)
                self.assertEqual(code, 1 if expect else 0)
                # MIK-8195: the count is inventory rows; a diagnostic is not one.
                self.assertIn("critical rows graded: 1\n", out.getvalue())

    def test_a_macro_that_is_not_known_safe_is_unverifiable(self):
        # A local macro_rules! (whatever its delimiters or body) or a macro
        # from a dependency may wrap tracing, so its line is unverifiable; a
        # known-safe macro's line is graded by its count.
        wrappers = [
            "macro_rules! hidden ( ($($t:tt)*) => { tracing::debug!($($t)*); } );\n",
            'macro_rules! hidden { ($($t:tt)*) => { let _ = "}}"; tracing::debug!($($t)*); } }\n',
            "macro_rules /* c */ ! hidden { ($($t:tt)*) => { tracing::debug!($($t)*) } }\n",
        ]
        for header in wrappers:
            with self.subTest(header=header):
                line = header.count("\n") + 2
                result = self.graded_with(header, "    hidden!(v = clean(x));\n")
                self.assertEqual(result[9], [f"src/lib.rs:{line} (head count 1)"])
        dependency = self.graded_with("", "    other::log!(v = clean(x));\n")
        self.assertEqual(dependency[4], [2])
        negation = self.graded_with("", "    if !(x > 1 || clean(x)) {}\n")
        self.assertEqual(negation[9], [], "a negation after a keyword is not a macro")
        safe = self.graded_with("", '    let s = format!("{}", clean(x));\n')
        self.assertEqual((safe[0], safe[9]), ("ok", []))
        shadowed = self.graded_with("macro_rules /* c */ ! format { ($($t:tt)*) => { tracing::debug!($($t)*) } }\n", '    let s = format!("{}", clean(x));\n')
        self.assertEqual(len(shadowed[9]), 1)

    def test_a_macro_split_across_lines_is_unverifiable(self):
        # MIK-7864: with the name and the delimiter on different lines, a scan
        # of one line at a time sees no call on either.
        for body in [
            "    hidden\n        !(clean(x));\n",
            "    hidden!\n        (clean(x));\n",
            "    debug\n        !(url = %clean(x));\n",
        ]:
            with self.subTest(body=body):
                result = self.grade(body, {2: 1, 3: 1})
                self.assertEqual(result[4], [2, 3])
                self.assertEqual(
                    result[9], ["src/lib.rs:2 (head count 1)", "src/lib.rs:3 (head count 1)"]
                )
        # Control: a known-safe macro split the same way is graded by its counts.
        safe = self.grade('    let s = format\n        !("{}", x);\n', {2: 1, 3: 1})
        self.assertEqual((safe[0], safe[9]), ("ok", []))

    def test_a_qualified_macro_is_not_a_safe_built_in_by_its_name(self):
        # MIK-7864: `other::format!` is some crate's macro, not `format!`.
        for line in [
            '    let s = other::format!("{}", clean(x));\n',
            '    let s = ::other::format!("{}", clean(x));\n',
            '    let v = my_crate::json!({ "a": clean(x) });\n',
            # After a single colon, as in a compact struct or map literal.
            '    let v = json!({"field":other::format!("{}", clean(x))});\n',
            '    let v = json!({"field":hidden!(clean(x))});\n',
        ]:
            with self.subTest(line=line):
                self.assertEqual(self.graded_with("", line)[4], [2])
        # Control: the standard crates' paths, and serde_json's json!, stay safe.
        for line in [
            '    let s = std::format!("{}", clean(x));\n',
            '    let s = ::core::format_args!("{}", clean(x));\n',
            '    let v = serde_json::json!({ "a": clean(x) });\n',
            '    telemetry_metrics::counter!("hits", "k" => clean(x)).increment(1);\n',
        ]:
            with self.subTest(line=line):
                result = self.graded_with("", line)
                self.assertEqual((result[0], result[9]), ("ok", []))

    def graded_with(self, header, body):
        source = header + "fn logs(x: u8) -> bool {\n" + body + "    x > 0\n}\n"
        first = header.count("\n") + 1
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            (root / "src/lib.rs").write_text(source)
            lcov = root / "cov.lcov"
            lcov.write_text("SF:/repo/src/lib.rs\n" + "".join(f"DA:{n},1\n" for n in range(first, first + 4)) + "end_of_record\n")
            inventory = root / "inv.tsv"
            inventory.write_text(HEADER + "src/lib.rs\tlogs\t1\tcritical\td\tlogs\tr\n")
            return cfc.grade(root, inventory, [lcov])[0]

    def test_the_cli_prints_the_unverifiable_line_and_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            (root / "src/lib.rs").write_text('fn logs(x: u8) -> bool {\n    debug!(v = %clean(x), "seen");\n    x > 0\n}\n')
            lcov = root / "cov.lcov"
            lcov.write_text("SF:/repo/src/lib.rs\nDA:1,1\nDA:2,1\nDA:3,1\nDA:4,1\nend_of_record\n")
            inventory = root / "inv.tsv"
            inventory.write_text(HEADER + "src/lib.rs\tlogs\t1\tcritical\td\tlogs\tr\n")
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = cfc.main(["--root", str(root), "--inventory", str(inventory), "--lcov", str(lcov)])
        self.assertEqual(code, 1)
        self.assertIn("unverifiable tracing head line src/lib.rs:2 (head count 1): graded missed", out.getvalue())

    def test_plain_fields_on_the_head_line_stay_covered(self):
        shapes = [
            '    debug!(url = %x, kind = ?k, n = 3, "seen {}", x);\n',
            '    tracing::warn!(%error, path = %shown_path, "task record unreadable");\n',
            '    ::tracing::info!(?reason, kind = Kind::Plain, n = 3u8, "seen")\n',
            '    error!(\n',
            '    debug!(url = %x,\n',
        ]
        for body in shapes:
            with self.subTest(body=body.strip()):
                result = self.grade(body, {2: 1})
                self.assertEqual(result[9], [])
                self.assertNotIn(2, result[4])

    def test_a_constant_target_on_the_head_line_stays_covered(self):
        shapes = [
            '    debug!(target: HTTP_TARGET, url = %x, "seen");\n',
            '    tracing::info!(target: crate::LOG_TARGET, n = 3, "seen")\n',
            '    warn!(target: "gateway.http", %error, "seen");\n',
            '    warn!(target: HTTP_TARGET,\n',
        ]
        for body in shapes:
            with self.subTest(body=body.strip()):
                result = self.grade(body, {2: 1})
                self.assertEqual(result[9], [])
                self.assertNotIn(2, result[4])

    def test_a_call_in_the_target_is_unverifiable(self):
        result = self.grade('    debug!(target: pick(x), "seen");\n', {2: 1})
        self.assertEqual(result[4], [2])
        self.assertEqual(result[9], ["src/lib.rs:2 (head count 1)"])

    def test_a_call_inside_the_message_literal_is_not_a_call(self):
        result = self.grade('    debug!("see clean(x) for {}", x);\n', {2: 1})
        self.assertEqual(result[0], "ok")
        self.assertEqual(result[9], [])

    def test_a_statement_before_the_macro_on_the_same_line_is_unverifiable(self):
        # The whole line must be a plain head line; anything sharing it, even
        # a statement before the macro, makes the line unverifiable.
        result = self.grade('    let y = f(x); debug!(y, "seen");\n', {2: 1})
        self.assertEqual(result[4], [2])
        self.assertEqual(result[9], ["src/lib.rs:2 (head count 1)"])

    def test_an_unreached_one_line_macro_with_a_call_is_missed_and_listed(self):
        result = self.grade('    debug!(url = %clean(x), "seen");\n', {2: 0})
        self.assertEqual(result[4], [2])
        self.assertEqual(result[9], ["src/lib.rs:2 (head count 0)"])


class PlainFieldWhitelist(unittest.TestCase):
    """Only a plain field line is ever excluded; every other shape stays graded."""

    ALLOWED = [
        'event = "",',
        "count = x,",
        "x,",
        "%self.name,",
        "?err,",
        "kind = a::B,",
        "n = -3,",
        "flag = true,",
    ]
    REFUSED = [
        "v = x.count_ones(),",
        "v = a + b,",
        "v = f()?,",
        "v = x?,",
        "v = !x,",
        "v = |x| x,",
        "v = m!(x),",
        "v = (x),",
        "v = x",
        "v = x && y,",
        "v = if a { b } else { c },",
    ]

    def test_the_table(self):
        for shape in self.ALLOWED:
            with self.subTest(allowed=shape):
                self.assertTrue(cfc.is_plain_field(shape))
        for shape in self.REFUSED:
            with self.subTest(refused=shape):
                self.assertFalse(cfc.is_plain_field(shape))


class RealTracingFixture(unittest.TestCase):
    """MIK-7731: the attribution rules against a real llvm-cov report, not
    synthetic DA records. scripts/release/fixtures/tracing_attribution holds a
    crate with the gateway's tracing version and `log` feature, its lcov from
    `cargo llvm-cov` and the toolchain that produced it (toolchain.txt)."""

    ROOT = HERE / "fixtures" / "tracing_attribution"

    def grade(self):
        with tempfile.TemporaryDirectory() as tmp:
            inventory = pathlib.Path(tmp) / "inv.tsv"
            inventory.write_text(HEADER + "".join(
                f"src/lib.rs\t{name}\t1\tcritical\td\t{name}\tr\n"
                for name in ("plain_fields", "head_call", "unreached")))
            results = cfc.grade(self.ROOT, inventory, [self.ROOT / "fixture.lcov"])
        return {r[1]["fn"]: r for r in results}

    def test_a_head_line_count_does_not_show_its_call_ran(self):
        # The report itself: the head line of `head_call` was reached, and
        # `label`, the call on that line, never ran (no subscriber, so tracing
        # never evaluated the field). The rule that grades such a line as
        # missed is what keeps that call from counting as covered.
        hits = cfc.read_lcov([self.ROOT / "fixture.lcov"], self.ROOT)["src/lib.rs"]
        self.assertEqual(hits[25], 1, "the head line was reached")
        self.assertEqual([hits[n] for n in (7, 8, 9)], [0, 0, 0], "label never ran")
        result = self.grade()["head_call"]
        self.assertEqual(result[0], "BELOW")
        self.assertEqual(result[4], [25])
        self.assertEqual(result[9], ["src/lib.rs:25 (head count 1)"])

    def test_a_reached_plain_field_macro_is_fully_covered(self):
        # This toolchain emits no record at all for the plain-field argument
        # lines (17, 18), so the plain-field rule has nothing to exclude: it is
        # inert here, and it can only ever drop a zero-count plain field of a
        # reached macro, never pass an unrun line.
        hits = cfc.read_lcov([self.ROOT / "fixture.lcov"], self.ROOT)["src/lib.rs"]
        self.assertNotIn(17, hits)
        self.assertNotIn(18, hits)
        result = self.grade()["plain_fields"]
        self.assertEqual((result[0], result[4], result[8]), ("ok", [], []))

    def test_an_unreached_macro_is_still_missed(self):
        result = self.grade()["unreached"]
        self.assertEqual(result[0], "BELOW")
        self.assertIn(33, result[4], "the unreached macro's head is missed")
        self.assertEqual(result[5], 0)


class InventoryResolves(unittest.TestCase):
    """Every row of the real inventory names a function that exists.

    Code moves: a refactor that relocates an enforcing function must move its
    row too, or the release grade would report it MISSING.
    """

    def test_every_inventory_row_resolves_in_the_tree(self):
        root = HERE.parent.parent
        rows = cfc.read_inventory(root / "docs/release/v4.0.0-critical-functions.tsv")
        self.assertTrue(rows)
        unresolved = []
        for row in rows:
            source = root / row["path"]
            lines = source.read_text().splitlines() if source.exists() else []
            if cfc.fn_line(lines, row["fn"], int(row["occurrence"])) is None:
                unresolved.append(f"{row['path']}:{row['fn']}#{row['occurrence']}")
        self.assertEqual(unresolved, [], "move these rows to the file that now defines them")

    def test_the_doc_states_no_critical_count_of_its_own(self):
        # MIK-8195: the grader prints the count from the inventory; a copy in
        # the doc went stale with each wave and conflicted every wave's merge.
        doc = (HERE.parent.parent / "docs/release/v4.0.0-critical-path-coverage.md").read_text()
        self.assertIsNone(re.search(r"\d+ rows are\s+Critical", doc), "the count lives in the grader")
        self.assertIn("critical rows graded", doc)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Rows for test-module-path.py: the libtest module path of a test file.

A Spark row run filtered by a test file's name, where a `#[path]` declaration
or a parent module mounts the file under another name, matches nothing and
wastes a build slot. Each row is a synthetic tree; no compile.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

SCRIPT = Path(__file__).resolve().parent / "test-module-path.py"


def load(root: Path):
    spec = importlib.util.spec_from_file_location("test_module_path", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.guard.ROOT = root
    return module


def tree(root: Path, files: dict[str, str]) -> None:
    for rel, body in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")


# Tonight's shape: relay_catalogue.rs is mounted as idempotency_caller_scope.
RENAMED = {
    "src/lib.rs": "pub mod gateway;\n",
    "src/gateway/mod.rs": "pub mod router;\n",
    "src/gateway/router.rs": '#[cfg(test)]\n#[path = "relay_catalogue.rs"]\nmod idempotency_caller_scope;\n',
    "src/gateway/relay_catalogue.rs": "#[test]\nfn a_row() {}\n",
}


class ModulePaths(unittest.TestCase):
    def paths(self, files: dict[str, str], target: str) -> list[str]:
        with TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            tree(root, files)
            return load(root).module_paths(root / target)

    def test_a_plain_mod_chain(self):
        files = {"src/lib.rs": "mod a;\n", "src/a.rs": "mod b;\n", "src/a/b.rs": ""}
        self.assertEqual(self.paths(files, "src/a/b.rs"), ["a::b"])

    def test_a_mod_rs_chain(self):
        files = {"src/lib.rs": "mod a;\n", "src/a/mod.rs": "mod b;\n", "src/a/b/mod.rs": ""}
        self.assertEqual(self.paths(files, "src/a/b/mod.rs"), ["a::b"])

    def test_an_inline_mod_names_the_file_under_it(self):
        files = {"src/lib.rs": "mod a {\n    mod b;\n}\n", "src/a/b.rs": ""}
        self.assertEqual(self.paths(files, "src/a/b.rs"), ["a::b"])

    def test_a_path_renamed_file_takes_the_declared_name(self):
        self.assertEqual(
            self.paths(RENAMED, "src/gateway/relay_catalogue.rs"),
            ["gateway::router::idempotency_caller_scope"],
        )

    def test_a_file_declared_from_a_sibling(self):
        files = {
            "src/lib.rs": "mod a;\n",
            "src/a.rs": '#[cfg(test)]\n#[path = "a_tests.rs"]\nmod tests;\n',
            "src/a_tests.rs": "",
        }
        self.assertEqual(self.paths(files, "src/a_tests.rs"), ["a::tests"])

    def test_a_path_child_resolves_from_its_own_directory(self):
        # A top-level #[path] resolves against the declaring file's directory (src/x.rs), and
        # the file it loads owns that directory: its plain `mod c;` is src/c.rs, not src/x/c.rs.
        files = {
            "src/lib.rs": "mod a;\n",
            "src/a.rs": '#[path = "x.rs"]\nmod renamed;\n',
            "src/x.rs": "mod c;\n",
            "src/c.rs": "",
        }
        self.assertEqual(self.paths(files, "src/c.rs"), ["a::renamed::c"])

    def test_a_file_mounted_twice_prints_both(self):
        files = {"src/lib.rs": 'mod a;\n#[path = "a.rs"]\nmod b;\n', "src/a.rs": ""}
        self.assertEqual(self.paths(files, "src/a.rs"), ["a", "b"])

    def test_a_path_inside_an_inline_mod_resolves_under_it(self):
        # Inside an inline module, #[path] resolves against the module directory plus that module.
        files = {"src/lib.rs": 'mod a {\n    #[path = "x.rs"]\n    mod y;\n}\n', "src/a/x.rs": ""}
        self.assertEqual(self.paths(files, "src/a/x.rs"), ["a::y"])

    def test_the_library_path_wins_over_a_binary_root(self):
        files = {"src/lib.rs": "mod a;\n", "src/a.rs": "", "src/bin/tool.rs": '#[path = "../a.rs"]\nmod a;\n'}
        self.assertEqual(self.paths(files, "src/a.rs"), ["a"])

    def test_a_self_loading_path_cycle_ends(self):
        # A cfg-disabled `#[path]` back to the file itself: rustc never loads it, the walk must stop.
        files = {"src/lib.rs": "mod a;\n", "src/a.rs": '#[cfg(any())]\n#[path = "a.rs"]\nmod again;\n'}
        self.assertEqual(self.paths(files, "src/a.rs"), ["a"])

    def test_a_raw_keyword_module_keeps_r_hash(self):
        # The scanner reads `r#override` as `override`; rustc prints a keyword name raw.
        files = {"src/lib.rs": "pub mod r#override;\n", "src/override.rs": ""}
        self.assertEqual(self.paths(files, "src/override.rs"), ["r#override"])

    def test_a_raw_non_keyword_module_prints_bare(self):
        files = {"src/lib.rs": "mod r#plain;\n", "src/plain.rs": ""}
        self.assertEqual(self.paths(files, "src/plain.rs"), ["plain"])

    def test_the_crate_root_has_the_empty_path(self):
        self.assertEqual(self.paths({"src/lib.rs": ""}, "src/lib.rs"), [""])


class Cli(unittest.TestCase):
    def run_main(self, files: dict[str, str], argv: list[str]) -> tuple[int, str, str]:
        with TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            tree(root, files)
            module = load(root)
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = module.main([str(root / a) if a.endswith(".rs") else a for a in argv])
            return code, out.getvalue(), err.getvalue()

    def test_prints_the_path(self):
        code, out, _ = self.run_main(RENAMED, ["src/gateway/relay_catalogue.rs"])
        self.assertEqual((code, out), (0, "gateway::router::idempotency_caller_scope\n"))

    def test_an_orphan_exits_non_zero_naming_it(self):
        files = {"src/lib.rs": "", "src/lost_tests.rs": ""}
        code, out, err = self.run_main(files, ["src/lost_tests.rs"])
        self.assertEqual((code, out), (1, ""))
        self.assertIn("src/lost_tests.rs", err)

    def test_a_file_reached_only_from_a_test_target_names_its_root(self):
        # tests/common/mod.rs, not tests/common.rs: cargo builds every tests/*.rs as its own crate.
        files = {"src/lib.rs": "", "tests/it.rs": "mod common;\n", "tests/common/mod.rs": ""}
        code, out, _ = self.run_main(files, ["tests/common/mod.rs"])
        self.assertEqual((code, out), (0, "tests/it.rs: common\n"))


class CheckFilter(unittest.TestCase):
    def warnings(self, names: list[str]) -> list[str]:
        with TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            tree(root, RENAMED)
            return load(root).check_filter(names)

    def test_tonights_stem_filter_warns_naming_the_real_path(self):
        found = self.warnings(["relay_catalogue"])
        self.assertEqual(len(found), 1, found)
        self.assertIn("src/gateway/relay_catalogue.rs", found[0])
        self.assertIn("gateway::router::idempotency_caller_scope", found[0])

    def test_a_stem_inside_a_longer_filter_warns(self):
        self.assertEqual(len(self.warnings(["relay_catalogue::a_row"])), 1)

    def test_the_real_module_path_is_silent(self):
        self.assertEqual(self.warnings(["gateway::router::idempotency_caller_scope::a_row"]), [])

    def test_a_stem_that_is_also_its_module_name_is_silent(self):
        self.assertEqual(self.warnings(["router", "gateway::router"]), [])

    def test_a_stem_that_is_another_modules_name_is_silent(self):
        # relay_catalogue is also a (file-backed) module elsewhere, so a filter on it can match.
        with TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            extra = {"src/lib.rs": "pub mod gateway;\nmod other;\n", "src/other.rs": "mod relay_catalogue;\n",
                     "src/other/relay_catalogue.rs": ""}
            tree(root, {**RENAMED, **extra})
            self.assertEqual(load(root).check_filter(["relay_catalogue"]), [])

    def test_a_name_matching_no_file_is_silent(self):
        self.assertEqual(self.warnings(["a_row", "mod", "lib"]), [])

    def test_the_cli_warns_and_still_exits_zero(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            tree(root, RENAMED)
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                code = load(root).main(["--check-filter", "relay_catalogue"])
            self.assertEqual(code, 0)
            self.assertIn("idempotency_caller_scope", err.getvalue())


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Tests for check_macos_exclusions.py: each case is a small tree with one
Rust file and the exclusion list, and the check must report what it states."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("mac", HERE / "check_macos_exclusions.py")
mac = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mac)

HEADER = "path\titem\tportable\treason\n"


class CheckMacosExclusions(unittest.TestCase):
    def tree(
        self, rust: str, rows: str = "", path: str = "src/x_tests.rs", skips: str = ""
    ) -> list[str]:
        root = Path(self.dir.name)
        (root / mac.WORKFLOW).parent.mkdir(parents=True, exist_ok=True)
        (root / mac.WORKFLOW).write_text(
            f"jobs:\n  macos-check:\n    steps:\n      - run: cargo test{skips}\n"
            "  test:\n    steps:\n      - run: cargo test -- --skip linux_only\n"
        )
        (root / path).parent.mkdir(parents=True, exist_ok=True)
        (root / path).write_text(rust)
        (root / mac.LIST).parent.mkdir(parents=True, exist_ok=True)
        (root / mac.LIST).write_text(HEADER + rows)
        return mac.problems(root)

    def setUp(self) -> None:
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)

    def test_an_unlisted_linux_only_test_fails(self) -> None:
        found = self.tree('#[cfg(target_os = "linux")]\n#[test]\nfn probe() {}\n')
        self.assertEqual(found, ["not run on macOS and not listed: src/x_tests.rs probe"])

    def test_a_listed_test_with_a_reason_passes(self) -> None:
        found = self.tree(
            '/// doc\n#[cfg(target_os = "linux")]\n#[tokio::test]\nasync fn probe() {}\n',
            "src/x_tests.rs\tprobe\tinherent\tuses /dev/full\n",
        )
        self.assertEqual(found, [])

    def test_every_gate_spelling_is_seen(self) -> None:
        rust = (
            '#[test]\n#[cfg_attr(target_os = "macos", ignore = "flaky")]\nfn a() {}\n'
            '#[cfg(not(target_os = "macos"))]\n#[test]\nfn b() {}\n'
            '#[cfg(all(unix, not(target_os = "macos")))]\n#[test]\nfn c() {}\n'
            '#[cfg(target_os = "linux")]\nmod d;\n'
            '#[cfg(all(test, target_os = "linux"))]\n#[test]\nfn e() {}\n'
        )
        self.assertEqual(len(self.tree(rust)), 5)

    def test_a_macos_job_skip_needs_a_row_and_a_row_needs_the_skip(self) -> None:
        # The Tests job's own skip is not the macOS job's and needs no row.
        found = self.tree(
            "fn nothing() {}\n",
            ".github/workflows/ci.yml\tgone_skip\tn/a\tr\n",
            skips=" -- --skip burst",
        )
        self.assertEqual(
            found,
            [
                "not run on macOS and not listed: .github/workflows/ci.yml burst",
                "stale row, nothing matches: .github/workflows/ci.yml gone_skip",
            ],
        )

    def test_a_row_without_a_reason_and_a_stale_row_fail(self) -> None:
        found = self.tree("fn nothing() {}\n", "src/x_tests.rs\tgone\tinherent\tr\nsrc/y.rs\tz\tno\t\n")
        self.assertEqual(
            found,
            [
                "row without a reason: 'src/y.rs\\tz\\tno\\t'",
                "stale row, nothing matches: src/x_tests.rs gone",
            ],
        )

    def test_a_test_gated_module_in_a_production_file_is_seen(self) -> None:
        rust = '#[cfg(all(test, target_os = "linux"))]\nmod e2e_tests;\n'
        self.assertEqual(
            self.tree(rust, path="src/reload/mod.rs"),
            ["not run on macOS and not listed: src/reload/mod.rs e2e_tests"],
        )

    def test_a_file_kept_off_apple_is_seen_as_a_whole(self) -> None:
        rust = '#![cfg(all(unix, not(target_vendor = "apple")))]\n#[test]\nfn a() {}\n'
        self.assertEqual(
            self.tree(rust, path="tests/events.rs"),
            ["not run on macOS and not listed: tests/events.rs *"],
        )

    def test_an_equals_skip_is_seen(self) -> None:
        found = self.tree("fn nothing() {}\n", skips=" -- --skip=burst")
        self.assertEqual(found, ["not run on macOS and not listed: .github/workflows/ci.yml burst"])

    def test_linux_only_production_code_is_not_a_test(self) -> None:
        rust = '#[cfg(target_os = "linux")]\nfn read_proc() {}\n#[cfg(target_os = "linux")]\nmod inotify;\n'
        self.assertEqual(self.tree(rust, path="src/watch.rs"), [])

    def test_the_linux_and_macos_gate_runs_on_macos(self) -> None:
        # MIK-8181: the exact real-watcher gate is on macOS; a gate that names
        # macOS but still requires Linux, or excludes Apple, stays off.
        rust = (
            '#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]\nmod e2e_tests;\n'
            '#[cfg(all(test, target_os = "linux", any(feature = "foo", target_os = "macos")))]\n'
            "mod linux_and_mac_tests;\n"
            '#[cfg(all(test, any(target_os = "linux", target_os = "macos"), '
            'not(target_vendor = "apple")))]\nmod apple_off_tests;\n'
        )
        self.assertEqual(
            self.tree(rust, path="src/reload/mod.rs"),
            [
                "not run on macOS and not listed: src/reload/mod.rs apple_off_tests",
                "not run on macOS and not listed: src/reload/mod.rs linux_and_mac_tests",
            ],
        )

    def test_the_release_tree_passes(self) -> None:
        self.assertEqual(mac.problems(HERE.parents[1]), [])


if __name__ == "__main__":
    unittest.main()

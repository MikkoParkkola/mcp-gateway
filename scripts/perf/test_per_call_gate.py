#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Tests for per_call_gate.py's verdict rules (MIK-8014): a row whose null-arm
budget is above the ceiling is VOID, a head-base difference above the budget
is OVER, anything else PASS; a run that cannot measure is VOID, never FAIL."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("gate", HERE / "per_call_gate.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def judge(budget, delta):
    with contextlib.redirect_stdout(io.StringIO()):
        return gate.judge(budget, delta)


class Judge(unittest.TestCase):
    def test_within_budget_passes(self):
        self.assertEqual(judge({"r": 900}, {"r": 900}), {"r": "PASS"})

    def test_over_budget_is_over(self):
        self.assertEqual(judge({"r": 900}, {"r": 901}), {"r": "OVER"})

    def test_a_faster_head_passes(self):
        self.assertEqual(judge({"r": 900}, {"r": -5000}), {"r": "PASS"})

    def test_a_budget_above_the_ceiling_is_void_even_when_within(self):
        budget = gate.CEILING_NS + 1
        self.assertEqual(judge({"r": budget}, {"r": 0}), {"r": "VOID"})

    def test_a_budget_at_the_ceiling_still_judges(self):
        budget = gate.CEILING_NS
        self.assertEqual(judge({"r": budget}, {"r": budget + 1}), {"r": "OVER"})

    def test_each_row_is_judged_on_its_own_budget(self):
        verdict = judge({"a": 100, "b": 5000}, {"a": 50, "b": 50})
        self.assertEqual(verdict, {"a": "PASS", "b": "VOID"})


def decide(*verdicts):
    with contextlib.redirect_stdout(io.StringIO()):
        return gate.decide(list(verdicts))


class Decide(unittest.TestCase):
    def test_over_twice_fails(self):
        self.assertEqual(decide({"r": "OVER"}, {"r": "OVER"}), 1)

    def test_over_once_then_pass_passes(self):
        self.assertEqual(decide({"r": "OVER"}, {"r": "PASS"}), 0)

    def test_a_void_confirmation_is_void_not_pass(self):
        self.assertEqual(decide({"r": "OVER"}, {"r": "VOID"}), 2)

    def test_a_void_row_voids_the_run(self):
        self.assertEqual(decide({"a": "PASS", "b": "VOID"}), 2)

    def test_all_pass_passes(self):
        self.assertEqual(decide({"a": "PASS", "b": "PASS"}), 0)


class Errors(unittest.TestCase):
    def test_a_failed_command_is_void_not_fail(self):
        with self.assertRaises(gate.Void) as raised:
            gate.sh(["sh", "-c", "echo broken >&2; exit 101"])
        self.assertIn("broken", str(raised.exception))

    def test_a_failed_repository_lookup_is_void_through_main(self):
        from unittest import mock

        def sh(cmd, cwd=None, env=None, timeout=None):
            raise gate.Void("not a git repository")

        argv = ["per_call_gate.py", "--base", "x", "--head", "y"]
        with mock.patch.object(gate, "sh", sh), mock.patch.object(gate.sys, "argv", argv), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(gate.main(), 2)

    def test_a_hung_command_is_void(self):
        with self.assertRaises(gate.Void):
            gate.sh(["sleep", "5"], timeout=0.2)


class Prebuilt(unittest.TestCase):
    """--measure-only measures only binaries whose manifest names the
    requested commits and whose bytes still match it."""

    def setUp(self):
        import os
        import tempfile

        self.dir = tempfile.TemporaryDirectory()
        self.binary = os.path.join(self.dir.name, "abc.bin")
        with open(self.binary, "wb") as f:
            f.write(b"built")
        # Explicit compiler identity: Python-only tests never run rustc -V.
        gate.write_manifest(
            self.binary, ["a" * 40], rustc_version="rustc 1.0.0", profile="release"
        )

    def tearDown(self):
        self.dir.cleanup()

    def verified(self, commits):
        return gate.verified(
            self.binary, commits, rustc_version="rustc 1.0.0", profile="release"
        )

    def test_matching_commits_are_accepted(self):
        self.assertEqual(self.verified(["a" * 40]), self.binary)

    def test_a_binary_built_from_another_commit_is_refused(self):
        with self.assertRaises(gate.Void) as raised:
            self.verified(["b" * 40])
        self.assertIn("was built from", str(raised.exception))

    def test_a_binary_changed_after_its_build_is_refused(self):
        with open(self.binary, "ab") as f:
            f.write(b"tampered")
        with self.assertRaises(gate.Void):
            self.verified(["a" * 40])

    def test_a_binary_without_a_manifest_is_refused(self):
        import os

        os.remove(self.binary + ".json")
        with self.assertRaises(gate.Void):
            self.verified(["a" * 40])

    def test_build_reuses_a_verified_binary_without_building(self):
        from unittest import mock

        with mock.patch.object(gate, "current_rustc", return_value="rustc 1.0.0"), \
                contextlib.redirect_stdout(io.StringIO()):
            # No repo and no cargo: a rebuild would fail.
            _, got = gate.build(None, "a" * 40, self.dir.name, "abc", ["a" * 40])
        self.assertEqual(got, self.binary)


class Measure(unittest.TestCase):
    """The whole decision flow over stubbed harness runs and host load."""

    def flow(self, head_ns, armed_ns, load=0.5, loads=None, sampler_fails=False):
        """measure() over the real run(), with the harness process stubbed:
        BASE prints 100 us on every row, HEAD `head_ns`, armed HEAD `armed_ns`.
        `loads` overrides the host load per reading (the last value repeats).
        With `sampler_fails`, getloadavg raises only off the main thread, so
        only the in-run sampler threads fail."""
        import threading
        import types
        from unittest import mock

        stages = gate.STAGES_FROM_HARNESS()
        self.sampler_failures = [0]

        def sh(cmd, cwd=None, env=None, timeout=None):
            armed = bool(env and env.get("PER_CALL_NEGATIVE_CONTROL"))
            ns = 100_000 if cmd[0] == "base" else (armed_ns if armed else head_ns)
            return "".join(f"PER_CALL_NS {row} {ns}\n" for row in stages)

        readings = iter(loads or [])
        last = [load]

        def getloadavg():
            if sampler_fails and threading.current_thread() is not threading.main_thread():
                self.sampler_failures[0] += 1
                raise OSError("load unavailable in sampler")
            last[0] = next(readings, last[0])
            return (last[0], last[0], last[0])

        gate.PEAK_LOAD[0] = 0.0
        a = types.SimpleNamespace(k=2, blocks=1)
        with mock.patch.object(gate, "sh", sh), \
                mock.patch.object(gate.os, "getloadavg", getloadavg), \
                contextlib.redirect_stdout(io.StringIO()):
            return gate.measure(a, gate.random.Random(1), ("base", "head"))

    def test_a_load_spike_mid_run_voids_though_the_end_is_quiet(self):
        spike = [0.5, gate.MAX_LOAD + 5, gate.MAX_LOAD + 5, 0.5]
        self.assertEqual(self.flow(100_000, 110_000, loads=spike), 2)

    def test_an_unchanged_head_passes(self):
        self.assertEqual(self.flow(100_000, 110_000), 0)

    def test_a_slower_head_fails_after_its_confirmation(self):
        self.assertEqual(self.flow(103_000, 113_000), 1)

    def test_a_control_that_does_not_move_voids_the_run(self):
        self.assertEqual(self.flow(100_000, 100_000), 2)

    def test_a_busy_host_voids_even_a_clean_result(self):
        self.assertEqual(self.flow(100_000, 110_000, load=gate.MAX_LOAD + 1), 2)

    def test_a_sampler_failure_voids_the_full_flow(self):
        # Rows and main-thread load are clean, so only the samplers' own
        # failure can void this: a failed observation is no observation.
        with self.assertRaises(gate.Void) as raised:
            self.flow(100_000, 110_000, sampler_fails=True)
        self.assertGreaterEqual(self.sampler_failures[0], 1)
        self.assertIn("sampler", str(raised.exception).lower())


class Overlay(unittest.TestCase):
    """F2: BASE gets only per_call_timing.rs, mounted by its mod line. The
    rest of tests/mod.rs and the shared helpers stay BASE's own."""

    def test_only_the_harness_file_is_overlaid(self):
        self.assertEqual(
            gate.HARNESS, ["src/gateway/server/tests/per_call_timing.rs"]
        )

    def mount(self, mod_rs):
        import os
        import tempfile

        tree = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(tree, ignore_errors=True))
        mod = os.path.join(tree, "src/gateway/server/tests/mod.rs")
        os.makedirs(os.path.dirname(mod))
        with open(mod, "w") as f:
            f.write(mod_rs)
        gate.ensure_harness_mounted(tree)
        with open(mod) as f:
            return f.read()

    def test_a_missing_mod_line_is_added(self):
        got = self.mount("mod other;\n")
        self.assertIn("mod other;\n", got)
        self.assertIn("mod per_call_timing;\n", got)

    def test_a_present_mod_line_is_not_duplicated(self):
        before = "mod other;\nmod per_call_timing;\n"
        self.assertEqual(self.mount(before), before)

    def test_a_pub_crate_mod_line_is_not_duplicated(self):
        before = "mod other;\npub(crate) mod per_call_timing;\n"
        self.assertEqual(self.mount(before), before)

    def test_an_attributed_mod_line_is_not_duplicated(self):
        before = "#[cfg(test)]\nmod per_call_timing;\nmod other;\n"
        self.assertEqual(self.mount(before), before)
        inline = "#[cfg(test)] mod per_call_timing;\nmod other;\n"
        self.assertEqual(self.mount(inline), inline)

    def test_adding_the_mod_line_preserves_every_existing_byte(self):
        before = "mod other;\n\n\n// a trailing comment\n"
        got = self.mount(before)
        self.assertTrue(got.startswith(before), repr(got))
        self.assertEqual(got, before + "mod per_call_timing;\n")

    def test_build_overlays_only_the_harness_onto_base(self):
        import os
        import tempfile
        import types
        from unittest import mock

        base_mod = b"mod invoke_argument_copies;\nmod signing_support;\n"
        base_files = {
            "src/gateway/server/tests/mod.rs": base_mod,
            "src/gateway/server/tests/invoke_argument_copies.rs": b"// BASE helper\n",
            "src/gateway/server/tests/signing_support.rs": b"// BASE support\n",
            "src/gateway/server/tests/unchanged.rs": b"// BASE other test\n",
            "src/lib.rs": b"// BASE lib\n",
        }
        head_harness = b"// HEAD per_call_timing\n"

        def fake_run(cmd, cwd=None, env=None, input=None, check=False, **kw):
            if cmd[:2] == ["git", "archive"]:
                return types.SimpleNamespace(returncode=0, stdout=b"tar-bytes")
            if cmd[0] == "tar":
                tree = cmd[cmd.index("-C") + 1]
                for rel, data in base_files.items():
                    path = os.path.join(tree, rel)
                    os.makedirs(os.path.dirname(path), exist_ok=True)
                    with open(path, "wb") as f:
                        f.write(data)
                return types.SimpleNamespace(returncode=0, stdout=b"")
            if cmd[:2] == ["git", "show"]:
                self.assertTrue(cmd[2].endswith(gate.HARNESS[0]), cmd)
                return types.SimpleNamespace(returncode=0, stdout=head_harness)
            raise AssertionError(f"unexpected command {cmd}")

        def fake_sh(cmd, cwd=None, env=None, timeout=None):
            exe = os.path.join(os.path.dirname(cwd), "mcp_gateway-deadbeef")
            with open(exe, "wb") as f:
                f.write(b"exe")
            return '{"executable":"' + exe + '"}\n'

        with tempfile.TemporaryDirectory() as work, \
                mock.patch.object(gate.subprocess, "run", fake_run), \
                mock.patch.object(gate, "sh", fake_sh), \
                mock.patch.object(gate, "current_rustc", return_value="rustc 1.0.0"), \
                contextlib.redirect_stdout(io.StringIO()):
            tree, binary = gate.build(
                "repo", "b" * 40, work, "basekey", ["b" * 40, "h" * 40],
                overlay_from="h" * 40,
            )
            self.assertTrue(os.path.exists(binary))
            after = {}
            for base, _dirs, names in os.walk(tree):
                for name in names:
                    path = os.path.join(base, name)
                    with open(path, "rb") as f:
                        after[os.path.relpath(path, tree)] = f.read()
        want = dict(base_files)
        want[gate.HARNESS[0]] = head_harness
        want[gate.TESTS_MOD] = base_mod + b"mod per_call_timing;\n"
        self.assertEqual(after, want)

    def test_a_missing_tests_mod_is_void(self):
        import tempfile

        with self.assertRaises(gate.Void):
            gate.ensure_harness_mounted(tempfile.mkdtemp())


class ManifestToolchain(unittest.TestCase):
    """F7: a cached binary built by another rustc or profile is stale."""

    def setUp(self):
        import os
        import tempfile

        self.dir = tempfile.TemporaryDirectory()
        self.binary = os.path.join(self.dir.name, "abc.bin")
        with open(self.binary, "wb") as f:
            f.write(b"built")
        gate.write_manifest(
            self.binary, ["a" * 40], rustc_version="rustc 1.0.0", profile="release"
        )

    def tearDown(self):
        self.dir.cleanup()

    def test_the_same_toolchain_and_profile_are_accepted(self):
        got = gate.verified(
            self.binary, ["a" * 40], rustc_version="rustc 1.0.0", profile="release"
        )
        self.assertEqual(got, self.binary)

    def test_a_different_rustc_is_stale(self):
        with self.assertRaises(gate.Void) as raised:
            gate.verified(
                self.binary, ["a" * 40], rustc_version="rustc 2.0.0", profile="release"
            )
        self.assertIn("stale", str(raised.exception))

    def test_a_different_profile_is_stale(self):
        with self.assertRaises(gate.Void) as raised:
            gate.verified(
                self.binary, ["a" * 40], rustc_version="rustc 1.0.0", profile="dev"
            )
        self.assertIn("stale", str(raised.exception))

    def test_a_manifest_without_toolchain_fields_is_stale(self):
        import json

        with open(self.binary + ".json") as f:
            manifest = json.load(f)
        del manifest["rustc_version"], manifest["profile"]
        with open(self.binary + ".json", "w") as f:
            json.dump(manifest, f)
        with self.assertRaises(gate.Void) as raised:
            gate.verified(
                self.binary, ["a" * 40], rustc_version="rustc 1.0.0", profile="release"
            )
        self.assertIn("stale", str(raised.exception))

    def rewrite_manifest(self, **changes):
        import json

        with open(self.binary + ".json") as f:
            manifest = json.load(f)
        for key, value in changes.items():
            if value is None:
                manifest.pop(key, None)
            else:
                manifest[key] = value
        with open(self.binary + ".json", "w") as f:
            json.dump(manifest, f)

    def test_a_manifest_without_a_compiler_is_refused(self):
        self.rewrite_manifest(rustc_version=None)
        with self.assertRaises(gate.Void) as raised:
            gate.verified(
                self.binary, ["a" * 40], rustc_version="rustc 1.0.0", profile="release"
            )
        self.assertIn("rustc", str(raised.exception))

    def test_a_manifest_with_an_empty_compiler_is_refused(self):
        self.rewrite_manifest(rustc_version="")
        with self.assertRaises(gate.Void) as raised:
            gate.verified(
                self.binary, ["a" * 40], rustc_version="rustc 1.0.0", profile="release"
            )
        self.assertIn("rustc", str(raised.exception))

    def test_an_unavailable_current_compiler_is_refused_not_accepted(self):
        from unittest import mock

        with mock.patch.object(gate, "current_rustc", return_value=None):
            with self.assertRaises(gate.Void) as raised:
                gate.verified(self.binary, ["a" * 40], profile="release")
        self.assertIn("rustc", str(raised.exception))

    def test_no_current_and_no_recorded_compiler_is_refused(self):
        from unittest import mock

        self.rewrite_manifest(rustc_version=None)
        with mock.patch.object(gate, "current_rustc", return_value=None):
            with self.assertRaises(gate.Void) as raised:
                gate.verified(self.binary, ["a" * 40], profile="release")
        self.assertIn("rustc", str(raised.exception))

    def test_a_current_compiler_that_cannot_be_determined_is_refused(self):
        import types
        from unittest import mock

        def cannot_run(*args, **kw):
            raise OSError("no rustc on this host")

        with mock.patch.object(gate.subprocess, "run", cannot_run):
            with self.assertRaises(gate.Void) as raised:
                gate.current_rustc()
        self.assertIn("rustc", str(raised.exception))
        failed = types.SimpleNamespace(returncode=1, stdout="")
        with mock.patch.object(gate.subprocess, "run", return_value=failed):
            with self.assertRaises(gate.Void):
                gate.current_rustc()
        empty = types.SimpleNamespace(returncode=0, stdout="  \n")
        with mock.patch.object(gate.subprocess, "run", return_value=empty):
            with self.assertRaises(gate.Void):
                gate.current_rustc()

    def test_write_manifest_never_certifies_an_unknown_compiler(self):
        import os
        from unittest import mock

        fresh = os.path.join(self.dir.name, "fresh.bin")
        with open(fresh, "wb") as f:
            f.write(b"built")
        with self.assertRaises(gate.Void):
            gate.write_manifest(fresh, ["a" * 40], rustc_version="")
        self.assertFalse(os.path.exists(fresh + ".json"))
        with mock.patch.object(gate, "current_rustc", return_value=None):
            with self.assertRaises(gate.Void):
                gate.write_manifest(fresh, ["a" * 40])
        self.assertFalse(os.path.exists(fresh + ".json"))
        with mock.patch.object(
            gate, "current_rustc", side_effect=gate.Void("rustc unavailable")
        ):
            with self.assertRaises(gate.Void):
                gate.write_manifest(fresh, ["a" * 40])
        self.assertFalse(os.path.exists(fresh + ".json"))


class LoadDuringRun(unittest.TestCase):
    """F3: load is sampled while a harness run is in flight, not only
    between runs, and a breach during the run reaches the peak."""

    def test_a_breach_during_a_run_is_sampled(self):
        import threading
        from unittest import mock

        entered = threading.Event()
        sampled_in_run = threading.Event()
        breach_threads = []

        def getloadavg():
            # Only the sampler thread, and only after sh() has actually
            # been entered, may report the breach: a pre-process sample
            # and the before/after main-thread samples are always quiet,
            # so neither can satisfy this test.
            if threading.current_thread() is threading.main_thread():
                return (0.5, 0.5, 0.5)
            if not entered.is_set():
                return (0.5, 0.5, 0.5)
            breach_threads.append(threading.current_thread())
            sampled_in_run.set()
            return (gate.MAX_LOAD + 5, 0.5, 0.5)

        def sh(cmd, cwd=None, env=None, timeout=None):
            entered.set()
            # The run stays in flight until the sampler samples it
            # after this entry; the timeout only bounds a failure.
            self.assertTrue(sampled_in_run.wait(5), "no load sample during the run")
            rows = gate.STAGES_FROM_HARNESS()
            return "".join(f"PER_CALL_NS {row} 100000\n" for row in rows)

        gate.PEAK_LOAD[0] = 0.0
        with mock.patch.object(gate, "sh", sh), \
                mock.patch.object(gate.os, "getloadavg", getloadavg), \
                mock.patch.object(gate, "LOAD_SAMPLE_S", 0.001), \
                contextlib.redirect_stdout(io.StringIO()):
            gate.run("base")
        self.assertTrue(entered.is_set())
        self.assertTrue(sampled_in_run.is_set())
        self.assertGreaterEqual(len(breach_threads), 1)
        self.assertTrue(
            all(t is not threading.main_thread() for t in breach_threads),
            breach_threads,
        )
        self.assertGreater(gate.PEAK_LOAD[0], gate.MAX_LOAD)

    def test_a_sampler_exception_is_void_and_the_thread_is_joined(self):
        import threading
        from unittest import mock

        failures = [0]

        def getloadavg():
            if threading.current_thread() is threading.main_thread():
                return (0.5, 0.5, 0.5)
            failures[0] += 1
            raise OSError("load unavailable in sampler")

        def sh(cmd, cwd=None, env=None, timeout=None):
            rows = gate.STAGES_FROM_HARNESS()
            return "".join(f"PER_CALL_NS {row} 100000\n" for row in rows)

        gate.PEAK_LOAD[0] = 0.0
        before_threads = threading.active_count()
        with mock.patch.object(gate, "sh", sh), \
                mock.patch.object(gate.os, "getloadavg", getloadavg), \
                mock.patch.object(gate, "LOAD_SAMPLE_S", 0.001), \
                contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(gate.Void) as raised:
                gate.run("base")
        self.assertGreaterEqual(failures[0], 1)
        self.assertIn("sampler", str(raised.exception).lower())
        self.assertEqual(threading.active_count(), before_threads)


if __name__ == "__main__":
    unittest.main()

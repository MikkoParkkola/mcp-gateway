#!/usr/bin/env python3
"""Tests for cwe532-leak-lint.py (CWE-532 secret-leak lint).

Stdlib-only. Run directly:

    python3 scripts/dev/test_cwe532_leak_lint.py

Covers the structured-field detection (the idiomatic `tracing` leak vector),
struct-derive detection, baseline handling, multiline derives, raw strings,
the extra sinks (`dbg!`/`panic!`), and fail-closed behavior on unreadable
files.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import sys
import tempfile
import unittest
from pathlib import Path

# The linter's filename has hyphens, so it can't be a normal import target.
_HERE = Path(__file__).resolve().parent
_LINT_PATH = _HERE / "cwe532-leak-lint.py"


def _load_lint():
    spec = importlib.util.spec_from_file_location("cwe532_leak_lint", _LINT_PATH)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    # Register before exec so @dataclass can resolve the module namespace.
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


lint = _load_lint()


def _scan_source(src: str, name: str = "sample.rs"):
    """Write `src` to a temp .rs file and return its findings."""
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / name
        p.write_text(src, encoding="utf-8")
        return lint.scan_file(p)


def _run_main(roots, baseline_text=None):
    """Run main() over `roots` with an optional temp baseline, returning
    (exit_code, stdout, stderr). BASELINE_PATH is monkeypatched and restored."""
    old_baseline = lint.BASELINE_PATH
    tmp_baseline = None
    try:
        if baseline_text is not None:
            fd, tmp_baseline = tempfile.mkstemp(suffix=".txt")
            os.write(fd, baseline_text.encode("utf-8"))
            os.close(fd)
            lint.BASELINE_PATH = Path(tmp_baseline)
        else:
            # Point at a path that does not exist -> empty baseline.
            lint.BASELINE_PATH = Path(tempfile.gettempdir()) / "no-such-baseline.txt"
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = lint.main(["prog", *roots])
        return code, out.getvalue(), err.getvalue()
    finally:
        lint.BASELINE_PATH = old_baseline
        if tmp_baseline:
            os.unlink(tmp_baseline)


class TestCwe532Lint(unittest.TestCase):
    # (1) struct derives Debug over a secret field -> flagged
    def test_struct_debug_secret_field_flagged(self):
        src = (
            "#[derive(Debug, Clone)]\n"
            "pub struct Creds {\n"
            "    pub api_key: String,\n"
            "}\n"
        )
        findings = _scan_source(src)
        debug = [f for f in findings if f.kind == "debug"]
        self.assertTrue(debug, "expected a debug finding for api_key")
        self.assertIn("api_key", debug[0].detail)

    # (2) safe-named fields (_count, _id, has_) -> not flagged
    def test_safe_named_fields_not_flagged(self):
        src = (
            "#[derive(Debug)]\n"
            "pub struct Stats {\n"
            "    pub token_count: u64,\n"
            "    pub session_id: String,\n"
            "    pub has_bearer: bool,\n"
            "}\n"
        )
        findings = _scan_source(src)
        self.assertEqual(findings, [], f"expected no findings, got {findings}")

    # (3) baselined finding -> not a build failure (exit 0)
    def test_baselined_finding_does_not_fail_build(self):
        src = (
            "#[derive(Debug)]\n"
            "pub struct T {\n"
            "    pub access_token: String,\n"
            "}\n"
        )
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "sample.rs"
            p.write_text(src, encoding="utf-8")
            findings = lint.scan_file(p)
            self.assertTrue(findings)
            key = findings[0].key

            # No baseline -> the new finding fails the build (exit 1).
            code, _, _ = _run_main([d], baseline_text=None)
            self.assertEqual(code, 1)

            # Same finding baselined -> build passes (exit 0).
            code, _, _ = _run_main([d], baseline_text=f"# baseline\n{key}\n")
            self.assertEqual(code, 0)

    # (4) positional log leak -> flagged
    def test_positional_log_leak_flagged(self):
        src = 'fn f() {\n    println!("value: {}", api_key);\n}\n'
        findings = _scan_source(src)
        logs = [f for f in findings if f.kind == "log"]
        self.assertTrue(logs, "expected a log finding for positional api_key")
        self.assertIn("api_key", logs[0].detail)

    # (5) STRUCTURED FIELD leak `warn!(token = %token)` -> flagged (the HIGH)
    def test_structured_field_leak_flagged(self):
        cases = [
            'warn!(access_token = %access_token, "auth failed");',
            "error!(secret = ?secret);",
            "info!(api_key = api_key);",
            "warn!(token = %token);",
        ]
        for line in cases:
            with self.subTest(line=line):
                findings = _scan_source("fn f() {\n    " + line + "\n}\n")
                logs = [f for f in findings if f.kind == "log"]
                self.assertTrue(logs, f"expected structured-field leak flagged: {line}")

    def test_structured_field_safe_value_not_flagged(self):
        # Field NAME is secret-shaped, but the logged VALUE is a benign label /
        # count / duration -> no leak. Mirrors the real-tree audit logs.
        safe = [
            "info!(credential = %rule.name);",
            "debug!(credentials = ?injected_names);",
            "info!(credentials = config.secrets.len());",
            "info!(token_ttl_secs = self.cfg.token_ttl_secs);",
            'warn!(server, error = %audit_err, "audit failed");',
        ]
        for line in safe:
            with self.subTest(line=line):
                findings = _scan_source("fn f() {\n    " + line + "\n}\n")
                logs = [f for f in findings if f.kind == "log"]
                self.assertEqual(logs, [], f"benign value wrongly flagged: {line}")

    # (5c) secret VALUE wrapped in an accessor chain on a NEUTRAL field NAME ->
    # flagged. This is the residual gap: `value = %access_token.expose_secret()`
    # leaks the secret bytes even though the field name (`value`, `v`) is benign
    # and the accessor (`.expose_secret()`, `.unwrap()`) is outside BARE_TAIL_RE.
    def test_wrapped_accessor_secret_value_flagged(self):
        cases = [
            # explicit neutral field name + secret-shaped wrapped value
            "info!(value = %access_token.expose_secret());",
            "warn!(v = %token.as_deref().unwrap());",
            # sigil-shorthand forms (the exact forms named in the finding)
            "info!(%access_token.expose_secret());",
            "warn!(%secret.as_deref().unwrap());",
        ]
        for line in cases:
            with self.subTest(line=line):
                findings = _scan_source("fn f() {\n    " + line + "\n}\n")
                logs = [f for f in findings if f.kind == "log"]
                self.assertTrue(
                    logs, f"expected wrapped-accessor secret value flagged: {line}"
                )

    # (5d) genuinely-neutral wrapped VALUE (a count/label) -> NOT flagged, even
    # though the accessor chain is the same shape as the leak above.
    def test_wrapped_accessor_neutral_value_not_flagged(self):
        safe = [
            "info!(value = %count.to_string());",
            "debug!(%count.to_string());",
            "info!(v = %name.clone());",
        ]
        for line in safe:
            with self.subTest(line=line):
                findings = _scan_source("fn f() {\n    " + line + "\n}\n")
                logs = [f for f in findings if f.kind == "log"]
                self.assertEqual(
                    logs, [], f"neutral wrapped value wrongly flagged: {line}"
                )

    # (6) multiline derive -> flagged
    def test_multiline_derive_flagged(self):
        src = (
            "#[derive(\n"
            "    Debug,\n"
            "    Clone,\n"
            ")]\n"
            "pub struct Multi {\n"
            "    pub client_secret: String,\n"
            "}\n"
        )
        findings = _scan_source(src)
        debug = [f for f in findings if f.kind == "debug"]
        self.assertTrue(debug, "expected a debug finding on multiline derive")
        self.assertIn("client_secret", debug[0].detail)

    # (7) raw-string inline capture -> flagged
    def test_raw_string_inline_capture_flagged(self):
        for line in (
            'error!(r"token is {token}");',
            'error!(r#"the api_key is {api_key} here"#);',
        ):
            with self.subTest(line=line):
                findings = _scan_source("fn f() {\n    " + line + "\n}\n")
                logs = [f for f in findings if f.kind == "log"]
                self.assertTrue(logs, f"expected raw-string capture flagged: {line}")

    # (8) dbg!(secret) / panic!("{token}") -> flagged
    def test_extra_sinks_flagged(self):
        for line in (
            "dbg!(secret);",
            'panic!("boom {token}");',
            'todo!("handle {password}");',
        ):
            with self.subTest(line=line):
                findings = _scan_source("fn f() {\n    " + line + "\n}\n")
                logs = [f for f in findings if f.kind == "log"]
                self.assertTrue(logs, f"expected extra-sink leak flagged: {line}")

    # (9) unreadable / undecodable file -> fail closed (exit 2)
    def test_unreadable_file_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "bad.rs"
            # Invalid UTF-8 -> UnicodeDecodeError on read.
            p.write_bytes(b"\xff\xfe fn main() { let token = 1; }")
            code, _out, err = _run_main([d], baseline_text=None)
            self.assertEqual(code, 2, "unreadable file must fail closed with exit 2")
            self.assertIn("bad.rs", err)


if __name__ == "__main__":
    unittest.main(verbosity=2)

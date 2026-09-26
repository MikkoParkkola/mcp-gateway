#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The OWASP citation check fails on a stale citation and passes on the real doc."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

SCRIPT = Path(__file__).resolve().parent / "check-owasp-citations.py"


def load():
    spec = importlib.util.spec_from_file_location("owasp_citations", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class OwaspCitations(unittest.TestCase):
    def problems_in(self, doc: str) -> list[str]:
        guard = load()
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src" / "security").mkdir(parents=True)
            (root / "src" / "security" / "policy.rs").write_text(
                "#[test]\nfn deny_pattern_blocks_exec() {}\n", encoding="utf-8"
            )
            (root / "tests").mkdir()
            path = root / "doc.md"
            path.write_text(doc, encoding="utf-8")
            return guard.problems(path, root)

    def test_a_missing_path_is_reported(self):
        found = self.problems_in("Policy (`src/security/ssrf.rs`).\n")
        self.assertEqual(found, ["cited path does not exist: src/security/ssrf.rs"])

    def test_a_validation_command_matching_no_test_is_reported(self):
        found = self.problems_in("```bash\ncargo test --lib no_such_test\n```\n")
        self.assertEqual(found, ["validation command matches no test: cargo test no_such_test"])

    def test_existing_citations_pass(self):
        doc = (
            "Policy (`src/security/policy.rs`, `src/security/`).\n"
            "```bash\ncargo test deny_pattern_blocks\n```\n"
        )
        self.assertEqual(self.problems_in(doc), [])

    def test_the_published_self_assessment_is_current(self):
        guard = load()
        self.assertEqual(guard.problems(guard.DOC, guard.ROOT), [])


if __name__ == "__main__":
    unittest.main()

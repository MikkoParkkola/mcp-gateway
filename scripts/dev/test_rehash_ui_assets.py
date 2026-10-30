#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Checks for rehash_ui_assets.py, each on a throwaway copy of the layout.

The script finds the repository from its own path, so each case copies it
into a temporary tree and runs it there; the real tree is never touched.

    python3 -I scripts/dev/test_rehash_ui_assets.py
"""

import hashlib
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
SCRIPT = HERE / "rehash_ui_assets.py"
REAL_SHELL = HERE.parents[1] / "src/gateway/ui/shell"
HASHED = re.compile(r"^(?P<stem>.+?)\.(?P<digest>[0-9a-f]{12})\.(?P<ext>css|js|json|woff2|svg|png)$")
ASSET_EXTS = {"css", "js", "json", "woff2", "svg", "png"}
TABLE = 'pub(super) const ASSETS: &[(&str, &[u8])] = &[\n];\n'


class Tree:
    """A temporary repository holding the script and a shell directory."""

    def __init__(self, files):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        (self.root / "scripts/dev").mkdir(parents=True)
        shutil.copy(SCRIPT, self.root / "scripts/dev/rehash_ui_assets.py")
        self.shell = self.root / "src/gateway/ui/shell"
        self.shell.mkdir(parents=True)
        (self.root / "src/gateway/ui/shell.rs").write_text(TABLE)
        for rel, text in files.items():
            path = self.shell / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)

    def run(self):
        return subprocess.run(
            [sys.executable, "-I", str(self.root / "scripts/dev/rehash_ui_assets.py")],
            capture_output=True, text=True, check=False,
        )

    def stale(self):
        """Every asset whose name does not carry the hash of its bytes."""
        out = []
        for path in self.shell.rglob("*"):
            if not path.is_file() or path.suffix.lstrip(".") not in ASSET_EXTS:
                continue
            m = HASHED.match(path.name)
            digest = hashlib.sha256(path.read_bytes()).hexdigest()[:12]
            if not m or m["digest"] != digest:
                out.append(path.name)
        return sorted(out)

    def close(self):
        self.tmp.cleanup()


class RehashOrder(unittest.TestCase):
    def tree(self, files):
        t = Tree(files)
        self.addCleanup(t.close)
        return t

    def test_a_module_that_sorts_before_the_shell_and_imports_it(self):
        t = self.tree({
            "index.html": '<script type="module" src="/ui/assets/shell.js"></script>\n'
                          '<script type="module" src="/ui/assets/actions.js"></script>\n',
            "shell.js": "export const register = () => {};\n",
            "actions.js": "import { register } from '/ui/assets/shell.js';\nregister();\n",
        })
        run = t.run()
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(t.stale(), [])
        actions = next(t.shell.glob("actions.*.js")).read_text()
        shell = next(t.shell.glob("shell.*.js")).name
        self.assertIn(f"/ui/assets/{shell}", actions)

    def test_a_chain_of_imports_is_hashed_dependencies_first(self):
        t = self.tree({
            "index.html": '<script type="module" src="/ui/assets/a.js"></script>\n',
            "c.js": "export const c = 1;\n",
            "b.js": "import { c } from '/ui/assets/c.js';\nexport const b = c;\n",
            "a.js": "import { b } from '/ui/assets/b.js';\nconsole.log(b);\n",
        })
        run = t.run()
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(t.stale(), [])

    def test_the_screen_manifest_names_are_rewritten(self):
        # The document lists its screens in a JSON block the shell reads; those
        # names follow their files like any tag's.
        t = self.tree({
            "index.html": '<script type="module" src="/ui/assets/shell.js"></script>\n'
                          '<script type="application/json" id="screens">'
                          '{"tools": {"js": "/ui/assets/tools.js", "css": "/ui/assets/tools.css"}}</script>\n',
            "shell.js": "export const register = () => {};\n",
            "tools.js": "import { register } from '/ui/assets/shell.js';\nregister();\n",
            "tools.css": "a{}\n",
        })
        run = t.run()
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(t.stale(), [])
        doc = (t.shell / "index.html").read_text()
        for pattern in ("tools.*.js", "tools.*.css"):
            self.assertIn(f'"/ui/assets/{next(t.shell.glob(pattern)).name}"', doc)

    def test_a_cycle_is_refused(self):
        t = self.tree({
            "index.html": "",
            "a.js": "import '/ui/assets/b.js';\n",
            "b.js": "import '/ui/assets/a.js';\n",
        })
        run = t.run()
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("cycle", run.stderr)

    def test_a_self_reference_is_refused_before_anything_moves(self):
        t = self.tree({
            "index.html": "",
            "a.js": "import '/ui/assets/a.js';\n",
        })
        run = t.run()
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("cycle", run.stderr)
        self.assertTrue((t.shell / "a.js").exists(), "nothing renamed before the refusal")

    def test_a_second_run_changes_nothing(self):
        t = self.tree({
            "index.html": '<script type="module" src="/ui/assets/shell.js"></script>\n',
            "shell.js": "export const x = 1;\n",
            "actions.js": "import { x } from '/ui/assets/shell.js';\n",
        })
        self.assertEqual(t.run().returncode, 0)
        before = sorted(p.name for p in t.shell.rglob("*") if p.is_file())
        self.assertEqual(t.run().returncode, 0)
        self.assertEqual(sorted(p.name for p in t.shell.rglob("*") if p.is_file()), before)

    def test_changing_only_the_copy_renames_it_and_every_module_that_reaches_it(self):
        t = self.tree({
            "index.html": '<script type="module" src="/ui/assets/tools.js"></script>\n',
            "tips.json": '{"a.status.b": {"title": "A", "text": "first"}}\n',
            "tooltip.js": "export const tip = () => fetch('/ui/assets/tips.json');\n",
            "tools.js": "import { tip } from '/ui/assets/tooltip.js';\ntip();\n",
        })
        self.assertEqual(t.run().returncode, 0)
        self.assertEqual(t.stale(), [])

        def names():
            return {HASHED.match(p.name)["stem"]: p.name for p in t.shell.iterdir() if HASHED.match(p.name)}

        before = names()
        copy = t.shell / before["tips"]
        copy.write_text(copy.read_text().replace("first", "second"))
        run = t.run()
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(t.stale(), [])
        after = names()
        for stem in ("tips", "tooltip", "tools"):
            self.assertNotEqual(after[stem], before[stem], f"{stem} keeps its old name")
        self.assertIn(f"/ui/assets/{after['tips']}", (t.shell / after["tooltip"]).read_text())
        self.assertIn(f"/ui/assets/{after['tooltip']}", (t.shell / after["tools"]).read_text())
        self.assertIn(f"/ui/assets/{after['tools']}", (t.shell / "index.html").read_text())
        table = (t.root / "src/gateway/ui/shell.rs").read_text()
        for stem in ("tips", "tooltip", "tools"):
            self.assertIn(f'"{after[stem]}"', table)
        settled = sorted(p.name for p in t.shell.iterdir())
        self.assertEqual(t.run().returncode, 0)
        self.assertEqual(sorted(p.name for p in t.shell.iterdir()), settled)

    def test_the_real_shell_is_already_hashed_and_stays_so(self):
        t = Tree({})
        self.addCleanup(t.close)
        shutil.rmtree(t.shell)
        shutil.copytree(REAL_SHELL, t.shell)
        before = sorted(p.name for p in t.shell.rglob("*") if p.is_file())
        run = t.run()
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(t.stale(), [])
        self.assertEqual(sorted(p.name for p in t.shell.rglob("*") if p.is_file()), before)


if __name__ == "__main__":
    unittest.main(verbosity=2)

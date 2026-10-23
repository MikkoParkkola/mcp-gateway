# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Drift test for pre-push's CI script checks (MIK-8410 DRIFT.1, RUST.1).

Every script a pull-request workflow executes is in exactly one bucket: RUN
(pre-push runs it, `scripts/dev/prepush-ci-checks.txt`), ALREADY (an existing
pre-push step runs the same form) or CI_ONLY (with a reason from a closed set
of classes). The scanner here is importable; the rows below pin it.

SKELETON: the scanner functions return nothing yet.
"""
from __future__ import annotations

import pathlib
import re
import sys
import tempfile
import textwrap
import unittest

import yaml

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(HERE))

import workflow_shell  # noqa: E402

RUN_LIST = pathlib.Path("scripts/dev/prepush-ci-checks.txt")
CI_ONLY_CLASSES = ("cargo", "binary", "artifact", "release", "ci-env", "network", "budget", "windows")
# form (script, args) -> "class: free text". Forms whose own step makes them
# CI-only (a pwsh step, a base bound to a URL or to push-only event data) are
# classified by the walker and are not listed here.
CI_ONLY: dict[tuple[str, tuple[str, ...]], str] = {
    ("scripts/ci/check-codeql-ignore.py", ()): "cargo: runs cargo metadata/build; Spark only",
    ("scripts/ci/check_docker_hub_pulls.py", ()): "network: queries Docker Hub",
    ("scripts/ci/check_needs.py", ("macos-shards",)): "ci-env: reads NEEDS from ${{ toJSON(needs) }}",
    ("scripts/ci/check_needs.py", ("test-shards",)): "ci-env: reads NEEDS from ${{ toJSON(needs) }}",
    ("scripts/ci/check_needs.py", ("windows-shards", "windows-clippy")): "ci-env: reads NEEDS from ${{ toJSON(needs) }}",
    ("scripts/ci/shard_tests.py", ("run", "linux", "${{matrix.shard}}")): "cargo: runs cargo test shards",
    ("scripts/ci/shard_tests.py", ("run", "macos", "${{matrix.shard}}")): "cargo: runs cargo test shards",
    ("scripts/dev/check-registry-packages.py", ()): "network: live npm/PyPI/HTTP lookups",
    ("scripts/dev/check-registry-packages.py", ("scripts/dev/testdata/registry-dead.rs",)): "network: live lookups, CI expects exit 1 (registry-packages.yml:52-57)",
    ("scripts/release/check_known_issues.py", ("--release",)): "release: tag-time form",
    ("scripts/release/check_release_assets.py", ("sbom", "--version", "$version", "--sbom-only", "${{matrix.artifact}}${{matrix.suffix}}")): "binary: needs a built release binary and syft",
    ("scripts/release/check_scope_acceptance.py", ("--publish-check",)): "release: publish-time form",
    ("scripts/release/check_tag_manifest.py", ()): "release: needs a tag in GITHUB_REF_NAME",
    ("scripts/release/critical_function_coverage.py", ("$@",)): "artifact: reads a cargo llvm-cov profile",
    ("scripts/release/critical_path_coverage.py", ("art/coverage-linux/cov.json",)): "artifact: reads a CI coverage artifact",
    ("scripts/release/test_workflow_wiring_mutations.py", ()): "budget: 329 s alone, over the 120 s budget",
}



PR_EVENTS = ("pull_request", "pull_request_target")
NON_POSIX_SHELLS = ("pwsh", "powershell", "cmd")
RUST_READS = re.compile(r'"[^"\n]*\bdocs/|include_str!\("\.\./docs|Cli::command\(\)|Cli::(?:try_)?parse_from\(')


def _load(path):
    return yaml.safe_load(path.read_text()) or {}


def _is_pr(doc) -> bool:
    on = doc.get(True, doc.get("on"))  # PyYAML reads a bare `on:` key as True
    if isinstance(on, str):
        return on in PR_EVENTS
    if isinstance(on, (list, dict)):
        return any(event in on for event in PR_EVENTS)
    return False


def pr_workflows(root: pathlib.Path) -> list[pathlib.Path]:
    """Workflows triggered by pull_request or pull_request_target, any YAML form."""
    return sorted(p for p in (root / ".github/workflows").glob("*.yml") if _is_pr(_load(p)))


def _steps(root, path, seen):
    """(workflow name, step) for every step, following local reusable-workflow calls."""
    if path in seen:
        return
    seen.add(path)
    for job in (_load(path).get("jobs") or {}).values():
        uses = job.get("uses", "") if isinstance(job, dict) else ""
        if uses.startswith("./.github/workflows/"):
            yield from _steps(root, root / uses[2:], seen)
            continue
        for step in (job.get("steps") or []) if isinstance(job, dict) else []:
            yield path.name, step


def _scan(root):
    """(form -> [workflows], form -> automatic CI_ONLY reason, problems)."""
    forms, auto, found = {}, {}, []
    seen = set()
    for workflow in pr_workflows(root):
        for name, step in _steps(root, workflow, seen):
            run = step.get("run") if isinstance(step, dict) else None
            if not run:
                continue
            try:
                executed = workflow_shell.executions(run)
            except workflow_shell.UnsupportedSyntax as err:
                found.append(f"unsupported execution syntax in {name} step {step.get('name', '?')!r}: {err}")
                continue
            windows = str(step.get("shell", "")).split()[:1] in ([s] for s in NON_POSIX_SHELLS)
            for ex in executed:
                scripts = sorted(str(p.relative_to(root)) for p in root.glob(ex.script)) if "*" in ex.script else [ex.script]
                for script in scripts:
                    form = (script, ex.args)
                    forms.setdefault(form, []).append(name)
                    if windows:
                        auto[form] = "windows: runs under a non-POSIX shell step"
                    elif ex.auto_class:
                        auto[form] = ex.auto_class
    return forms, auto, found


def _forms_of(text):
    forms = set()
    for command in text.splitlines():
        command = command.split("\t")[0].strip()
        if command and not command.startswith("#"):
            forms |= {(e.script, e.args) for e in workflow_shell.executions(command)}
    return forms


def scanned_forms(root: pathlib.Path) -> dict:
    return _scan(root)[0]


def buckets(root: pathlib.Path, *, ci_only=None):
    """(RUN forms, ALREADY forms, CI_ONLY form -> reason)."""
    table = CI_ONLY if ci_only is None else ci_only
    run = _forms_of((root / RUN_LIST).read_text()) if (root / RUN_LIST).exists() else set()
    pre_push = root / "scripts/dev/pre-push.sh"
    already = {(e.script, e.args) for e in workflow_shell.executions(pre_push.read_text())} if pre_push.exists() else set()
    return run, already, {**table, **_scan(root)[1]}


def problems(root: pathlib.Path, *, ci_only=None) -> list[str]:
    """Every drift problem, each naming its form and, when scanned, its workflows."""
    table = CI_ONLY if ci_only is None else ci_only
    forms, auto, found = _scan(root)
    run, already, ci = buckets(root, ci_only=table)
    for form, workflows in sorted(forms.items()):
        label = " ".join((form[0], *form[1])) + f" ({', '.join(sorted(set(workflows)))})"
        homes = [b for b, members in (("RUN", run), ("ALREADY", already), ("CI_ONLY", ci)) if form in members]
        if not homes:
            found.append(f"in no bucket: {label}")
        elif len(homes) > 1:
            found.append(f"in two buckets {homes}: {label}")
        if form not in ci and any("${{" in a or "$RUNNER_" in a for a in form[1]):
            found.append(f"untranslated CI token in {label}")
    for form in sorted(run - set(forms)):
        found.append(f"stale RUN line (no PR workflow runs it): {' '.join((form[0], *form[1]))}")
    for form, reason in sorted(table.items()):
        if form not in forms:
            found.append(f"stale CI_ONLY entry: {form[0]}")
        if reason.split(":")[0].strip() not in CI_ONLY_CLASSES:
            found.append(f"CI_ONLY reason names no class from {CI_ONLY_CLASSES}: {form[0]}: {reason!r}")
    return found


def rust_targets(root: pathlib.Path) -> list[str]:
    """Test targets whose sources read docs/ or the CLI definition (§7)."""
    names = []
    for target in sorted((root / "tests").glob("*.rs")):
        sources = [target, *sorted((root / "tests" / target.stem).rglob("*.rs"))]
        if any(RUST_READS.search(s.read_text(errors="replace")) for s in sources):
            names.append(target.stem)
    return names


# ---------------------------------------------------------------- fixtures


class Tree:
    """A throwaway repository root with workflows, scripts and a run list."""

    def __init__(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self._tmp.name)
        (self.root / ".github/workflows").mkdir(parents=True)
        (self.root / "scripts/dev").mkdir(parents=True)
        (self.root / RUN_LIST).write_text("")
        (self.root / "scripts/dev/pre-push.sh").write_text("#!/usr/bin/env bash\n")

    def close(self):
        self._tmp.cleanup()

    def workflow(self, name, body):
        (self.root / ".github/workflows" / name).write_text(textwrap.dedent(body))

    def script(self, path):
        f = self.root / path
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text("print('ok')\n")

    def run_list(self, *lines):
        (self.root / RUN_LIST).write_text("".join(f"{line}\n" for line in lines))

    def pre_push(self, text):
        (self.root / "scripts/dev/pre-push.sh").write_text(textwrap.dedent(text))


def pr_job(*runs, on="pull_request:", extra=""):
    steps = "".join(f"      - run: {r}\n" if "\n" not in r else f"      - run: |\n{textwrap.indent(r, ' ' * 10)}\n" for r in runs)
    return f"on:\n  {on}\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n{steps}{extra}"


def scripts_of(forms):
    return {form[0] for form in forms}


class Rows(unittest.TestCase):
    def setUp(self):
        self.t = Tree()

    def tearDown(self):
        self.t.close()

    # D1
    def test_d1_an_unbucketed_execution_is_named_with_its_workflow(self):
        self.t.script("scripts/x.py")
        self.t.workflow("ci.yml", pr_job("python3 scripts/x.py"))
        found = problems(self.t.root, ci_only={})
        self.assertTrue(any("scripts/x.py" in p and "ci.yml" in p for p in found), found)

    # D2
    def test_d2_a_run_line_no_workflow_runs_is_stale(self):
        self.t.script("scripts/y.py")
        self.t.run_list("python3 scripts/y.py\t1\tclosed")
        self.t.workflow("ci.yml", pr_job("echo nothing"))
        found = problems(self.t.root, ci_only={})
        self.assertTrue(any("stale" in p and "scripts/y.py" in p for p in found), found)

    # D3
    def test_d3_a_ci_only_reason_without_a_class_fails(self):
        self.t.script("scripts/z.py")
        self.t.workflow("ci.yml", pr_job("python3 scripts/z.py"))
        found = problems(self.t.root, ci_only={("scripts/z.py", ()): "because"})
        self.assertTrue(any("class" in p and "scripts/z.py" in p for p in found), found)

    # D4
    def test_d4_a_form_in_two_buckets_fails(self):
        self.t.script("scripts/z.py")
        self.t.workflow("ci.yml", pr_job("python3 scripts/z.py"))
        self.t.run_list("python3 scripts/z.py\t1\tclosed")
        found = problems(self.t.root, ci_only={("scripts/z.py", ()): "network: test"})
        self.assertTrue(any("two buckets" in p and "scripts/z.py" in p for p in found), found)

    # D5
    def test_d5_a_test_glob_loop_expands_to_every_suite(self):
        self.t.script("scripts/release/test_a.py")
        self.t.script("scripts/release/test_b.py")
        self.t.workflow("ci.yml", pr_job('for s in scripts/release/test_*.py; do python3 "$s"; done'))
        self.assertEqual(
            scripts_of(scanned_forms(self.t.root)),
            {"scripts/release/test_a.py", "scripts/release/test_b.py"},
        )

    # D6
    def test_d6_only_pull_request_workflows_are_demanded(self):
        for s in ("scripts/z.py", "scripts/w.py"):
            self.t.script(s)
        self.t.workflow("push.yml", pr_job("python3 scripts/z.py", on="push:"))
        self.t.workflow("ci.yml", pr_job("python3 scripts/w.py"))
        self.assertEqual(scripts_of(scanned_forms(self.t.root)), {"scripts/w.py"})

    # D7
    def test_d7_mentions_are_not_executions(self):
        for s in ("scripts/m.py", "scripts/n.py"):
            self.t.script(s)
        self.t.workflow(
            "ci.yml",
            pr_job('# python3 scripts/m.py\necho "scripts/m.py"\ngrep -q scripts/m.py README.md || true\npython3 scripts/n.py'),
        )
        self.assertEqual(scripts_of(scanned_forms(self.t.root)), {"scripts/n.py"})

    # D8
    def test_d8_chains_split_and_a_pipeline_stays_one_form(self):
        found = workflow_shell.executions(
            "python3 scripts/a.py --base \\\n  x && \\\n  python3 scripts/b.py; python3 scripts/c.py || true\n"
            'python3 scripts/g.py "$t" | cmp - f.json\n'
        )
        self.assertEqual([e.script for e in found], ["scripts/a.py", "scripts/b.py", "scripts/c.py", "scripts/g.py"])
        # A continuation inside one command joins its argument (F14).
        self.assertEqual(found[0].args, ("--base", "x"))
        self.assertEqual(found[3].pipeline, ('python3 scripts/g.py "$t"', "cmp - f.json"))

    # D17 (impl r1 F2): a script fed by a pipe is an execution, with its pipeline.
    def test_d17_a_script_after_a_pipe_is_an_execution(self):
        found = workflow_shell.executions("cat f.json | python3 scripts/p.py --x")
        self.assertEqual([(e.script, e.args, e.pipeline) for e in found],
                         [("scripts/p.py", ("--x",), ("cat f.json", "python3 scripts/p.py --x"))])

    # D18 (impl r1 F3): single-quoted text is data, not a substitution.
    def test_d18_a_single_quoted_substitution_is_not_an_execution(self):
        self.assertEqual(workflow_shell.executions("echo '$(python3 scripts/q.py)'"), [])

    # D19 (impl r1 F4): a quoted argument with a space stays one argument;
    # an unbalanced quote fails closed.
    def test_d19_a_quoted_argument_is_one_word(self):
        found = workflow_shell.executions('python3 scripts/r.py "two words" x')
        self.assertEqual([e.args for e in found], [("two words", "x")])
        with self.assertRaises(workflow_shell.UnsupportedSyntax):
            workflow_shell.executions('python3 scripts/r.py "open')

    # D9
    def test_d9_pull_request_target_counts_as_a_pr_workflow(self):
        self.t.script("scripts/t.py")
        self.t.workflow("bot.yml", "on: pull_request_target\n" + pr_job("python3 scripts/t.py").split("\n", 2)[2])
        self.assertEqual([p.name for p in pr_workflows(self.t.root)], ["bot.yml"])
        self.assertIn("scripts/t.py", scripts_of(scanned_forms(self.t.root)))

    # D10
    def test_d10_a_called_reusable_workflow_is_scanned(self):
        self.t.script("scripts/r.py")
        self.t.workflow("reusable.yml", "on:\n  workflow_call:\n" + pr_job("python3 scripts/r.py").split("\n", 2)[2])
        self.t.workflow("ci.yml", "on:\n  pull_request:\njobs:\n  call:\n    uses: ./.github/workflows/reusable.yml\n")
        self.assertIn("scripts/r.py", scripts_of(scanned_forms(self.t.root)))

    # D11
    def test_d11_ci_tokens_become_placeholders_and_unknown_ones_fail(self):
        found = workflow_shell.executions(
            'python3 scripts/k.py "origin/${{ github.base_ref }}" "$RUNNER_TEMP/x" "${{ secrets.X }}"'
        )
        self.assertEqual([e.args[:2] for e in found], [("<BASE_TIP>", "<TMP>/x")])
        self.t.script("scripts/k.py")
        self.t.workflow("ci.yml", pr_job('python3 scripts/k.py "${{ secrets.X }}"'))
        self.assertTrue(any("secrets.X" in p for p in problems(self.t.root, ci_only={})))

    # D12
    def test_d12_substitutions_are_executions_and_unknown_syntax_fails_closed(self):
        found = workflow_shell.executions('out="$(python3 scripts/s.py)"\nv=`python3 scripts/u.py`\n')
        self.assertEqual({e.script for e in found}, {"scripts/s.py", "scripts/u.py"})
        self.t.workflow("ci.yml", pr_job('eval "$cmd"'))
        self.assertTrue(any("unsupported" in p.lower() and "ci.yml" in p for p in problems(self.t.root, ci_only={})))

    # D13
    def test_d13_heredocs_keywords_and_pwsh_steps(self):
        for s in ("scripts/h.py", "scripts/w.py"):
            self.t.script(s)
        pwsh = "      - shell: pwsh\n        run: python scripts/w.py\n"
        self.t.workflow(
            "ci.yml",
            pr_job("python3 - <<'PY'\nprint('python3 scripts/h.py')\nPY\nif true; then echo x; fi", extra=pwsh),
        )
        self.assertNotIn("scripts/h.py", scripts_of(scanned_forms(self.t.root)))
        ci_only = buckets(self.t.root, ci_only={})[2]
        self.assertTrue(any(f[0] == "scripts/w.py" and r.startswith("windows") for f, r in ci_only.items()), ci_only)

    # D14a / D14b / D14c (D1: per-source binding of $base)
    def test_d14a_pre_push_base_is_the_merge_base(self):
        self.t.pre_push(
            'base="$(git merge-base HEAD origin/docs/ranking-1-release-line)"\n'
            'python3 scripts/dev/check-file-size.py --base "$base"\n'
        )
        already = buckets(self.t.root, ci_only={})[1]
        self.assertIn(("scripts/dev/check-file-size.py", ("--base", "<MERGE_BASE>")), already)

    def test_d14b_ci_file_size_base_is_the_base_tip_and_not_already(self):
        self.t.script("scripts/dev/check-file-size.py")
        self.t.pre_push(
            'base="$(git merge-base HEAD origin/docs/ranking-1-release-line)"\n'
            'python3 scripts/dev/check-file-size.py --base "$base"\n'
        )
        self.t.workflow("ci.yml", pr_job('base="${BASE_SHA:-}"\npython3 scripts/dev/check-file-size.py --base "$base"'))
        forms = scanned_forms(self.t.root)
        self.assertIn(("scripts/dev/check-file-size.py", ("--base", "<BASE_TIP>")), forms)
        self.assertTrue(any("check-file-size.py" in p for p in problems(self.t.root, ci_only={})))

    def test_d14c_a_url_base_is_ci_only_network(self):
        self.t.script("scripts/dl.py")
        self.t.workflow("ci.yml", pr_job('base=https://example.invalid/releases/download/v1\npython3 scripts/dl.py "$base"'))
        ci_only = buckets(self.t.root, ci_only={})[2]
        self.assertTrue(any(f[0] == "scripts/dl.py" and r.startswith("network") for f, r in ci_only.items()), ci_only)

    # D15 (D2)
    def test_d15_a_push_only_event_base_is_ci_only_ci_env(self):
        self.t.script("scripts/dev/check-timing-asserts.py")
        self.t.workflow(
            "ci.yml",
            pr_job('base="$BEFORE"\npython3 scripts/dev/check-timing-asserts.py --base "$base"',
                   extra="        env:\n          BEFORE: ${{ github.event.before }}\n"),
        )
        ci_only = buckets(self.t.root, ci_only={})[2]
        self.assertTrue(
            any(f[0] == "scripts/dev/check-timing-asserts.py" and r.startswith("ci-env") for f, r in ci_only.items()), ci_only
        )

    # D16 (D3)
    def test_d16_windows_is_a_legal_class(self):
        self.t.script("scripts/z.py")
        self.t.workflow("ci.yml", pr_job("python3 scripts/z.py"))
        self.assertIn("windows", CI_ONLY_CLASSES)
        self.assertEqual(problems(self.t.root, ci_only={("scripts/z.py", ()): "windows: pwsh shard"}), [])
        self.assertTrue(problems(self.t.root, ci_only={("scripts/z.py", ()): "because"}))


class Repository(unittest.TestCase):
    # R1
    def test_r1_every_executed_form_has_one_bucket(self):
        names = sorted(p.name for p in pr_workflows(REPO))
        self.assertEqual(
            names,
            sorted([
                "alert-rules.yml", "c6-obligations.yml", "changelog.yml", "ci.yml", "coverage-probe.yml",
                "dependabot-auto-merge.yml", "docker.yml", "mrtr7b-full-burst.yml", "registry-packages.yml", "rustdoc.yml",
            ]),
        )
        self.assertEqual(problems(REPO), [])

    # R2
    def test_r2_rust_targets_are_derived_from_sources(self):
        expected = {
            "capability_pin_policy", "cli_debug_assert", "cli_surface_inventory", "client_matrix_claims",
            "e2e_quickstart_minimal_config", "kubernetes_manifest_tests", "mik_5226_acs", "mik_6550_roadmap",
            "mik_6556_trust_cbom", "mik_6977_acs", "mik_7272_conformance", "public_claims_validation",
            "registry_doc_counts", "shadow_scan_docs", "stdio_tests", "team_deployment_guide_claims",
            "upgrading_summary_rows", "webui_management_tests",
        }
        self.assertEqual(set(rust_targets(REPO)), expected)
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "tests").mkdir()
            (root / "tests/only_parse_from.rs").write_text('fn t(){ let _ = Cli::parse_from(["x"]); }\n')
            (root / "tests/unrelated.rs").write_text("fn t(){}\n")
            self.assertEqual(rust_targets(root), ["only_parse_from"])


if __name__ == "__main__":
    unittest.main()

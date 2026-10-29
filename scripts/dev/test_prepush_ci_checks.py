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
import shlex
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
    ("scripts/ci/check_needs.py", ("${skippable[@]}", "scope", "windows-shards", "windows-clippy", "windows-check", "release-script-tests", "task-sdk-recovery", "gws-dry-run", "linux-keychain", "kani", "upgrade-rehearsal")): "ci-env: reads NEEDS from ${{ toJSON(needs) }} (heavy-gate)",
    ("scripts/ci/shard_tests.py", ("run", "linux", "${{matrix.shard}}")): "cargo: runs cargo test shards",
    ("scripts/ci/shard_tests.py", ("run", "macos", "${{matrix.shard}}")): "cargo: runs cargo test shards",
    ("scripts/dev/check-registry-packages.py", ()): "network: live npm/PyPI/HTTP lookups",
    ("scripts/dev/check-registry-packages.py", ("scripts/dev/testdata/registry-dead.rs", "--integrity", "scripts/dev/testdata/registry-dead.integrity.json")): "network: live lookups, CI expects exit 1 (registry-packages.yml, known-dead step)",
    ("scripts/dev/check-registry-packages.py", ("scripts/dev/testdata/registry-integrity.rs", "--integrity", "scripts/dev/testdata/registry-integrity.integrity.json")): "network: live digest lookup, CI expects exit 1 (MIK-8513 wrong-digest step)",
    ("scripts/dev/check-registry-packages.py", ("--start",)): "network: fetches and starts packages in Docker (MIK-8513 starts job)",
    ("scripts/dev/check-registry-packages.py", ("--start", "scripts/dev/testdata/registry-integrity.rs", "--integrity", "scripts/dev/testdata/registry-integrity.integrity.json")): "network: real npm pack in Docker, CI expects exit 1 (MIK-8513 served-bytes step)",
    ("scripts/dev/check-registry-packages.py", ("--start", "scripts/dev/testdata/registry-wont-start.rs", "--integrity", "scripts/dev/testdata/registry-wont-start.integrity.json")): "network: starts packages in Docker, CI expects exit 1 (MIK-8513 won't-start step)",
    ("scripts/release/check_known_issues.py", ("--release",)): "release: tag-time form",
    ("scripts/release/check_release_assets.py", ("sbom", "--version", "$version", "--sbom-only", "${{matrix.artifact}}${{matrix.suffix}}")): "binary: needs a built release binary and syft",
    ("scripts/release/check_scope_acceptance.py", ("--publish-check",)): "release: publish-time form",
    ("scripts/release/check_tag_manifest.py", ()): "release: needs a tag in GITHUB_REF_NAME",
    ("scripts/release/critical_function_coverage.py", ("$@",)): "artifact: reads a cargo llvm-cov profile",
    ("scripts/release/critical_path_coverage.py", ("art/coverage-linux/cov.json",)): "artifact: reads a CI coverage artifact",
    ("scripts/dev/test_run_prepush_ci_checks.py", ()): (
        "budget: tests the runner itself; 22.5 s would put the CI-checks stage at about 114 s of its "
        "120 s budget on every push; CI runs it on every PR"
    ),
    ("scripts/release/test_workflow_wiring_mutations.py", ()): "budget: 329 s alone, over the 120 s budget",
}



PR_EVENTS = ("pull_request", "pull_request_target")
NON_POSIX_SHELLS = ("pwsh", "powershell", "cmd")
# The doc/CLI-reading Rust targets (§7). Derived on every push and checked
# against this set (R3): a new reader is pinned here, a lost one is a regression.
RUST_TARGETS = frozenset({
    "capability_pin_policy", "cli_debug_assert", "cli_surface_inventory", "client_matrix_claims",
    "e2e_quickstart_minimal_config", "kubernetes_manifest_tests", "mik_5226_acs", "mik_6550_roadmap",
    "mik_6556_trust_cbom", "mik_6977_acs", "mik_7272_conformance", "mik_8783_cli_help",
    "mik_8783_docs", "mik_8783_upgrade_retired_settings", "public_claims_validation",
    "registry_doc_counts", "shadow_scan_docs", "stdio_tests", "team_deployment_guide_claims",
    "upgrading_summary_rows", "webui_management_tests",
})
UNTRANSLATED = re.compile(r"\$\{\{|\$\{?RUNNER_")
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
    found = [*(root / ".github/workflows").glob("*.yml"), *(root / ".github/workflows").glob("*.yaml")]
    return sorted(p for p in found if _is_pr(_load(p)))


def _job_steps(root, path, seen, caller=""):
    """(workflow path, workflow env, job, job name chain, step) for every step,
    following local reusable-workflow calls (the caller's name is carried)."""
    if path in seen:
        return
    seen.add(path)
    doc = _load(path)
    for job in (doc.get("jobs") or {}).values():
        if not isinstance(job, dict):
            continue
        names = f"{caller} / {job.get('name', '')}" if caller else str(job.get("name", ""))
        uses = job.get("uses", "")
        if uses.startswith("./.github/workflows/"):
            yield from _job_steps(root, root / uses[2:], seen, names)
            continue
        for step in job.get("steps") or []:
            yield path, doc.get("env") or {}, job, names, step


def _steps(root, path, seen):
    """(workflow name, step) for every step, following local reusable-workflow calls."""
    for workflow, _, _, _, step in _job_steps(root, path, seen):
        yield workflow.name, step


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
                if not scripts:
                    found.append(f"glob matches no file: {ex.script} ({name})")
                for script in scripts:
                    form = _form(script, ex)
                    forms.setdefault(form, []).append(name)
                    if windows:
                        auto[form] = "windows: runs under a non-POSIX shell step"
                    elif ex.auto_class:
                        auto[form] = ex.auto_class
    return forms, auto, found


def _form(script, ex):
    """A form's identity: script and args, plus the whole pipeline when it has one (F5)."""
    return (script, ex.args, ex.pipeline) if ex.pipeline else (script, ex.args)


def _label(form):
    return " ".join((form[0], *form[1])) + (f" [pipeline: {' | '.join(form[2])}]" if len(form) > 2 else "")


def _forms_of(text):
    forms = set()
    for command in text.splitlines():
        command = command.split("\t")[0].strip()
        if command and not command.startswith("#"):
            forms |= {_form(e.script, e) for e in workflow_shell.executions(command)}
    return forms


def scanned_forms(root: pathlib.Path) -> dict:
    return _scan(root)[0]


def buckets(root: pathlib.Path, *, ci_only=None):
    """(RUN forms, ALREADY forms, CI_ONLY form -> reason)."""
    table = CI_ONLY if ci_only is None else ci_only
    run = _forms_of((root / RUN_LIST).read_text()) if (root / RUN_LIST).exists() else set()
    pre_push = root / "scripts/dev/pre-push.sh"
    already = {_form(e.script, e) for e in workflow_shell.executions(pre_push.read_text())} if pre_push.exists() else set()
    return run, already, {**table, **_scan(root)[1]}


def problems(root: pathlib.Path, *, ci_only=None) -> list[str]:
    """Every drift problem, each naming its form and, when scanned, its workflows."""
    table = CI_ONLY if ci_only is None else ci_only
    forms, auto, found = _scan(root)
    run, already, ci = buckets(root, ci_only=table)
    for form, workflows in sorted(forms.items()):
        label = _label(form) + f" ({', '.join(sorted(set(workflows)))})"
        homes = [b for b, members in (("RUN", run), ("ALREADY", already), ("CI_ONLY", ci)) if form in members]
        if not homes:
            found.append(f"in no bucket: {label}")
        elif len(homes) > 1:
            found.append(f"in two buckets {homes}: {label}")
        if form not in ci and any(UNTRANSLATED.search(a) for a in form[1]):
            found.append(f"untranslated CI token in {label}")
    found += clippy_problems(root)
    for form in sorted(run - set(forms)):
        found.append(f"stale RUN line (no PR workflow runs it): {_label(form)}")
    for form, reason in sorted(table.items()):
        if form not in forms:
            found.append(f"stale CI_ONLY entry: {form[0]}")
        if reason.split(":")[0].strip() not in CI_ONLY_CLASSES:
            found.append(f"CI_ONLY reason names no class from {CI_ONLY_CLASSES}: {form[0]}: {reason!r}")
    return found


def _module_resolver():
    """scripts/dev/check-orphan-test-modules.py's Rust module resolver: one
    reading of `mod` and `#[path]`, shared with the orphan-module check."""
    import importlib.util

    path = pathlib.Path(__file__).with_name("check-orphan-test-modules.py")
    spec = importlib.util.spec_from_file_location("orphan_test_modules", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.declarations


INCLUDE = re.compile(r'\binclude!\s*\(\s*"([^"]+)"\s*\)')


def _sources(target):
    """`target` and every file its module tree pulls in, resolved as rustc does:
    `mod`/`#[path]` through the shared resolver, `include!` textually. A file is
    visited once per module context, since its `mod` children resolve per context."""
    declarations = _module_resolver()
    pending, visited, files = [(target, True)], set(), []
    while pending:
        source, owns_dir = pending.pop()
        if (source, owns_dir) in visited or not source.is_file():
            continue
        visited.add((source, owns_dir))
        if source not in files:
            files.append(source)
        pending += sorted(declarations(source, owns_dir))
        text = source.read_text(errors="replace")
        pending += [((source.parent / rel).resolve(), owns_dir) for rel in INCLUDE.findall(text)]
    return files


# MIK-8733: clippy coverage. A pre-push clippy step covers a CI one when both
# lint the same code the same way: same profile, same feature selection, a
# superset of targets, identical lint args and other flags, and the same
# build-relevant environment (CLIPPY_CONF_DIR above all: the registry ban runs
# under its own config).
ALL_TARGETS = frozenset({"lib", "bins", "tests", "benches", "examples"})
DEFAULT_TARGETS = frozenset({"lib", "bins"})  # cargo's selection with no target flag
CLIPPY_ENV = re.compile(r"^(CLIPPY_CONF_DIR|RUSTFLAGS|CARGO_ENCODED_RUSTFLAGS|CARGO_BUILD_RUSTFLAGS|CARGO_PROFILE_\w+)$")
WORKSPACE_PREFIXES = ("${{github.workspace}}/", "${{ github.workspace }}/", "$GITHUB_WORKSPACE/", "${GITHUB_WORKSPACE}/",
                      "$REPO_ROOT/", "${REPO_ROOT}/")
CARGO_VALUE_OPTIONS = {"--color", "--config", "-Z", "-C", "--manifest-path"}
RESOLUTION_ONLY = {"--quiet", "-q", "--locked", "--frozen", "--offline"}


def _env_value(value):
    value = str(value).strip().strip("'\"")
    for prefix in WORKSPACE_PREFIXES:
        if value.startswith(prefix):
            return value[len(prefix):]
    return value


def _clippy_key(words, env):
    """(profile, features, targets, lints, other flags, env) of `clippy <words>`."""
    flags, lints = (words[:words.index("--")], words[words.index("--") + 1:]) if "--" in words else (words, [])
    profile, features, named, targets, other, i = "dev", [], [], set(), [], 0
    while i < len(flags):
        flag = flags[i]
        if flag == "--release":
            profile = "release"
        elif flag == "--profile" and i + 1 < len(flags):
            profile, i = flags[i + 1], i + 1
        elif flag in ("--features", "-F") and i + 1 < len(flags):
            features += flags[i + 1].replace(",", " ").split()
            i += 1
        elif flag in ("--all-features", "--no-default-features"):
            named.append(flag)
        elif flag == "--all-targets":
            targets |= ALL_TARGETS
        elif flag in ("--lib", "--bins", "--tests", "--benches", "--examples"):
            targets.add(flag[2:])
        elif flag not in RESOLUTION_ONLY:
            other.append(flag)
        i += 1
    env = {k: _env_value(v) for k, v in env.items() if CLIPPY_ENV.match(k)}
    # The workflow's RUSTFLAGS=-Dwarnings repeats `-- -D warnings`; anything else must match.
    if env.get("RUSTFLAGS", "").replace(" ", "") == "-Dwarnings" and lints == ["-D", "warnings"]:
        env.pop("RUSTFLAGS")
    return (profile, (tuple(sorted(named)), tuple(sorted(features))), frozenset(targets) or DEFAULT_TARGETS,
            tuple(lints), tuple(other), tuple(sorted(env.items())))


def _covers(pre, ci):
    """Whether pre-push's clippy key `pre` lints everything CI's `ci` does, the same way."""
    return pre[0] == ci[0] and pre[1] == ci[1] and pre[2] >= ci[2] and pre[3:] == ci[3:]


def _clippy_words(words):
    """`(prefix env, words after clippy)` when `words` run cargo clippy, else None.
    Raises ValueError for a subcommand the scan cannot read (an expression)."""
    env = {}
    if words[:1] == ["env"]:
        words = words[1:]
    while words and workflow_shell.ASSIGN.match(words[0]):
        name, _, value = words[0].partition("=")
        env[name], words = value, words[1:]
    if words[:1] != ["cargo"]:
        return None
    i, globals_ = 1, []
    while i < len(words) and (words[i].startswith("+") or words[i].startswith("-")):
        globals_.append(words[i])
        if words[i] in CARGO_VALUE_OPTIONS and i + 1 < len(words):
            globals_.append(words[i + 1])
            i += 1
        i += 1
    if i < len(words) and "${{" in words[i]:
        raise ValueError(f"cargo subcommand is an expression: {' '.join(words)}")
    if i < len(words) and words[i] == "clippy":
        return env, [g for g in globals_ if not g.startswith("+")] + words[i + 1:]
    return None


def _shell_commands(text):
    """Every simple command in shell `text` as shlex words (continuations joined)."""
    for raw in workflow_shell.heredocs_dropped(text.replace("\\\n", " ").splitlines()):
        for piece in workflow_shell._chains(raw):
            for stage in workflow_shell._pipe_stages(piece):
                yield stage


def pre_push_clippy(root: pathlib.Path) -> list[tuple[list[str], dict]]:
    """pre-push.sh's clippy steps: (words after `clippy`, exported env at that line)."""
    found, env = [], {}
    for stage in _shell_commands((root / "scripts/dev/pre-push.sh").read_text()):
        try:
            words = shlex.split(stage, comments=True)
        except ValueError:
            continue
        if words[:1] == ["export"]:
            for item in words[1:]:
                name, eq, value = item.partition("=")
                if eq:
                    env[name] = value
        elif words[:1] == ["unset"]:
            for name in words[1:]:
                env.pop(name, None)
        elif words[:1] == ["run_cargo"] and len(words) > 2 and words[2] == "clippy":
            found.append((words[3:], dict(env)))
    return found


def _ci_clippy(root):
    """(workflow, command text, words after clippy, env) for every clippy command a
    PR workflow's pedantic job runs; an unreadable one is (workflow, text, None, error)."""
    found = []
    seen = set()
    for workflow in pr_workflows(root):
        for path, wf_env, job, names, step in _job_steps(root, workflow, seen):
            if "pedantic" not in names.lower() or not isinstance(step, dict) or not step.get("run"):
                continue
            base_env = {**wf_env, **(job.get("env") or {}), **(step.get("env") or {})}
            for stage in _shell_commands(str(step["run"])):
                stage = " ".join(stage.split())
                if "cargo" not in stage:  # not "clippy": `cargo ${{ matrix.cmd }}` must be read
                    continue
                try:
                    hit = _clippy_words(shlex.split(stage))
                except ValueError as err:
                    found.append((path.name, stage, None, str(err)))
                    continue
                if hit:
                    found.append((path.name, stage, hit[1], {**base_env, **hit[0]}))
    return found


def clippy_problems(root: pathlib.Path) -> list[str]:
    """A pedantic-job clippy command no pre-push clippy step covers, or cannot read, named."""
    pre_push = root / "scripts/dev/pre-push.sh"
    pre = [_clippy_key(w, e) for w, e in pre_push_clippy(root)] if pre_push.exists() else []
    problems = []
    for name, text, words, env in _ci_clippy(root):
        if words is None:
            problems.append(f"cannot read CI clippy command ({name}): {text}: {env}")
            continue
        ci = _clippy_key(words, env)
        if not any(_covers(p, ci) for p in pre):
            conf = dict(ci[5]).get("CLIPPY_CONF_DIR")
            where = f" [CLIPPY_CONF_DIR={conf}]" if conf else ""
            problems.append(f"pre-push runs no clippy covering CI's: {text}{where} ({name})")
    return problems


def rust_targets(root: pathlib.Path) -> list[str]:
    """Test targets whose sources read docs/ or the CLI definition (§7)."""
    names = []
    for target in sorted((root / "tests").glob("*.rs")):
        if any(RUST_READS.search(s.read_text(errors="replace")) for s in _sources(target)):
            names.append(target.stem)
    return names


def rust_drift(root: pathlib.Path) -> list[str]:
    """The derived Rust target set against RUST_TARGETS, run on the push path (R3)."""
    derived = set(rust_targets(root))
    return [f"Rust target reads docs/CLI but is not pinned in RUST_TARGETS: {t}" for t in sorted(derived - RUST_TARGETS)] + [
        f"Rust target pinned in RUST_TARGETS is no longer derived: {t}" for t in sorted(RUST_TARGETS - derived)
    ]


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
        self.t.workflow("ci.yml", pr_job('# python3 scripts/m.py\necho "scripts/m.py"\npython3 scripts/n.py'))
        self.assertEqual(scripts_of(scanned_forms(self.t.root)), {"scripts/n.py"})
        # Under the completeness guard any other mention fails closed, named.
        self.t.workflow("ci.yml", pr_job("grep -q scripts/m.py README.md || true\npython3 scripts/n.py"))
        found = problems(self.t.root, ci_only={})
        self.assertTrue(any("unsupported" in p and "scripts/m.py" in p for p in found), found)

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
        self.assertEqual(workflow_shell._walk("echo '$(python3 scripts/q.py)'"), [])
        # The guard still counts the python word: data that names Python fails closed.
        with self.assertRaises(workflow_shell.UnsupportedSyntax):
            workflow_shell.executions("echo '$(python3 scripts/q.py)'")

    # D19 (impl r1 F4): a quoted argument with a space stays one argument;
    # an unbalanced quote fails closed.
    def test_d19_a_quoted_argument_is_one_word(self):
        found = workflow_shell.executions('python3 scripts/r.py "two words" x')
        self.assertEqual([e.args for e in found], [("two words", "x")])
        with self.assertRaises(workflow_shell.UnsupportedSyntax):
            workflow_shell.executions('python3 scripts/r.py "open')

    # D25 (impl r2, gpt + grok): one quote-aware reading of the shell. Each
    # case is a form the r2 seats reproduced as missed or merged.
    def test_d25_the_walker_reads_quotes_escapes_and_substitutions_as_the_shell_does(self):
        def forms(text):
            return [(e.script, e.args) for e in workflow_shell.executions(text)]

        cases = {
            # adjacent quoted text is one word; separate words stay two
            'python3 scripts/a.py "foo"bar': [("scripts/a.py", ("foobar",))],
            "python3 scripts/a.py foo bar": [("scripts/a.py", ("foo", "bar"))],
            # a single quote inside double quotes does not hide a substitution
            "echo \"it's $(python3 scripts/b.py) here's\"": [("scripts/b.py", ())],
            # an escaped double quote does not end the quoted word
            "printf '%s' \"a\\\"b\" | python3 scripts/c.py": [("scripts/c.py", ())],
            # nested substitutions: the outer and the inner command both run
            'echo "$(python3 scripts/outer.py $(python3 scripts/inner.py))"':
                [("scripts/inner.py", ()), ("scripts/outer.py", ())],
            # `env` and quoted assignment prefixes are peeled off
            "env FOO=x python3 scripts/d.py": [("scripts/d.py", ())],
            'FOO="a b" python3 scripts/e.py': [("scripts/e.py", ())],
            # a chain operator inside a substitution does not split the command
            'v="$(true && python3 scripts/f.py)"': [("scripts/f.py", ())],
        }
        for text, expected in cases.items():
            with self.subTest(text=text):
                self.assertEqual(sorted(forms(text)), sorted(expected))
        with self.assertRaises(workflow_shell.UnsupportedSyntax):
            workflow_shell.executions("env -i python3 scripts/g.py")

    # D26 (MIK-8733.REL.3, r3b): every clippy command the pedantic job runs is
    # covered by a pre-push clippy step that lints the same code the same way;
    # each dimension of "the same way" is broken once and must be named.
    def test_d26_a_pedantic_clippy_command_pre_push_lacks_is_named(self):
        ci = (
            "on:\n  pull_request:\nenv:\n  RUSTFLAGS: -Dwarnings\njobs:\n  check:\n    name: Clippy (pedantic)\n"
            "    runs-on: ubuntu-latest\n    steps:\n"
            "      - run: cargo clippy --all-targets --all-features -- -D warnings\n"
            "      - env:\n          CLIPPY_CONF_DIR: ${{ github.workspace }}/lint/ban\n"
            "        run: |\n"
            "          cargo +stable clippy --release --lib \\\n"
            "            --bins --all-features -- -D warnings\n"
            "          cargo --locked clippy -p a --exclude b -- -D warnings\n"
        )
        self.t.workflow("ci.yml", ci)
        good = (
            'run_cargo "all" clippy --all-targets --all-features --quiet -- -D warnings\n'
            'export CLIPPY_CONF_DIR="$REPO_ROOT/lint/ban"\n'
            'run_cargo "rel" clippy --release --lib --bins --all-features --quiet -- -D warnings\n'
            'run_cargo "pkg" clippy -p a --exclude b --quiet -- -D warnings\n'
            "unset CLIPPY_CONF_DIR\n"
        )
        self.t.pre_push(good)
        self.assertEqual([p for p in problems(self.t.root, ci_only={}) if "clippy" in p], [])
        rel = "cargo +stable clippy --release --lib --bins --all-features -- -D warnings [CLIPPY_CONF_DIR=lint/ban] (ci.yml)"
        pkg = "cargo --locked clippy -p a --exclude b -- -D warnings [CLIPPY_CONF_DIR=lint/ban] (ci.yml)"
        broken = {
            "config dir not exported": (good.replace('export CLIPPY_CONF_DIR="$REPO_ROOT/lint/ban"\n', ""), [rel, pkg]),
            "feature mode differs": (good.replace("--release --lib --bins --all-features", "--release --lib --bins --no-default-features"), [rel]),
            "a lint suppressed": (good.replace("--all-features --quiet -- -D warnings\nrun_cargo \"pkg\"", "--all-features --quiet -- -D warnings -A warnings\nrun_cargo \"pkg\""), [rel]),
            "fewer targets": (good.replace("--release --lib --bins", "--release --lib"), [rel]),
            "debug profile": (good.replace("clippy --release --lib", "clippy --lib"), [rel]),
            "flags swapped": (good.replace("-p a --exclude b", "-p b --exclude a"), [pkg]),
        }
        for label, (text, expected) in broken.items():
            with self.subTest(label):
                self.t.pre_push(text)
                found = [p for p in problems(self.t.root, ci_only={}) if "clippy" in p]
                self.assertEqual(sorted(found), sorted(f"pre-push runs no clippy covering CI's: {e}" for e in expected))
        # A command with no target flag lints lib + bins: a tests-only step does not cover it.
        self.t.workflow("ci.yml", ci.replace("cargo clippy --all-targets --all-features", "cargo clippy --all-features"))
        self.t.pre_push(good.replace("clippy --all-targets --all-features", "clippy --tests --all-features"))
        self.assertIn("pre-push runs no clippy covering CI's: cargo clippy --all-features -- -D warnings (ci.yml)",
                      problems(self.t.root, ci_only={}))
        # A subcommand the scan cannot read is named, never dropped.
        self.t.workflow("ci.yml", ci.replace("cargo --locked clippy", "cargo ${{ matrix.cmd }}"))
        self.t.pre_push(good)
        self.assertTrue(any(p.startswith("cannot read CI clippy command") for p in problems(self.t.root, ci_only={})))

    # D27 (lead ruling 2026-10-23): each of r3's fail-open shapes is now
    # UnsupportedSyntax, named with its step, instead of no execution at all.
    def test_d27_r3_fail_open_shapes_fail_closed_naming_the_step(self):
        self.t.script("scripts/x.py")
        shapes = {
            "multi-line substitution": "out=$(python3 scripts/x.py\n)",
            "bare ampersand": "echo done & python3 scripts/x.py",
            "time prefix": "time python3 scripts/x.py",
            "nohup prefix": "nohup python3 scripts/x.py",
            "subshell": "(python3 scripts/x.py)",
            "case arm": "case x in *) python3 scripts/x.py ;; esac",
            "process substitution": "cat <(python3 scripts/x.py)",
            "xargs": "echo scripts/x.py | xargs -I{} python3 {}",
            "ansi-c quote": "python3 $'scripts/x.py'",
            "unquoted heredoc": "cat <<EOF\n$(python3 scripts/x.py)\nEOF",
        }
        for label, run in shapes.items():
            with self.subTest(label):
                self.t.workflow("ci.yml", pr_job(run).replace("      - run:", "      - name: shape step\n        run:", 1))
                found = problems(self.t.root, ci_only={})
                self.assertTrue(any(p.startswith("unsupported execution syntax in ci.yml step 'shape step'") for p in found), found)

    # D28 (lead ruling 2026-10-23): a `.py` path run by something other than a
    # python word is named, not lost.
    def test_d28_a_py_path_run_without_a_python_word_is_named(self):
        for run in ("$PY scripts/x.py", "${{ env.PYTHON }} scripts/x.py", "uv run scripts/x.py"):
            with self.subTest(run):
                with self.assertRaises(workflow_shell.UnsupportedSyntax) as caught:
                    workflow_shell.executions(run)
                self.assertIn("scripts/x.py", str(caught.exception))

    # D29 (lead ruling 2026-10-23): the guard's exceptions are closed lists.
    def test_d29_the_guards_exception_lists_are_closed(self):
        self.assertEqual(workflow_shell.LOOKUPS, ("command -v", "which", "type", "hash"))
        self.assertEqual(workflow_shell.DATA_COMMANDS, ("echo", "printf"))
        for lookup in ("command -v python3", "which python3", "type python3", "hash python3"):
            with self.subTest(lookup):
                self.assertEqual(workflow_shell.executions(lookup), [])
        self.assertEqual(workflow_shell.executions('echo "see scripts/x.py"'), [])
        # DATA_COMMANDS exempts only the path class: python words in or after
        # echo text still count, so piping echo into python or bash still raises.
        for piped in ("echo scripts/x.py | xargs python3", "echo 'python3 scripts/x.py' | bash"):
            with self.subTest(piped):
                with self.assertRaises(workflow_shell.UnsupportedSyntax) as caught:
                    workflow_shell.executions(piped)
                self.assertIn("python command(s)", str(caught.exception))
        for not_a_lookup in ("whereis python3", "command python3 -V", "ls python3"):
            with self.subTest(not_a_lookup):
                with self.assertRaises(workflow_shell.UnsupportedSyntax):
                    workflow_shell.executions(not_a_lookup)

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
        self.t.run_list("python3 scripts/k.py ${{secrets.X}}\t1\tclosed")
        found = problems(self.t.root, ci_only={})
        self.assertFalse(any(p.startswith("in no bucket") for p in found), found)
        self.assertTrue(any(p.startswith("untranslated CI token") and "secrets.X" in p for p in found), found)

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
        found = workflow_shell.executions(
            "if python3 scripts/i.py; then python3 scripts/j.py; fi\n"
            "while python3 scripts/k.py; do break; done\n! python3 scripts/l.py\n"
        )
        self.assertEqual([e.script for e in found], ["scripts/i.py", "scripts/j.py", "scripts/k.py", "scripts/l.py"])
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


    # D20 (impl r1 F13): a `.yaml` workflow is scanned like a `.yml` one.
    def test_d20_a_yaml_extension_workflow_is_scanned(self):
        self.t.script("scripts/y.py")
        self.t.workflow("other.yaml", pr_job("python3 scripts/y.py"))
        self.assertEqual(scripts_of(scanned_forms(self.t.root)), {"scripts/y.py"})

    # D21 (impl r1 F5): a pipeline is part of the form; dropping a stage is drift.
    def test_d21_a_run_line_missing_the_ci_pipeline_stage_is_drift(self):
        self.t.script("scripts/g.py")
        self.t.workflow("ci.yml", pr_job("python3 scripts/g.py | cmp - f.json"))
        self.t.run_list("python3 scripts/g.py | cmp - f.json\t1\tclosed")
        self.assertEqual(problems(self.t.root, ci_only={}), [])
        self.t.run_list("python3 scripts/g.py\t1\tclosed")
        found = problems(self.t.root, ci_only={})
        self.assertTrue(any(p.startswith("in no bucket") and "cmp - f.json" in p for p in found), found)
        self.assertTrue(any(p.startswith("stale RUN line") for p in found), found)

    # D22 (impl r1 F12): a braced runner variable is an untranslated token.
    def test_d22_a_braced_runner_variable_is_untranslated(self):
        self.t.script("scripts/v.py")
        self.t.workflow("ci.yml", pr_job('python3 scripts/v.py "${RUNNER_OS}"'))
        self.t.run_list("python3 scripts/v.py ${RUNNER_OS}\t1\tclosed")
        found = problems(self.t.root, ci_only={})
        self.assertTrue(any(p.startswith("untranslated CI token") and "RUNNER_OS" in p for p in found), found)

    # D24 (grok I3): a `for x in <glob>` loop matching no file is drift, not zero suites.
    def test_d24_a_suite_glob_matching_nothing_is_drift(self):
        self.t.workflow("ci.yml", pr_job('for s in scripts/none/test_*.py; do python3 "$s"; done'))
        found = problems(self.t.root, ci_only={})
        self.assertTrue(any(p.startswith("glob matches no file") and "scripts/none/test_*.py" in p for p in found), found)


class Repository(unittest.TestCase):
    # R1
    def test_r1_every_executed_form_has_one_bucket(self):
        names = sorted(p.name for p in pr_workflows(REPO))
        self.assertEqual(
            names,
            sorted([
                "alert-rules.yml", "c6-obligations.yml", "changelog.yml", "ci.yml", "coverage-probe.yml",
                "dependabot-auto-merge.yml", "docker.yml", "mrtr7b-full-burst.yml", "pr-body-hygiene.yml",
                "registry-packages.yml", "rustdoc.yml", "ui-tests.yml",
            ]),
        )
        self.assertEqual(problems(REPO), [])
        # MIK-8733.REL.1/3: the scan sees all five pedantic clippy commands (so
        # "clean" is not vacuous), and the release pair under the registry-ban
        # config is covered by pre-push's (problems() above is empty).
        ci = _ci_clippy(REPO)
        self.assertEqual(len(ci), 5, [c[1] for c in ci])
        self.assertEqual(sum("--release" in c[1] and "registry-ban" in str(c[3].get("CLIPPY_CONF_DIR")) for c in ci), 2)
        # The gate's own suites run in CI (lead 2026-10-23): the scanner suite
        # also in pre-push (ALREADY), the runner suite in CI only (budget).
        _, already, ci_only = buckets(REPO)
        scanner, runner_suite = ("scripts/dev/test_prepush_ci_checks.py", ()), ("scripts/dev/test_run_prepush_ci_checks.py", ())
        self.assertIn(scanner, scanned_forms(REPO))
        self.assertIn(runner_suite, scanned_forms(REPO))
        self.assertIn(scanner, already)
        self.assertNotIn(runner_suite, already)
        self.assertTrue(ci_only.get(runner_suite, "").startswith("budget:"), ci_only.get(runner_suite))

    # R2
    def test_r2_rust_targets_are_derived_from_sources(self):
        self.assertEqual(set(rust_targets(REPO)), RUST_TARGETS)
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "tests").mkdir()
            (root / "tests/only_parse_from.rs").write_text('fn t(){ let _ = Cli::parse_from(["x"]); }\n')
            (root / "tests/unrelated.rs").write_text("fn t(){}\n")
            self.assertEqual(rust_targets(root), ["only_parse_from"])

    # D23 (impl r1 F9): a target whose docs read sits in a `#[path]` or `mod`
    # file outside tests/<stem>/ is derived.
    def test_d23_path_and_mod_sources_outside_the_stem_dir_count(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "tests/common").mkdir(parents=True)
            (root / "tests/common/reads.rs").write_text('pub fn r(){ let _ = std::fs::read("docs/x.md"); }\n')
            (root / "tests/helper.rs").write_text('pub fn h(){ let _ = std::fs::read("docs/y.md"); }\n')
            (root / "tests/via_path.rs").write_text('#[path = "common/reads.rs"]\nmod reads;\nfn t(){}\n')
            (root / "tests/via_mod.rs").write_text("mod helper;\nfn t(){}\n")
            (root / "tests/plain.rs").write_text("fn t(){}\n")
            # A plain `mod` inside a `#[path]` file resolves beside it (r2 gpt).
            (root / "tests/lib2").mkdir()
            (root / "tests/lib2/outer.rs").write_text("mod deeper;\n")
            (root / "tests/lib2/deeper.rs").write_text('pub fn d(){ let _ = std::fs::read("docs/w.md"); }\n')
            (root / "tests/via_deep.rs").write_text('#[path = "lib2/outer.rs"]\nmod outer;\nfn t(){}\n')
            # `include!` pulls a file in textually (r3 gpt).
            (root / "tests/inc").mkdir()
            (root / "tests/inc/reader.rs").write_text('fn r(){ let _ = std::fs::read("docs/v.md"); }\n')
            (root / "tests/via_include.rs").write_text('include!("inc/reader.rs");\nfn t(){}\n')
            # One file reached in two module contexts: its `mod` children
            # resolve differently in each, so both are followed (r3 gpt).
            (root / "tests/two").mkdir()
            (root / "tests/two/helper").mkdir()
            (root / "tests/two/helper.rs").write_text("mod child;\n")
            (root / "tests/two/helper/child.rs").write_text('fn c(){ let _ = std::fs::read("docs/u.md"); }\n')
            (root / "tests/via_two.rs").write_text('#[path = "two/helper.rs"]\nmod a;\nmod two { mod helper; }\nfn t(){}\n')
            self.assertEqual(rust_targets(root), ["helper", "via_deep", "via_include", "via_mod", "via_path", "via_two"])

    # R3 (impl r1 F10): the push path checks the derived Rust set against the
    # pinned one, so a derivation regression stops the push, not only this suite.
    def test_r3_the_rust_target_set_is_checked_on_the_push_path(self):
        self.assertEqual(rust_drift(REPO), [])
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "tests").mkdir()
            (root / "tests/new_doc_reader.rs").write_text('fn t(){ let _ = std::fs::read("docs/z.md"); }\n')
            found = rust_drift(root)
            self.assertTrue(any("new_doc_reader" in p for p in found), found)
            self.assertTrue(any("cli_surface_inventory" in p for p in found), found)


if __name__ == "__main__":
    unittest.main()

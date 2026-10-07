#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Routing check for the throwaway test run and the mutant batch.

Evaluates each job's `if:` for representative events, with the repository
variable MCPGW_TRUSTED_RUNNER unset and set to `ready`, and asserts:
  * unset  -> exactly one throwaway test job runs, on a GitHub-hosted label;
  * ready  -> exactly one runs, on the trusted self-hosted label;
  * the self-hosted label is never reachable from a fork, a non-throwaway
    branch, a PR into main, or a push;
  * both variants run identical steps.
The same holds for the linux leg of the mutant batch.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
TRUSTED = "mcpgw-trusted-arm64"
REPO = "MikkoParkkola/mcp-gateway"
RELEASE_LINE = "docs/ranking-1-release-line"


def evaluate(expr: str, ctx: dict) -> bool:
    """A small evaluator for the expression subset these conditions use."""
    expr = expr.strip()
    if expr.startswith("${{") and expr.endswith("}}"):
        expr = expr[3:-2].strip()

    def lookup(path: str):
        cur = ctx
        for part in path.split("."):
            cur = cur.get(part) if isinstance(cur, dict) else None
        return cur

    tokens = re.findall(r"startsWith|contains|\(|\)|,|&&|\|\||==|!=|!|'[^']*'|[A-Za-z_][\w.\-]*", expr)
    status = ctx.get("_status", {})
    pos = 0

    def peek():
        return tokens[pos] if pos < len(tokens) else None

    def take():
        nonlocal pos
        pos += 1
        return tokens[pos - 1]

    def primary():
        t = take()
        if t == "(":
            v = disj()
            assert take() == ")"
            return v
        if t == "!":
            return not primary()
        if t == "startsWith":
            assert take() == "("
            a = disj()
            assert take() == ","
            b = disj()
            assert take() == ")"
            return str(a or "").lower().startswith(str(b).lower())
        if t == "contains":
            assert take() == "("
            a = disj()
            assert take() == ","
            b = disj()
            assert take() == ")"
            return str(b).lower() in str(a or "").lower()
        if t in ("cancelled", "always", "success", "failure") and peek() == "(":
            take()
            assert take() == ")"
            return {"always": True}.get(t, status.get(t, t == "success"))
        if t.startswith("'"):
            return t[1:-1]
        if t in ("true", "false"):
            return t == "true"
        return lookup(t)

    def comparison():
        left = primary()
        while peek() in ("==", "!="):
            op = take()
            right = primary()
            eq = (left or "") == (right or "")
            left = eq if op == "==" else not eq
        return left

    def conj():
        v = comparison()
        while peek() == "&&":
            take()
            r = comparison()
            v = bool(v) and bool(r)
        return v

    def disj():
        v = conj()
        while peek() == "||":
            take()
            r = conj()
            v = bool(v) or bool(r)
        return v

    result = disj()
    assert pos == len(tokens), f"unparsed tail in {expr!r}"
    return bool(result)


def event(kind: str, var: str | None) -> dict:
    pr = {"head": {"repo": {"full_name": REPO}}}
    g = {"repository": REPO, "event_name": "pull_request", "base_ref": RELEASE_LINE,
         "head_ref": "throwaway/x", "event": {"pull_request": pr}}
    if kind == "fork":
        pr["head"]["repo"]["full_name"] = "someone/fork"
    elif kind == "branch":
        g["head_ref"] = "feature/x"
    elif kind == "into-main":
        g["base_ref"] = "main"
    elif kind == "push":
        g.update(event_name="push", base_ref="", head_ref="", event={})
    return {"github": g, "vars": {"MCPGW_TRUSTED_RUNNER": var} if var else {},
            "needs": {"plan": {"outputs": {"has_linux": "true"}}}}


def check(workflow: str, name: str, rc: list) -> None:
    jobs = yaml.safe_load((ROOT / ".github/workflows" / workflow).read_text())["jobs"]
    group = {k: j for k, j in jobs.items() if j.get("name") == name}
    if len(group) != 2:
        rc.append(f"{workflow}: expected two '{name}' jobs, found {sorted(group)}")
        return
    steps = [yaml.safe_dump(j.get("steps")) for j in group.values()]
    if steps[0] != steps[1]:
        rc.append(f"{workflow}: the two '{name}' jobs run different steps")
    kinds = ("throwaway", "fork", "branch", "into-main", "push")
    if workflow == "mutants.yml":
        kinds = ("throwaway",)  # push-triggered only; admission is the runner hook
    for var in (None, "ready"):
        for kind in kinds:
            ctx = event(kind, var)
            labels = [j["runs-on"] for j in group.values() if evaluate(str(j.get("if", "true")), ctx)]
            want_run = kind == "throwaway"
            if not want_run:
                if labels:
                    rc.append(f"{workflow}: '{name}' runs for a {kind} event (var={var}): {labels}")
                continue
            if len(labels) != 1:
                rc.append(f"{workflow}: '{name}' runs {len(labels)} times for var={var}: {labels}")
                continue
            hosted = re.match(r"^(ubuntu|windows|macos)-", labels[0]) is not None
            if var is None and not hosted:
                rc.append(f"{workflow}: with the variable unset '{name}' runs on {labels[0]}")
            if var == "ready" and labels[0] != TRUSTED:
                rc.append(f"{workflow}: with the variable ready '{name}' runs on {labels[0]}")


def only_throwaway_tests(rc: list) -> None:
    """A same-repo throwaway PR into the release line runs exactly one ci.yml
    job, `Tests (throwaway)`: every other job must skip it, or each red-first
    and mutant PR pays for extra hosted builds. Jobs are resolved in
    dependency order with GitHub's rules, so a job that runs only because a
    dependency (including the throwaway test job itself) succeeded is caught."""
    jobs = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())["jobs"]
    # A started job may succeed or fail; a downstream job can react to either
    # (`if: failure()`), so both outcomes are resolved and their runs combined.
    for var, outcome in ((v, o) for v in (None, "ready") for o in ("success", "failure")):
        base = event("throwaway", var)
        base["inputs"] = {}
        result: dict[str, str] = {}
        # failure() is true when any ancestor failed, not only a direct need.
        failed_upstream: dict[str, bool] = {}

        def resolve(name, stack=()):
            if name in result:
                return result[name]
            job = jobs[name]
            needs = job.get("needs") or []
            needs = [needs] if isinstance(needs, str) else needs
            for n in needs:
                resolve(n, stack + (name,))
            declared = {n: {"result": result[n], "outputs": {}} for n in needs}
            ok = all(result[n] == "success" for n in needs)
            # Only declared dependencies exist in `needs`, as on GitHub.
            ctx = dict(base, needs=declared,
                       _status={"cancelled": False, "success": ok,
                                "failure": any(result[n] == "failure" or failed_upstream[n] for n in needs)})
            cond = str(job.get("if", ""))
            if not cond:
                runs = ok
            elif not re.search(r"\b(cancelled|always|success|failure)\s*\(", cond) and not ok:
                runs = False
            else:
                runs = evaluate(cond, ctx)
            result[name] = outcome if runs else "skipped"
            failed_upstream[name] = any(result[n] == "failure" or failed_upstream[n] for n in needs)
            return result[name]

        for name in jobs:
            resolve(name)
        ran = sorted(n for n, r in result.items() if r != "skipped")
        names = sorted({jobs[n].get("name", n) for n in ran})
        if names != ["Tests (throwaway)"] or len(ran) != 1:
            rc.append(f"ci.yml: a throwaway PR (var={var}, jobs {outcome}) runs {ran}, expected only Tests (throwaway)")


# Jobs a throwaway PR skips (MIK-8067): (workflow, job id, job name, opt-in).
# A head whose name holds the opt-in word still runs the job, so a red proof
# for that job keeps it. Names are required-check contexts and must not move.
HEAVY = (
    ("docker.yml", "scope", "Decide whether to build the image", None),
    ("docker.yml", "build-gate", "build", None),
    ("alert-rules.yml", "promtool", "Alert rules (promtool)", "promtool"),
    ("rustdoc.yml", "rustdoc", "Rustdoc intra-doc links (MIK-8008)", "rustdoc"),
)


def heavy_jobs_skip_throwaway(rc: list) -> None:
    """Image, alert-rule and rustdoc jobs skip a same-repo throwaway PR into
    the release line, run for every other event, and run for a throwaway
    head that names their opt-in word."""
    for workflow, job_id, name, opt_in in HEAVY:
        job = yaml.safe_load((ROOT / ".github/workflows" / workflow).read_text())["jobs"].get(job_id)
        if not job or job.get("name") != name:
            rc.append(f"{workflow}: job {job_id} missing or renamed from {name!r}")
            continue
        cond = str(job.get("if", "true"))
        for kind in ("throwaway", "fork", "branch", "into-main", "push"):
            ctx = event(kind, None)
            ctx["needs"] = {}
            if evaluate(cond, ctx) == (kind == "throwaway"):
                want = "skip" if kind == "throwaway" else "run"
                rc.append(f"{workflow}: {job_id} does not {want} for a {kind} event")
        if opt_in:
            ctx = event("throwaway", None)
            ctx["github"]["head_ref"] = f"throwaway/{opt_in}-red-1"
            if not evaluate(cond, ctx):
                rc.append(f"{workflow}: {job_id} skips a throwaway head naming {opt_in!r}")


def main() -> int:
    rc: list[str] = []
    check("ci.yml", "Tests (throwaway)", rc)
    only_throwaway_tests(rc)
    heavy_jobs_skip_throwaway(rc)
    check("mutants.yml", "Mutants (linux)", rc)
    for line in rc:
        print(f"routing: {line}", file=sys.stderr)
    if not rc:
        print("routing: throwaway tests and linux mutant rows resolve to hosted (unset) / trusted (ready)")
    return 1 if rc else 0


if __name__ == "__main__":
    sys.exit(main())

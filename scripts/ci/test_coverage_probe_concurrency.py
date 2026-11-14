#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Pins which Coverage probe runs share a concurrency group.

Release-line pushes share ONE group with cancel-in-progress false, so a burst of merges grades its first and its newest push
(GitHub keeps one running and one pending run per group, and a newer pending run replaces an older one). A pull request keeps a
group per ref and cancels its older run. Everything else, above all the throwaway/coverage-* push that is the C5 grade of
record and any workflow_dispatch (even one on the release-line ref), has a group of its own, so it is never replaced.

The workflow's `group:` and `cancel-in-progress:` expressions are evaluated here with a small evaluator of the GitHub
expression subset they use (`&&`, `||`, `==`, parentheses, string literals, github.* contexts; `&&` and `||` return
operands, not booleans, as in Actions). `--self-test` checks the evaluator alone. Standard library only.
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

# COVERAGE_PROBE_WORKFLOW points the rows at a changed copy of the workflow (the mutants that prove the rows can fail).
WORKFLOW = Path(os.environ.get("COVERAGE_PROBE_WORKFLOW") or Path(__file__).resolve().parents[2] / ".github" / "workflows" / "coverage-probe.yml")
LINE = "refs/heads/docs/ranking-1-release-line"


def tokenize(src: str) -> list[str]:
    toks = re.findall(r"'(?:[^']|'')*'|&&|\|\||==|!=|\(|\)|[A-Za-z_][A-Za-z0-9_.]*|true|false", src)
    if "".join(toks) != re.sub(r"\s+", "", src):
        raise ValueError(f"cannot tokenize {src!r}")
    return toks


def truthy(v) -> bool:
    return v not in ("", False, 0, None)


def evaluate(expr: str, ctx: dict[str, str]):
    toks = tokenize(expr)
    pos = 0

    def peek():
        return toks[pos] if pos < len(toks) else None

    def take():
        nonlocal pos
        pos += 1
        return toks[pos - 1]

    def primary():
        t = take()
        if t == "(":
            v = or_expr()
            assert take() == ")", "missing )"
            return v
        if t.startswith("'"):
            return t[1:-1].replace("''", "'")
        if t in ("true", "false"):
            return t == "true"
        return ctx[t]

    def eq():
        left = primary()
        if peek() in ("==", "!="):
            op = take()
            right = primary()
            same = str(left).lower() == str(right).lower()
            return same if op == "==" else not same
        return left

    def and_expr():
        v = eq()
        while peek() == "&&":
            take()
            right = eq()
            v = right if truthy(v) else v
        return v

    def or_expr():
        v = and_expr()
        while peek() == "||":
            take()
            right = and_expr()
            v = v if truthy(v) else right
        return v

    out = or_expr()
    assert pos == len(toks), f"trailing tokens in {expr!r}"
    return out


def interpolate(template: str, ctx: dict[str, str]) -> str:
    """`prefix-${{ expr }}` or `${{ expr }}` to its value as Actions renders it (booleans as true/false)."""
    def sub(m):
        v = evaluate(m.group(1), ctx)
        return {True: "true", False: "false"}.get(v, str(v)) if isinstance(v, bool) else str(v)
    return re.sub(r"\$\{\{(.*?)\}\}", sub, template)


def workflow_expressions() -> tuple[str, str]:
    text = WORKFLOW.read_text()
    m = re.search(r"^concurrency:\s*\n\s+group:\s*(.+?)\n\s+cancel-in-progress:\s*(.+?)\s*$", text, re.M | re.S)
    # The group expression may continue on following indented lines; join them up to cancel-in-progress.
    block = re.search(r"^concurrency:\s*\n(.*?)(?=^\S)", text, re.M | re.S)
    if not m or not block:
        raise SystemExit("coverage-probe.yml: no concurrency block")
    body = block.group(1)
    g = re.search(r"group:\s*(.*?)\s*\n\s+cancel-in-progress:", body, re.S).group(1)
    c = re.search(r"cancel-in-progress:\s*(.+?)\s*$", body, re.S).group(1)
    g = re.sub(r"^[>|][-+]?\s*", "", g)  # a folded scalar's marker; its lines are joined by single spaces
    return re.sub(r"\s*\n\s*", " ", g), c.strip()


def ctx(event: str, ref: str, run_id: str) -> dict[str, str]:
    return {"github.event_name": event, "github.ref": ref, "github.run_id": run_id}


def rows(group_t: str, cancel_t: str) -> int:
    wrong = 0

    def check(label, got, want):
        nonlocal wrong
        ok = got == want
        wrong += not ok
        print(f"{'ok   ' if ok else 'WRONG'} {label}" + ("" if ok else f": got {got!r}, want {want!r}"))

    def g(event, ref, run_id):
        return interpolate(group_t, ctx(event, ref, run_id))

    def c(event, ref, run_id):
        return interpolate(cancel_t, ctx(event, ref, run_id))

    pr = lambda n, run: ("pull_request", f"refs/pull/{n}/merge", run)
    check("a pull request's group is its ref", g(*pr(9, "1")), "coverage-probe-refs/pull/9/merge")
    check("a newer run of the same pull request shares it", g(*pr(9, "1")) == g(*pr(9, "2")), True)
    check("two pull requests do not share", g(*pr(9, "1")) == g(*pr(10, "1")), False)
    check("a pull request cancels its older run", c(*pr(9, "1")), "true")
    a, b = g("push", LINE, "100"), g("push", LINE, "200")
    check("two release-line pushes share one group", a == b, True)
    check("and it is not keyed by the run", "100" in a or "200" in b, False)
    check("a release-line push does not cancel the run in progress", c("push", LINE, "100"), "false")
    check("the release-line group is not a pull request's", a == g(*pr(9, "1")), False)
    t1, t2 = g("push", "refs/heads/throwaway/coverage-freeze-1", "300"), g("push", "refs/heads/throwaway/coverage-freeze-1", "301")
    check("two throwaway grade pushes never share (the C5 grade of record is never replaced)", t1 == t2, False)
    check("a throwaway grade push is not in the release-line group", t1 == a, False)
    check("a throwaway grade push does not cancel", c("push", "refs/heads/throwaway/coverage-x", "300"), "false")
    d1, d2 = g("workflow_dispatch", LINE, "400"), g("workflow_dispatch", LINE, "401")
    check("two dispatches on the release-line ref never share", d1 == d2, False)
    check("a dispatch on the release-line ref is not the release-line push group", d1 == a, False)
    check("a dispatch does not cancel", c("workflow_dispatch", LINE, "400"), "false")
    check("a dispatch on another ref has its own group", g("workflow_dispatch", "refs/heads/x", "500") == g("workflow_dispatch", "refs/heads/x", "501"), False)
    check("a push to another branch is not the release-line group", g("push", "refs/heads/other", "600") == a, False)
    return wrong


def self_test() -> int:
    wrong = 0

    def check(label, got, want):
        nonlocal wrong
        ok = got == want
        wrong += not ok
        print(f"{'ok   ' if ok else 'WRONG'} evaluator: {label}" + ("" if ok else f": got {got!r}, want {want!r}"))

    x = {"github.event_name": "push", "github.ref": "R", "github.run_id": "7"}
    check("&& returns the second operand when the first is truthy", evaluate("github.event_name == 'push' && github.ref", x), "R")
    check("&& returns the falsy first operand", evaluate("github.event_name == 'x' && github.ref", x), False)
    check("|| returns the first truthy operand", evaluate("'' || 'b' || 'c'", x), "b")
    check("|| falls through to the last", evaluate("'' || github.run_id", x), "7")
    check("&& binds tighter than ||", evaluate("false && 'a' || 'b'", x), "b")
    check("a && b || c when a and b are truthy", evaluate("true && 'a' || 'c'", x), "a")
    check("parentheses group", evaluate("(false || true) && 'z'", x), "z")
    check("== compares strings", evaluate("github.ref == 'R'", x), True)
    check("an empty string is falsy", truthy(""), False)
    check("a non-empty string is truthy", truthy("0.0") or truthy("x"), True)
    check("interpolation renders booleans as true/false", interpolate("${{ github.event_name == 'push' }}", x), "true")
    print(f"self-test: {wrong} wrong")
    return 1 if wrong else 0


def main() -> int:
    group_t, cancel_t = workflow_expressions()
    print(f"group:  {group_t}\ncancel: {cancel_t}")
    wrong = rows(group_t, cancel_t)
    print(f"coverage-probe concurrency: {wrong} wrong")
    return 1 if wrong else 0


if __name__ == "__main__":
    sys.exit(self_test() if sys.argv[1:] == ["--self-test"] else main())

#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Closed-world check for every CI step that writes a GitHub Actions cache.

Text only: expressions are split and compared, never evaluated, and no ref is sampled.
A missing optional key is skipped. The job ``if`` is never read; it can only narrow further.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]

LINE = "refs/heads/docs/ranking-1-release-line"
G = "(github.ref == 'refs/heads/docs/ranking-1-release-line' || github.ref == 'refs/heads/main')"
LINE_ONLY = "github.ref == 'refs/heads/docs/ranking-1-release-line'"
MAIN_ONLY = "github.ref == 'refs/heads/main'"
ACCEPTED = (G, LINE_ONLY, MAIN_ONLY)
BARE_G = G[1:-1]
MAIN_ONLY_STEP = ("docker.yml", "Build and push by digest (no tag)")
# The affected-tests map (scripts/ci/affected_map.py) is read by every lane PR's test legs, so one workflow alone
# saves its key, and only on a push to the release line: a dispatch, a PR or a push to main cannot plant a map.
MAP_KEY_PREFIX = "affected-map-"
MAP_WORKFLOW = "affected-map.yml"
MAP_PUSH = "github.event_name == 'push'"
MAP_MSG = f"only {MAP_WORKFLOW} saves the {MAP_KEY_PREFIX} key, on a release-line push: if: {LINE_ONLY} && {MAP_PUSH}"

PINS = {
    "aquasecurity/trivy-action": "ed142fd0673e97e23eac54620cfb913e5ce36c25",
    "docker/setup-buildx-action": "f87e5991a6d7451dcb8d9637bfbc97413f497069",
    "actions/setup-node": "949feb2413d6458794dcd2491c4babbbce0c15c1",
    "docker/build-push-action": "c3c9e263c25d99ce0380d002d59b67737d91b0dc",
}

# action -> (guard input or None when the action has no guard, warming)
WRITERS = {
    "Swatinem/rust-cache": ("save-if", True),
    "docker/build-push-action": ("cache-to", True),
    "actions/cache/save": (None, True),
    "astral-sh/setup-uv": ("save-cache", True),
}
COMBINED = "actions/cache"
EXCEPTION = "aquasecurity/trivy-action"
INERT = ("docker/setup-buildx-action", "actions/setup-node")
NON_WRITERS = frozenset({
    "actions/checkout",
    "actions/cache/restore",
    "actions/download-artifact",
    "actions/upload-artifact",
    "anchore/sbom-action/download-syft",
    "azure/setup-helm",
    "dependabot/fetch-metadata",
    "docker/login-action",
    "docker/metadata-action",
    "dtolnay/rust-toolchain",
    "github/codeql-action/analyze",
    "github/codeql-action/init",
    "google/osv-scanner-action/osv-scanner-action",
    "helm/kind-action",
    "model-checking/kani-github-action",
    "sigstore/cosign-installer",
    "softprops/action-gh-release",
    "trufflesecurity/trufflehog",
})
DANGEROUS = frozenset({"pull_request_target", "workflow_run"})
ACCEPTED_SET = frozenset(ACCEPTED)

CACHE_TO_FORM = '${CACHE_TO:+--cache-to "$CACHE_TO"}'
INERT_MSG = "combined restore+save switch now active: decide the guard (design section 5b)"
COMBINED_MSG = (
    "restore and save cannot be guarded apart; split into actions/cache/restore and actions/cache/save"
)
CLASSIFY_MSG = "classify this action: does it write a cache? (scripts/ci/cache_writers.py)"
PIN_MSG = "re-read the action at its new pin"
PAREN_MSG = f"write G in its parentheses: {G}"
OR_MSG = (
    "unanalysable top-level ||; write a conjunction, or use the cache-to idiom "
    "${{ <conjunction> && format('<spec>', <args>) || '' }}"
)
SKIP_SCRIPT = {
    "scripts/ci/cache_writers.py",
    "scripts/ci/test_docs_only_gating.py",
}

REF_RE = re.compile(r"\bgithub\.(?:head_ref|base_ref|ref)\b")
MATRIX_RE = re.compile(r"\$\{\{\s*matrix\.[A-Za-z_][A-Za-z0-9_-]*\s*\}\}")
FALSE_WRAP_RE = re.compile(r"\$\{\{\s*false\s*\}\}\Z", re.DOTALL)
EMPTY_WRAP_RE = re.compile(r"\$\{\{\s*''\s*\}\}\Z", re.DOTALL)
BAKE_RE = re.compile(r"\b(?:buildx|docker)\b.*\bbake\b")


def logical_lines(text: str) -> list[tuple[int, str]]:
    """Shell lines with backslash-newline continuations removed the way the shell removes them (the fragments join with
    no space added), each with the number of its first physical line, so a command split over several lines (kimi seat:
    `docker buildx \\` then `bake ...`; gpt seat: `ba\\` then `ke`) is matched as the one command it is. A line ending
    in an even number of backslashes ends in literal backslashes and is not continued. Quoting is not tracked: a
    trailing backslash inside single quotes or a quoted heredoc is taken as a continuation too, which can only refuse
    more (fail closed)."""
    out: list[tuple[int, str]] = []
    start, parts = 1, []
    for n, line in enumerate(text.splitlines(), 1):
        if not parts:
            start = n
        if (len(line) - len(line.rstrip("\\"))) % 2:
            parts.append(line[:-1])
            continue
        parts.append(line)
        out.append((start, "".join(parts)))
        parts = []
    if parts:
        out.append((start, "".join(parts)))
    return out
EXPORTER_MSG = (
    "an exporter (cache-to, CACHE_TO) must be the cache-to idiom, a plain exporter under a guarded step if, "
    "or empty; a boolean or a bare condition hands buildx a 'true' or 'false' exporter"
)
BAKE_MSG = "buildx bake reads cache-to from its bake file and --set flags, which this check cannot judge; classify it first"
ACTION_RE = re.compile(r"^\./\.github/actions/([^/@\s]+)/?$")
WORKFLOW_RE = re.compile(r"^\./\.github/workflows/([^/@\s]+)/?$")
FORMAT_RE = re.compile(r"format\s*\(")


class Parsed:
    """One guard or step ``if`` after classification."""

    def __init__(self, *, false_=False, plain=False, accepted=None, problems=None):
        self.false_ = false_
        self.plain = plain
        self.accepted = list(accepted or [])
        self.problems = list(problems or [])


def collapse(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def problem(file: str, job: str, step: str, rule: str, what: str) -> str:
    return f"cache: {file} {job} step '{step}': {rule}: {what}"


def top_level_ops(expr: str) -> list[tuple[str, int]]:
    """Top-level ``&&`` and ``||``. Paren depth 0, and outside single-quoted strings (``''`` escapes)."""
    ops: list[tuple[str, int]] = []
    depth = 0
    in_str = False
    i = 0
    n = len(expr)
    while i < n:
        char = expr[i]
        if in_str:
            if char == "'":
                if i + 1 < n and expr[i + 1] == "'":
                    i += 2
                    continue
                in_str = False
            i += 1
            continue
        if char == "'":
            in_str = True
            i += 1
            continue
        if char == "(":
            depth += 1
        elif char == ")" and depth:
            depth -= 1
        elif depth == 0 and expr.startswith("&&", i):
            ops.append(("&&", i))
            i += 2
            continue
        elif depth == 0 and expr.startswith("||", i):
            ops.append(("||", i))
            i += 2
            continue
        i += 1
    return ops


def split_and(expr: str) -> list[str]:
    parts: list[str] = []
    start = 0
    for kind, index in top_level_ops(expr):
        if kind != "&&":
            continue
        piece = expr[start:index].strip()
        if piece:
            parts.append(piece)
        start = index + 2
    tail = expr[start:].strip()
    if tail:
        parts.append(tail)
    return parts


def strip_wrapper(text: str) -> str:
    stripped = text.strip()
    match = re.fullmatch(r"\$\{\{(.*)\}\}", stripped, re.DOTALL)
    if not match:
        return stripped
    return match.group(1).strip()


def is_literal_false(value: object) -> bool:
    if value is False:
        return True
    if isinstance(value, str):
        text = value.strip()
        if text == "false":
            return True
        if FALSE_WRAP_RE.fullmatch(text):
            return True
    return False


def is_format_call(term: str) -> bool:
    match = FORMAT_RE.match(term.strip())
    if not match:
        return False
    start = match.end() - 1
    depth = 0
    in_str = False
    i = start
    n = len(term)
    while i < n:
        char = term[i]
        if in_str:
            if char == "'":
                if i + 1 < n and term[i + 1] == "'":
                    i += 2
                    continue
                in_str = False
            i += 1
            continue
        if char == "'":
            in_str = True
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return term[i + 1:].strip() == ""
        i += 1
    return False


def classify_term(term: str) -> tuple[str, str]:
    """``accepted`` with the predicate, ``narrow`` , or ``ref`` with the offending term."""
    text = collapse(term)
    if text in ACCEPTED_SET:
        return ("accepted", text)
    if REF_RE.search(text):
        return ("ref", text)
    return ("narrow", text)


def terms_of(terms: list[str]) -> Parsed:
    accepted: list[str] = []
    problems: list[str] = []
    for term in terms:
        kind, text = classify_term(term)
        if kind == "accepted":
            accepted.append(text)
        elif kind == "ref":
            problems.append(
                "unanalysable ref term "
                f"{text}; use an accepted predicate ({G}, {LINE_ONLY}, or {MAIN_ONLY}) "
                "or drop github.ref, github.head_ref and github.base_ref"
            )
    return Parsed(accepted=accepted, problems=problems)


def _idiom_terms(left: str) -> list[str] | None:
    terms = split_and(left)
    if not terms or not is_format_call(terms[-1]):
        return None
    return terms[:-1]


def classify_expr(text: str) -> Parsed:
    """A boolean condition: a conjunction of terms. The cache-to idiom is an exporter, judged by
    classify_exporter, so any top-level || here is unanalysable."""
    body = strip_wrapper(text)
    if collapse(body) == BARE_G:
        return Parsed(problems=[PAREN_MSG])
    if any(kind == "||" for kind, _ in top_level_ops(body)):
        return Parsed(problems=[OR_MSG])
    return terms_of(split_and(body))


def is_plain_text(text: str) -> bool:
    if text.startswith("${{"):
        return False
    return "${{" not in MATRIX_RE.sub("", text)


def classify_exporter(value: object, *, absent: bool) -> Parsed:
    """build-push-action's cache-to and the CLI's CACHE_TO hand buildx an exporter string, not a boolean:
    only the idiom, a plain exporter (the step if must then carry the predicate), or nothing at all."""
    if absent or value is None:
        return Parsed(false_=True)  # no export
    if isinstance(value, str):
        text = value.strip()
        if text == "" or EMPTY_WRAP_RE.fullmatch(text):
            return Parsed(false_=True)
        if set(text) <= {"'", '"'}:
            return Parsed(problems=[EXPORTER_MSG])  # kimi seat: a quotes-only value reaches buildx as a nonempty exporter
        if text not in ("true", "false") and is_plain_text(text):
            return Parsed(plain=True)
        if text.startswith("${{"):
            body = strip_wrapper(text)
            ors = [index for kind, index in top_level_ops(body) if kind == "||"]
            if len(ors) == 1 and collapse(body[ors[0] + 2:]) == "''":
                idiom = _idiom_terms(body[: ors[0]])
                if idiom is not None:
                    return terms_of(idiom)
    return Parsed(problems=[EXPORTER_MSG])


def classify_guard(value: object, *, absent: bool, allow_idiom: bool) -> Parsed:
    if allow_idiom:
        return classify_exporter(value, absent=absent)
    if absent:
        return Parsed(plain=True)
    if is_literal_false(value):
        return Parsed(false_=True)
    if value is True or (isinstance(value, str) and value.strip() == "true"):
        return Parsed(plain=True)
    if not isinstance(value, str):
        return Parsed(problems=["unanalysable guard; use a conjunction, the cache-to idiom, literal false, or a plain value"])
    text = value.strip()
    if is_plain_text(text):
        return Parsed(plain=True)
    return classify_expr(text)


def classify_step_if(value: object, *, absent: bool) -> Parsed:
    if absent:
        return Parsed()
    if is_literal_false(value):
        return Parsed(false_=True)
    if isinstance(value, str):
        body = strip_wrapper(value.strip())
        has_or = any(kind == "||" for kind, _ in top_level_ops(body))
        if has_or and collapse(body) != BARE_G and not REF_RE.search(body):
            # Design amendment A2: ANDed with the guard, a disjunction that names no ref
            # can only narrow the write, so the whole `if` is one narrowing term.
            return Parsed()
        return classify_expr(value.strip())
    if value is True:
        return Parsed()
    return Parsed(problems=["unanalysable step if"])


def step_label(step: dict, index: int) -> str:
    name = step.get("name")
    if isinstance(name, str) and name.strip():
        return name.strip()
    return f"#{index}"


def with_map(step: dict) -> dict:
    raw = step.get("with")
    return raw if isinstance(raw, dict) else {}


def judge_condition(
    step: dict,
    *,
    guard_value: object,
    guard_absent: bool,
    allow_idiom: bool,
    warming: bool,
    file: str,
    job: str,
    label: str,
    dangerous: bool,
    out: list[str],
) -> None:
    guard = classify_guard(guard_value, absent=guard_absent, allow_idiom=allow_idiom)
    # Literal false never writes, on the guard or on the step if. The job if is not consulted.
    if guard.false_ or is_literal_false(step.get("if")) and "if" in step:
        return
    step_if = classify_step_if(step.get("if"), absent="if" not in step)
    if step_if.false_:
        return
    if dangerous:
        out.append(problem(
            file, job, label, "R6",
            "unanalysable: pull_request_target or workflow_run can reach this write "
            "(this workflow, or a workflow that calls it); remove the writer or those triggers",
        ))
    problems = guard.problems + step_if.problems
    if problems:
        for item in problems:
            out.append(problem(file, job, label, "R4", item))
        return
    accepted = ([] if guard.plain else guard.accepted) + step_if.accepted
    if not accepted:
        out.append(problem(
            file, job, label, "R2",
            "no accepted ref predicate; put "
            f"{G} on the step if or the guard (a plain or absent guard writes whenever the step runs)",
        ))
        return
    if warming and all(item == MAIN_ONLY for item in accepted) and (file, label) != MAIN_ONLY_STEP:
        out.append(problem(
            file, job, label, "R5",
            "warming writer whose only accepted term is main; main-only is allowed only for "
            "docker.yml step 'Build and push by digest (no tag)'",
        ))


def cache_to_outside(text: str) -> bool:
    spans: list[tuple[int, int]] = []
    start = 0
    while True:
        found = text.find(CACHE_TO_FORM, start)
        if found < 0:
            break
        spans.append((found, found + len(CACHE_TO_FORM)))
        start = found + len(CACHE_TO_FORM)
    pos = 0
    while True:
        found = text.find("--cache-to", pos)
        if found < 0:
            return False
        if not any(begin <= found < end for begin, end in spans):
            return True
        pos = found + len("--cache-to")


def judge_run(step: dict, *, file: str, job: str, label: str, dangerous: bool, out: list[str]) -> None:
    run = step.get("run")
    if isinstance(run, str) and any(BAKE_RE.search(line) for _, line in logical_lines(run)):
        out.append(problem(file, job, label, "R9", BAKE_MSG))
    if not isinstance(run, str) or "--cache-to" not in run:
        return
    if cache_to_outside(run):
        out.append(problem(
            file, job, label, "R9",
            f"--cache-to is outside {CACHE_TO_FORM}; wrap every --cache-to in that form",
        ))
    env = step.get("env")
    env_map = env if isinstance(env, dict) else {}
    if "CACHE_TO" not in env_map:
        out.append(problem(
            file, job, label, "R9",
            "env.CACHE_TO is absent; set it to the cache-to idiom, a conjunction, or literal false",
        ))
        return
    guard = classify_guard(env_map.get("CACHE_TO"), absent=False, allow_idiom=True)
    if guard.plain:
        out.append(problem(
            file, job, label, "R9",
            "env.CACHE_TO is a plain value; use the cache-to idiom, a conjunction, or literal false",
        ))
        return
    judge_condition(
        step,
        guard_value=env_map.get("CACHE_TO"),
        guard_absent=False,
        allow_idiom=True,
        warming=True,
        file=file,
        job=job,
        label=label,
        dangerous=dangerous,
        out=out,
    )


def judge_inert(name: str, step: dict, *, file: str, job: str, label: str, out: list[str]) -> None:
    inputs = with_map(step)
    if name == "docker/setup-buildx-action":
        # gpt seat finding 4: an expression-valued driver can evaluate to cloud, so it counts as one.
        driver = "" if inputs.get("driver") is None else str(inputs.get("driver")).strip()
        if "version" in inputs or driver == "cloud" or "${{" in driver:
            out.append(problem(file, job, label, "inert", INERT_MSG))
        return
    cache = inputs.get("cache") if "cache" in inputs else None
    if "cache" in inputs and cache not in (None, "", False):
        out.append(problem(file, job, label, "inert", INERT_MSG))


def judge_uses(
    step: dict,
    uses: str,
    *,
    file: str,
    job: str,
    label: str,
    dangerous: bool,
    composites: dict,
    out: list[str],
    stack: frozenset[str],
) -> None:
    local = ACTION_RE.match(uses)
    if local:
        name = local.group(1)
        if name in stack:
            return
        body = composites.get(name)
        if not isinstance(body, dict):
            out.append(problem(file, job, label, "composite", f"no action.yml for ./.github/actions/{name}"))
            return
        runs = body.get("runs") if isinstance(body.get("runs"), dict) else {}
        # gpt seat finding 3: only a composite's steps can be read; a JavaScript or Docker action runs code
        # this check cannot see, so it is unclassified, not an empty composite.
        if str(runs.get("using", "")).strip() != "composite":
            out.append(problem(file, job, label, "classify",
                               f"{CLASSIFY_MSG}: ./.github/actions/{name} runs {runs.get('using')!r}, not a composite"))
            return
        inner = runs.get("steps") if isinstance(runs, dict) else None
        walk_steps(
            inner,
            file=f".github/actions/{name}/action.yml",
            job="composite",
            dangerous=dangerous,
            composites=composites,
            out=out,
            stack=stack | {name},
        )
        return
    if uses.startswith("./"):
        out.append(problem(file, job, label, "classify", CLASSIFY_MSG))
        return
    name, ref = (uses.split("@", 1) + [None])[:2] if "@" in uses else (uses, None)
    name = name.strip()
    ref = ref.strip() if isinstance(ref, str) else None
    if name in PINS and ref != PINS[name]:
        out.append(problem(file, job, label, "R10", f"{PIN_MSG} ({name}@{PINS[name]})"))
    if name in WRITERS:
        guard_input, warming = WRITERS[name]
        inputs = with_map(step)
        absent = guard_input is None or guard_input not in inputs
        judge_condition(
            step,
            guard_value=None if absent else inputs.get(guard_input),
            guard_absent=absent,
            allow_idiom=name == "docker/build-push-action",
            warming=warming,
            file=file,
            job=job,
            label=label,
            dangerous=dangerous,
            out=out,
        )
        if name == "actions/cache/save" and str(inputs.get("key", "")).strip().startswith(MAP_KEY_PREFIX):
            terms = {collapse(t) for t in split_and(strip_wrapper(str(step.get("if", ""))))}
            if file != MAP_WORKFLOW or LINE_ONLY not in terms or MAP_PUSH not in terms:
                out.append(problem(file, job, label, "R11", MAP_MSG))
        return
    if name == COMBINED:
        out.append(problem(file, job, label, "combined", COMBINED_MSG))
        return
    if name == EXCEPTION:
        return
    if name in INERT:
        judge_inert(name, step, file=file, job=job, label=label, out=out)
        return
    if name in NON_WRITERS:
        return
    out.append(problem(file, job, label, "classify", f"{CLASSIFY_MSG}: {name}"))


def walk_steps(
    steps: object,
    *,
    file: str,
    job: str,
    dangerous: bool,
    composites: dict,
    out: list[str],
    stack: frozenset[str],
) -> None:
    if not isinstance(steps, list):
        return
    for index, step in enumerate(steps, 1):
        if not isinstance(step, dict):
            continue
        label = step_label(step, index)
        uses = step.get("uses")
        if isinstance(uses, str) and uses.strip():
            judge_uses(
                step, uses.strip(),
                file=file, job=job, label=label, dangerous=dangerous,
                composites=composites, out=out, stack=stack,
            )
        judge_run(step, file=file, job=job, label=label, dangerous=dangerous, out=out)


def on_triggers(doc: object) -> set[str]:
    """PyYAML reads ``on`` as True. Accept a string, a list, or a mapping."""
    if not isinstance(doc, dict):
        return set()
    if True in doc:
        raw = doc[True]
    elif "on" in doc:
        raw = doc["on"]
    else:
        return set()
    if isinstance(raw, str):
        return {raw}
    if isinstance(raw, list):
        return {item for item in raw if isinstance(item, str)}
    if isinstance(raw, dict):
        return {str(key) for key in raw}
    return set()


def callers_of(docs: dict) -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}
    for name, doc in docs.items():
        jobs = doc.get("jobs") if isinstance(doc, dict) else None
        if not isinstance(jobs, dict):
            continue
        for job in jobs.values():
            if not isinstance(job, dict):
                continue
            uses = job.get("uses")
            if not isinstance(uses, str):
                continue
            match = WORKFLOW_RE.match(uses.strip())
            if match:
                found.setdefault(match.group(1), set()).add(str(name))
    return found


def dangerous_for(name: str, triggers: dict[str, set[str]], callers: dict[str, set[str]],
                  seen: frozenset[str] = frozenset()) -> bool:
    """Reachable from pull_request_target or workflow_run, through any chain of workflow_call callers."""
    own = triggers.get(name, set())
    if own & DANGEROUS:
        return True
    if "workflow_call" not in own or name in seen:
        return False
    return any(dangerous_for(caller, triggers, callers, seen | {name}) for caller in callers.get(name, ()))


def script_problems(script_lines: list) -> list[str]:
    out: list[str] = []
    for item in script_lines:
        if not isinstance(item, tuple) or len(item) != 3:
            continue
        path, lineno, text = item
        if not isinstance(text, str):
            continue
        # gpt seat findings 2 and 5: a script cannot show the guard of the step that calls it, so a
        # --cache-to in one is refused in any form, and a bake run is refused until classified.
        if "--cache-to" in text:
            out.append(problem(
                str(path), "line", f"#{lineno}", "R9",
                f"--cache-to at {path}:{lineno}: a script cannot carry the calling step's guard; pass the flag "
                f"from the workflow step as {CACHE_TO_FORM}",
            ))
        if BAKE_RE.search(text):
            out.append(problem(str(path), "line", f"#{lineno}", "R9", f"{BAKE_MSG} ({path}:{lineno})"))
    return out


def unwrap_package(item: object) -> tuple[str, object]:
    if isinstance(item, dict) and "path" in item and "data" in item:
        return str(item.get("path") or "package.json"), item.get("data")
    if isinstance(item, dict):
        return "package.json", item
    return "package.json", None


def package_problems(package_jsons: list) -> list[str]:
    """Once per run, not once per setup-node step."""
    bad: list[str] = []
    for item in package_jsons:
        path, data = unwrap_package(item)
        if not isinstance(data, dict):
            continue
        dev = data.get("devEngines")
        if "packageManager" in data or (isinstance(dev, dict) and "packageManager" in dev):
            bad.append(path)
    if not bad:
        return []
    return [problem(bad[0], "repo", "package.json", "inert", INERT_MSG + " (" + ", ".join(bad) + ")")]


def check(docs: dict, composites: dict, package_jsons: list, script_lines: list) -> list[str]:
    triggers = {str(name): on_triggers(doc) for name, doc in docs.items()}
    callers = callers_of(docs)
    out: list[str] = []
    for name in sorted(docs, key=str):
        doc = docs[name]
        if not isinstance(doc, dict):
            continue
        dangerous = dangerous_for(str(name), triggers, callers)
        jobs = doc.get("jobs")
        if not isinstance(jobs, dict):
            continue
        for job_id, job in jobs.items():
            if not isinstance(job, dict):
                continue
            if isinstance(job.get("uses"), str):
                # A local reusable workflow is checked as a file of its own; one from another
                # repository cannot be read here, so it is outside the closed world.
                if not WORKFLOW_RE.match(job["uses"].strip()):
                    out.append(problem(
                        str(name), str(job_id), "uses", "classify",
                        f"{CLASSIFY_MSG}: reusable workflow {job['uses'].strip()} lives in another repository, "
                        "so its cache writes cannot be read",
                    ))
                continue
            walk_steps(
                job.get("steps"),
                file=str(name),
                job=str(job_id),
                dangerous=dangerous,
                composites=composites,
                out=out,
                stack=frozenset(),
            )
    out.extend(package_problems(package_jsons))
    out.extend(script_problems(script_lines))
    seen: set[str] = set()
    unique: list[str] = []
    for item in out:
        if item not in seen:
            seen.add(item)
            unique.append(item)
    return unique


def _load_yaml(path: Path) -> dict:
    loaded = yaml.safe_load(path.read_text())
    return loaded if isinstance(loaded, dict) else {}


def errors(root: Path = ROOT) -> list[str]:
    root = Path(root)
    docs: dict[str, dict] = {}
    folder = root / ".github" / "workflows"
    if folder.is_dir():
        files = sorted(folder.glob("*.yml")) + sorted(folder.glob("*.yaml"))
        for path in files:
            docs[path.name] = _load_yaml(path)
    composites: dict[str, dict] = {}
    actions = root / ".github" / "actions"
    if actions.is_dir():
        for directory in sorted(path for path in actions.iterdir() if path.is_dir()):
            for cand in ("action.yml", "action.yaml"):
                found = directory / cand
                if found.is_file():
                    composites[directory.name] = _load_yaml(found)
                    break
    packages: list[dict] = []
    for directory, subdirs, names in os.walk(root):
        # Prune what holds no project package.json and is large: git objects, installs, build output.
        subdirs[:] = sorted(d for d in subdirs if d not in {".git", "node_modules", "target"})
        if "package.json" not in names:
            continue
        path = Path(directory) / "package.json"
        try:
            data = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        packages.append({"path": path.relative_to(root).as_posix(), "data": data})
    lines: list[tuple[str, int, str]] = []
    for folder_name in ("scripts", ".github/actions"):
        base = root / folder_name
        if not base.is_dir():
            continue
        for path in sorted(item for item in base.rglob("*") if item.is_file()):
            rel = path.relative_to(root).as_posix()
            if rel in SKIP_SCRIPT:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            for lineno, line in logical_lines(text):
                if "--cache-to" in line or BAKE_RE.search(line):
                    lines.append((rel, lineno, line))
    return check(docs, composites, packages, lines)


def _expr(inner: str) -> str:
    return "${{ " + inner + " }}"


def _doc(steps: list, *, on: object = "push", filename: str = "t.yml", job: str = "j", job_if: object = None, key: object = "on") -> dict:
    body: dict = {"steps": steps}
    if job_if is not None:
        body["if"] = job_if
    return {filename: {key: on, "jobs": {job: body}}}


def self_test() -> list[str]:
    out: list[str] = []
    build = "docker/build-push-action@" + PINS["docker/build-push-action"]
    trivy = "aquasecurity/trivy-action@" + PINS["aquasecurity/trivy-action"]
    buildx = "docker/setup-buildx-action@" + PINS["docker/setup-buildx-action"]
    node = "actions/setup-node@" + PINS["actions/setup-node"]
    bad_sha = "0" * 40
    plain_cache_to = "type=gha,mode=max,scope=docker-${{ matrix.arch }}"
    idiom = _expr(G + " && format('type=gha,scope=x-{0}', matrix.arch) || ''")
    guarded = {
        "Swatinem/rust-cache@x": {"with": {"save-if": _expr(G)}},
        build: {"with": {"cache-to": idiom}},
        "actions/cache/save@x": {"if": _expr(G)},
        "astral-sh/setup-uv@x": {"with": {"save-cache": _expr(G)}},
    }
    # An exporter left out exports nothing, so build-push's unguarded writer is a plain exporter.
    unguarded = {build: {"with": {"cache-to": "type=gha,mode=max,scope=x"}}}

    def bad(label: str, docs: dict, composites: dict | None = None, packages: list | None = None,
            scripts: list | None = None, contains: str | None = None) -> None:
        got = check(docs, composites or {}, packages or [], scripts or [])
        if not got:
            out.append(f"self-test: {label}: expected a failure")
        elif contains is not None and not any(contains in item for item in got):
            out.append(f"self-test: {label}: missing {contains!r} in {got}")

    def good(label: str, docs: dict, composites: dict | None = None, packages: list | None = None,
             scripts: list | None = None) -> None:
        got = check(docs, composites or {}, packages or [], scripts or [])
        if got:
            out.append(f"self-test: {label}: expected pass, got {got}")

    # The affected-tests map's key: saved by its own workflow on a release-line push, and by nothing else.
    map_save = {"name": "save the map", "uses": "actions/cache/save@x", "with": {"key": "affected-map-${{ github.sha }}"}}
    good("11 the map workflow saves its key on a release-line push",
         _doc([{**map_save, "if": _expr(LINE_ONLY + " && " + MAP_PUSH)}], filename=MAP_WORKFLOW))
    bad("11 another workflow saves the map key", _doc([{**map_save, "if": _expr(LINE_ONLY + " && " + MAP_PUSH)}],
                                                       filename="ci.yml"), contains="R11")
    bad("11 the map key saved on a dispatch too", _doc([{**map_save, "if": _expr(LINE_ONLY)}], filename=MAP_WORKFLOW),
        contains="R11")
    bad("11 the map key saved on main too", _doc([{**map_save, "if": _expr(G + " && " + MAP_PUSH)}],
                                                 filename=MAP_WORKFLOW), contains="R11")
    good("11 another key in another workflow is not the map's",
         _doc([{**map_save, "with": {"key": "other-${{ github.sha }}"}, "if": _expr(LINE_ONLY)}], filename="ci.yml"))
    bare = {"name": "cache", "uses": "Swatinem/rust-cache@x"}
    for uses in ("Swatinem/rust-cache@x", build, "actions/cache/save@x", "astral-sh/setup-uv@x"):
        bad(f"1 unguarded {uses.split('@')[0]}", _doc([{"uses": uses, **unguarded.get(uses, {})}]))
        extra = guarded[uses]
        good(f"2 guarded {uses.split('@')[0]}", _doc([{"name": "cache", "uses": uses, **extra}]))
    # gpt seat finding 1: an exporter is a string, never a boolean; absent or empty exports nothing.
    for label, value in (("(G) as a boolean", _expr(G)), ("literal false", False), ("string false", "false"),
                         ("a literal '' string", "''")):
        bad(f"1b exporter {label}", _doc([{"uses": build, "with": {"cache-to": value}}]), contains="exporter")
    good("1c exporter absent or empty", _doc([{"uses": build}, {"uses": build, "with": {"cache-to": ""}},
                                            {"uses": build, "with": {"cache-to": "${{ '' }}"}}]))
    good("1d plain exporter under a guarded step if", _doc([{
        "uses": build, "if": _expr(G), "with": {"cache-to": "type=gha,mode=max,scope=x-${{ matrix.arch }}"}}]))

    good("3 idiom", _doc([{"name": "build", "uses": build, "with": {"cache-to": idiom}}]))
    bad("3 else type=gha", _doc([{
        "name": "build", "uses": build,
        "with": {"cache-to": _expr(G + " && format('type=gha,scope=x-{0}', matrix.arch) || 'type=gha'")},
    }]))
    bad("3 ref after ||", _doc([{
        "name": "build", "uses": build,
        "with": {"cache-to": _expr(G + " && format('type=gha,scope=x-{0}', matrix.arch) || github.ref == 'refs/heads/x'")},
    }]))

    bad(
        "4 bare G",
        _doc([{"uses": "astral-sh/setup-uv@x", "with": {"save-cache": _expr(BARE_G)}}]),
        contains=PAREN_MSG,
    )
    bad("5 ref inequality", _doc([{"uses": "Swatinem/rust-cache@x", "with": {"save-if": "${{ github.ref != 'refs/heads/x' }}"}}]))
    bad("6 top-level ||", _doc([{
        "uses": "Swatinem/rust-cache@x",
        "if": "${{ github.event_name == 'push' || github.ref == 'refs/heads/main' }}",
        "with": {"save-if": _expr(G)},
    }]))
    # Design amendment A2: a step `if` disjunction that names no ref narrows an accepted guard (ci.yml
    # capability-pins), but it cannot carry the predicate itself, so with a plain guard the step still fails.
    ref_free_or = "needs.scope.result != 'success' || needs.scope.outputs.docs_only != 'true'"
    good("6a ref-free || beside an accepted guard", _doc([{
        "uses": "Swatinem/rust-cache@x", "if": ref_free_or, "with": {"save-if": _expr(LINE_ONLY)},
    }]))
    bad("6b ref-free || with a plain guard", _doc([{"uses": "astral-sh/setup-uv@x", "if": ref_free_or}]))
    beside = (
        f"{G} && matrix.target == 'x' && steps.a.outputs.b != 'true' "
        "&& (matrix.a == 'x' || matrix.a == 'y')"
    )
    good("7 narrowing terms", _doc([{"uses": "Swatinem/rust-cache@x", "with": {"save-if": _expr(beside)}}]))

    bad("8 main-only warming", _doc([{"uses": "Swatinem/rust-cache@x", "with": {"save-if": _expr(MAIN_ONLY)}}]))
    digest = {
        "name": "Build and push by digest (no tag)",
        "uses": build,
        "with": {"cache-to": plain_cache_to},
    }
    good("8 main-only step", _doc(
        [{**digest, "if": "github.event_name == 'push' && github.ref == 'refs/heads/main'"}],
        filename="docker.yml",
    ))
    bad("8 plain cache-to without step if", _doc([digest], filename="docker.yml"))

    good("9 setup-uv under (G)", _doc([{"uses": "astral-sh/setup-uv@x", "if": _expr(G)}]))
    bad("9 setup-uv without (G)", _doc([{"uses": "astral-sh/setup-uv@x"}]))

    for label, save_if in (("yaml false", False), ("string false", "false"), ("expr false", "${{ false }}"), ("spaced false", "${{  false  }}")):
        good(f"10 {label}", _doc([{"uses": "Swatinem/rust-cache@x", "with": {"save-if": save_if}}]))

    good("11 job if does not block", _doc(
        [{"uses": "Swatinem/rust-cache@x", "with": {"save-if": _expr(G)}}],
        job_if="${{ github.ref == 'refs/heads/a' || github.ref == 'refs/heads/b' }}",
    ))
    good_job_credit_would_pass = _doc(
        [digest],
        filename="docker.yml",
        job_if=_expr(MAIN_ONLY),
    )
    bad("11 job if does not credit", good_job_credit_would_pass)

    rust_g = {"name": "cache", "uses": "Swatinem/rust-cache@x", "with": {"save-if": _expr(G)}}
    bad("12 pull_request_target", { "bad.yml": {True: "pull_request_target", "jobs": {"j": {"steps": [rust_g]}}} })
    bad("12 workflow_run", _doc([rust_g], on="workflow_run", filename="run.yml"))
    bad("12 called by pull_request_target", {
        "caller.yml": {
            "on": {"pull_request_target": {"types": ["opened"]}},
            "jobs": {"c": {"uses": "./.github/workflows/callee.yml"}},
        },
        "callee.yml": {"on": "workflow_call", "jobs": {"j": {"steps": [rust_g]}}},
    })
    good("12 called by push and pull_request", {
        "caller.yml": {
            "on": ["push", "pull_request"],
            "jobs": {"c": {"uses": "./.github/workflows/callee.yml"}},
        },
        "callee.yml": {"on": "workflow_call", "jobs": {"j": {"steps": [rust_g]}}},
    })
    # Self-QA rows: the danger follows a chain of workflow_call callers, and a reusable workflow from
    # another repository is outside the closed world.
    bad("12c called through a middle workflow", {
        "top.yml": {"on": "pull_request_target", "jobs": {"c": {"uses": "./.github/workflows/mid.yml"}}},
        "mid.yml": {"on": "workflow_call", "jobs": {"c": {"uses": "./.github/workflows/leaf.yml"}}},
        "leaf.yml": {"on": "workflow_call", "jobs": {"j": {"steps": [rust_g]}}},
    })
    bad("12d remote reusable workflow", {
        "r.yml": {"on": "push", "jobs": {"c": {"uses": "someone/else/.github/workflows/w.yml@0123456789abcdef"}}},
    })

    bad("13 unclassified", _doc([{"uses": "someorg/custom-action@v1"}]), contains=CLASSIFY_MSG)
    bad("14 combined actions/cache", _doc([{"uses": "actions/cache@v6", "if": _expr(G)}]), contains=COMBINED_MSG)

    bad("15 workflow --cache-to", _doc([{"name": "build", "run": "docker buildx build --cache-to type=gha ."}]))
    bad("15 composite --cache-to", _doc([{"uses": "./.github/actions/b"}]), composites={
        "b": {"runs": {"using": "composite", "steps": [{"name": "build", "run": "docker build --cache-to type=gha ."}]}},
    }, contains="R9")
    # gpt seat finding 3: a local JavaScript or Docker action is unclassified, not an empty composite.
    bad("15d local javascript action", _doc([{"uses": "./.github/actions/js"}]),
        composites={"js": {"runs": {"using": "node24", "main": "index.js"}}}, contains="not a composite")
    bad("15 script --cache-to", {}, scripts=[("scripts/build.sh", 4, "docker build --cache-to type=gha .")])
    good("15 idiom form", _doc([{
        "name": "build",
        "run": 'docker buildx build ${CACHE_TO:+--cache-to "$CACHE_TO"} .',
        "env": {"CACHE_TO": idiom},
    }]))
    # gpt seat finding 2: a script cannot carry its caller's guard, so even the wrapped form is refused there.
    bad("15 script form", {}, scripts=[("scripts/build.sh", 4, 'docker buildx build ${CACHE_TO:+--cache-to "$CACHE_TO"} .')],
        contains="cannot carry")
    # gpt seat finding 5: bake reads cache-to from its own file and --set flags.
    bad("15b bake in a script", {}, scripts=[("scripts/b.sh", 2, "docker buildx bake --set '*.cache-to=type=gha'")],
        contains="bake")
    bad("15c bake in a run step", _doc([{"run": "docker buildx bake release"}]), contains="bake")
    bad("15e bake after a builder flag", _doc([{"run": "docker buildx --builder ci bake release"}]), contains="bake")
    bad("15g bake after a docker global flag", _doc([{"run": "docker --context ci bake release"}]), contains="bake")
    bad("15h bake split over continued lines", _doc([{"run": "docker buildx \\\n  --builder ci \\\n  bake release"}]),
        contains="bake")
    # gpt seat on the kimi fold: the shell joins continued fragments with no space; CRLF endings; an even run of
    # trailing backslashes is literal, not a continuation.
    bad("15j bake split inside its word", _doc([{"run": "docker buildx ba\\\nke release"}]), contains="bake")
    bad("15l bake continued over a CRLF line end", _doc([{"run": "docker buildx \\\r\n  bake release"}]), contains="bake")
    good("15k an escaped backslash at a line end is not a continuation",
         _doc([{"run": "echo docker \\\\\nbake release"}]))
    good("15m a backslash then a space at a line end is not a continuation",
         _doc([{"run": "echo docker \\ \nbake release"}]))
    bad("15i CACHE_TO a literal '' string", _doc([{
        "name": "build",
        "run": 'docker buildx build ${CACHE_TO:+--cache-to "$CACHE_TO"} .',
        "env": {"CACHE_TO": "''"},
    }]), contains="exporter")
    good("15f buildx build is not bake", _doc([{"run": "docker buildx build --load -t baked-image ."}]))

    bad("16 trivy other sha", _doc([{"uses": f"aquasecurity/trivy-action@{bad_sha}"}]), contains=PIN_MSG)
    bad("16 build-push other sha", _doc([{"uses": f"docker/build-push-action@{bad_sha}", "with": {"cache-to": _expr(G)}}]), contains=PIN_MSG)
    good("16 trivy pin", _doc([{"uses": trivy}]))
    good("16 build-push pin", _doc([{"uses": build, "with": {"cache-to": idiom}}]))

    good("17 buildx unguarded", _doc([{"uses": buildx}]))
    bad("17 buildx version", _doc([{"uses": buildx, "with": {"version": "latest"}}]), contains=INERT_MSG)
    bad("17 buildx driver cloud", _doc([{"uses": buildx, "with": {"driver": "cloud"}}]), contains=INERT_MSG)
    bad("17b buildx driver expression", _doc([{"uses": buildx, "with": {"driver": "${{ 'cloud' }}"}}]),
        contains=INERT_MSG)
    good("17c buildx driver-opts only", _doc([{"uses": buildx, "with": {
        "driver-opts": "image=mirror.gcr.io/moby/buildkit:buildx-stable-1"}}]))
    bad("17 buildx other sha", _doc([{"uses": f"docker/setup-buildx-action@{bad_sha}"}]), contains=PIN_MSG)

    good("18 setup-node unguarded", _doc([{"uses": node}]))
    bad("18 setup-node cache", _doc([{"uses": node, "with": {"cache": "npm"}}]), contains=INERT_MSG)
    bad("18 packageManager", _doc([{"uses": node}]), packages=[{"path": "package.json", "data": {"packageManager": "npm@10"}}], contains=INERT_MSG)
    bad(
        "18 devEngines.packageManager",
        _doc([{"uses": node}]),
        packages=[{"path": "ui/package.json", "data": {"devEngines": {"packageManager": {"name": "npm"}}}}],
        contains=INERT_MSG,
    )
    bad("18 setup-node other sha", _doc([{"uses": f"actions/setup-node@{bad_sha}"}]), contains=PIN_MSG)
    out.extend(_loader_self_test())
    return out


def _loader_self_test() -> list[str]:
    """Row 19 (gpt seat improvement): errors() itself, over a real file tree, finds a writer in a .yaml
    workflow, a --cache-to in a local composite, a bake line in a script, and a nested package.json naming a
    package manager, and skips one under node_modules. An unguarded rust-cache step fails on rule R2 in a
    .yaml and in a .yml workflow alike."""
    import tempfile

    found: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        # The same pull-request workflow, its rust-cache saving unconditionally, under both extensions GitHub runs.
        unguarded_rust = "on: pull_request\njobs:\n  j:\n    steps:\n      - uses: Swatinem/rust-cache@x\n"
        files = {
            ".github/workflows/rust.yaml": unguarded_rust,
            ".github/workflows/rust.yml": unguarded_rust,
            ".github/workflows/w.yaml": "on: push\njobs:\n  j:\n    steps:\n      - uses: astral-sh/setup-uv@x\n",
            ".github/actions/a/action.yml": "runs:\n  using: composite\n  steps:\n"
                                           "    - run: docker build --cache-to type=gha .\n      shell: bash\n",
            "scripts/ci/b.sh": "docker buildx bake release\n",
            "scripts/ci/c.sh": "set -e\ndocker buildx \\\n  bake release\n",
            "ui/package.json": json.dumps({"packageManager": "npm@10"}),
            "ui/node_modules/x/package.json": json.dumps({"packageManager": "pnpm@9"}),
        }
        for rel, text in files.items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(text)
        got = errors(root)
    want = {"w.yaml": "setup-uv writer in a .yaml workflow", "R9: --cache-to at .github/actions/a": "composite --cache-to",
            "scripts/ci/b.sh:1": "bake in a script", "scripts/ci/c.sh:2": "bake split over continued lines in a script",
            "ui/package.json": "nested package.json"}
    for needle, what in want.items():
        if not any(needle in item for item in got):
            found.append(f"self-test: 19 loader: {what} not found in {got}")
    if any("node_modules" in item for item in got):
        found.append(f"self-test: 19 loader: a package.json under node_modules was read: {got}")
    # Each copy must fail on the unguarded-writer rule itself, so dropping either extension from the loader shows.
    for name in ("rust.yaml", "rust.yml"):
        if not any(item.startswith(f"cache: {name} ") and ": R2: " in item for item in got):
            found.append(f"self-test: 19 loader: unguarded rust-cache in {name} not caught by R2 in {got}")
    return found

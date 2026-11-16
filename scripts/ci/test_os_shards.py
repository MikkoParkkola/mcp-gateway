#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The OS test shards reproduce the suites they replaced (MIK-8482).

Static checks on ci.yml and scripts/ci/shard_tests.py:

- every OS's shards are exact complements: the whole lib unfiltered, or a
  cascade of lib filters (each shard skips every earlier shard's filters, one
  catch-all skips them all), and integration globs that are `*` alone or a class and its negation;
- together they cover the targets the unsharded command ran (Linux, macOS:
  lib, bins, tests, doctests; Windows: `--tests`, which is lib, bins, tests);
- each shard matrix in ci.yml lists exactly that OS's shards;
- the Linux lib legs run from the shared lib test binary in their own job (SHARED_LIB): the same check names,
  run even when the build failed (`!cancelled()`), only `run-prebuilt`, and the aggregate needs it and the build;
- the aggregates keep the required names, need their shard jobs, run under
  !cancelled() with the shards' own skip guards, and pass the same job ids to
  check_needs.py;
- no shard name equals a required name, every macOS shard name starts with
  `macOS ` (merge tooling treats that prefix as macOS), and none contains
  the word `Tests`;
- option E: macos-shards' calls, gates and limits, each path's worst case within the job's limit, the
  Intel job (`macos-xbuild`) against obtain_lib.py's tables, and its advisory marker on no other job of any workflow.
"""
from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
JOBS = {  # os: (shard job, aggregate job, aggregate name, shard name prefix)
    "linux": ("test-shards", "test", "Tests", "Linux shard "),
    "windows": ("windows-shards", "windows-check", "Windows check", "Windows shard "),
    "macos": ("macos-shards", "macos-check", "macOS check", "macOS shard "),
}
EXTRA_NEEDS = {"windows-check": ["windows-clippy"], "test": ["test-shards-lib", "linux-lib-build"]}
# An OS whose lib legs run from one shared lib test binary: (their job, the build job). The legs are the runner's
# SHARED_BUILD; they keep the shard job's name, so the check names stay; the build job's own wiring is
# check_shared_lib.py's.
SHARED_LIB = {"linux": ("test-shards-lib", "linux-lib-build")}
# Every aggregate skips on a same-repo merge-train PR into the release line: merge-train judges its needs
# itself from the base copy of this workflow (the ROLLUP_EXPECTS ids below).
TRAIN_SKIP = ("!(github.event_name == 'pull_request' && github.base_ref == 'docs/ranking-1-release-line'"
              " && github.event.pull_request.head.repo.full_name == github.repository"
              " && startsWith(github.head_ref, 'train/'))")
# `matrix.shard == 'x'` in any spacing or quoting an expression accepts.
# The os-sensitive label's clause, as ci.yml's OS jobs spell it (test_os_label_routing.py
# checks what it routes).
LABEL = "os-sensitive"
LABELLED = f"contains(github.event.pull_request.labels.*.name, '{LABEL}')"
# What a labelled lane runs, by OS; an OS absent here never narrows its matrix.
LABELLED_LEGS = {"macos": ["lib-b"]}
# fromJSON(<cond> && '<labelled list>' || '<train list>'), as GitHub reads it:
# the function name in any case, any whitespace.
MATRIX = re.compile(
    r"^\$\{\{\s*fromjson\(\s*(?P<cond>.+?)\s*&&\s*'(?P<a>\[[^']*\])'\s*\|\|\s*'(?P<b>\[[^']*\])'\s*\)\s*\}\}$",
    re.IGNORECASE | re.DOTALL,
)


def matrix_lists(value) -> tuple[list | None, list | None]:
    """(train list, labelled list) of a shard matrix: a static list is both the
    train's and unlabelled (None); a fromJSON expression gives both lists."""
    if isinstance(value, list):
        return value, None
    m = MATRIX.match(str(value or "").strip())
    if not m or LABELLED not in m.group("cond"):
        return None, None
    return json.loads(m.group("b")), json.loads(m.group("a"))
PIN = re.compile(r"""matrix\.shard\s*==\s*['"]([^'"]+)['"]""")
COVERS = {"linux": {"lib", "bins", "tests", "doc"}, "macos": {"lib", "bins", "tests", "doc"},
          "windows": {"lib", "bins", "tests"}}


def legs_of(st, os_kind: str) -> list[str]:
    """The shards that are matrix legs: all but those run from another shard's binary (PREBUILT)."""
    return sorted(set(st.SHARDS[os_kind]) - set(getattr(st, "PREBUILT", {}).get(os_kind, {})))


def runner():
    spec = importlib.util.spec_from_file_location("shard_tests", ROOT / "scripts/ci/shard_tests.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def lib_cascade(lib_filters) -> bool:
    """Whether the lib shards run each library test exactly once: one shard with no filter at
    all, or a cascade where each shard takes its own filter group and skips every group an
    earlier shard took, and one shard takes no group and skips them all."""
    if lib_filters == [()]:
        return True
    parsed = []
    for args in lib_filters:
        pos, skip, it = set(), set(), iter(args)
        for a in it:
            if a == "--skip":
                skip.add(next(it, ""))
            else:
                pos.add(a)
        parsed.append((pos, skip))
    rest = [p for p in parsed if p[0]]
    catch = [p for p in parsed if not p[0]]
    if len(catch) != 1 or not rest:
        return False
    taken = set()
    for pos, skip in sorted(rest, key=lambda p: len(p[1])):
        # libtest filters match substrings: a filter containing a skipped one selects nothing.
        if skip != taken or any(t in p for p in pos for t in taken):
            return False
        taken |= pos
    return catch[0][1] == taken


def table_problems(st) -> list[str]:
    out = []
    for os_kind, shards in st.SHARDS.items():
        lib_filters, globs, kinds, bins = [], [], set(), 0
        for name, steps in shards.items():
            for step, args, test_args, floor in steps:
                if floor <= 0:
                    out.append(f"{os_kind} {name} {step}: floor must be positive")
                if "--lib" in args:
                    kinds.add("lib")
                    lib_filters.append(tuple(test_args))
                if "--doc" in args:
                    kinds.add("doc")
                if "--bins" in args:
                    kinds.add("bins")
                    bins += 1
                if "--test" in args:
                    kinds.add("tests")
                    globs.append(args[args.index("--test") + 1])
                if "--skip" in args or any(a in st.SKIPS[os_kind] for a in test_args if a != "--skip"):
                    out.append(f"{os_kind} {name} {step}: an OS skip belongs in SKIPS, not the shard")
        if not lib_cascade(lib_filters):
            out.append(f"{os_kind}: lib shards {lib_filters} are not the whole lib or a cascade of filters and their --skips")
        if sorted(globs) not in ([st.GLOB_ALL], sorted([st.GLOB_A, st.GLOB_B])):
            out.append(f"{os_kind}: integration globs {globs} are not `*` or a class and its negation")
        if st.GLOB_B != "[!" + st.GLOB_A[1:]:
            out.append(f"glob classes {st.GLOB_A} and {st.GLOB_B} are not complements")
        if bins != 1:
            out.append(f"{os_kind}: --bins must be in exactly one shard, found {bins}")
        for name, steps in shards.items():
            in_shard = [a[a.index("--test") + 1] for _, a, _, _ in steps if "--test" in a]
            if len(in_shard) > 1:
                out.append(f"{os_kind} {name}: holds {in_shard}; each glob class belongs to its own shard")
        if st.EXAMPLES.get(os_kind) not in shards:
            out.append(f"{os_kind}: the examples build is assigned to no shard ({st.EXAMPLES.get(os_kind)!r})")
        if kinds != COVERS[os_kind]:
            out.append(f"{os_kind}: shards cover {sorted(kinds)}, the suite ran {sorted(COVERS[os_kind])}")
    return out


def workflow_problems(jobs: dict, st) -> list[str]:
    out = []
    required = {agg_name for _, _, agg_name, _ in JOBS.values()}
    for os_kind, (shard_key, agg_key, agg_name, prefix) in JOBS.items():
        shard, agg = jobs.get(shard_key), jobs.get(agg_key)
        if not shard or not agg:
            out.append(f"{os_kind}: {shard_key} or {agg_key} missing")
            continue
        value = shard.get("strategy", {}).get("matrix", {}).get("shard")
        legs, labelled_legs = matrix_lists(value)
        shared_key, build_key = SHARED_LIB.get(os_kind, (None, None))
        shared_legs = list(getattr(st, "SHARED_BUILD", {}).get(os_kind, ()))
        if bool(shared_key) != bool(shared_legs):
            out.append(f"{os_kind}: the runner's SHARED_BUILD legs {shared_legs} and the workflow job {shared_key} must come together")
        if sorted(legs or []) != sorted(set(legs_of(st, os_kind)) - set(shared_legs)):
            out.append(f"{shard_key}: matrix {value} is not the runner's {legs_of(st, os_kind)}"
                       + (f" less the shared-binary legs {shared_legs}" if shared_legs else ""))
        # The os-sensitive label: macOS is train-only (a static matrix, no clause) or
        # labelled (the expression, its labelled list LABELLED_LEGS, the clause on the
        # shards and their aggregate); Windows runs every shard under the label.
        clause = [k for k in (shard_key, agg_key) if LABELLED in str(jobs[k].get("if", ""))]
        want_legs = LABELLED_LEGS.get(os_kind)
        if labelled_legs is None:
            if os_kind == "macos" and clause:
                out.append(f"{shard_key}: the label clause on {clause} with a static matrix")
        elif want_legs is None:
            out.append(f"{shard_key}: narrows its matrix to {labelled_legs} under the label; it never may")
        else:
            if labelled_legs != want_legs:
                out.append(f"{shard_key}: a labelled lane runs {labelled_legs}, not {want_legs}")
            if sorted(clause) != sorted([shard_key, agg_key]):
                out.append(f"{shard_key}: the labelled matrix needs the label clause on both "
                           f"{shard_key} and {agg_key}, found it on {clause}")
        if shard.get("strategy", {}).get("fail-fast") is not False:
            out.append(f"{shard_key}: fail-fast must be false, so one red shard does not cancel the rest")
        name = shard.get("name", "")
        py = "python" if os_kind == "windows" else "python3"
        # Linux shards build the library test binary through the memory log (check_swap_jobs.py enforces it there).
        memlog = "scripts/ci/with-memory-log.sh " if os_kind == "linux" else ""
        call = f"{memlog}{py} scripts/ci/shard_tests.py run {os_kind} ${{{{ matrix.shard }}}}"
        # An OS with PREBUILT shards also exports the lib binary first and runs each prebuilt
        # shard from it after the suite.
        prebuilt = sorted(getattr(st, "PREBUILT", {}).get(os_kind, {}))
        # Each prebuilt shard: wait for the binary, run from it, or build it here when it is not coming.
        want = ([f'{py} scripts/ci/shard_tests.py export-lib "$RUNNER_TEMP/lib-bin"'] if prebuilt else []) + [call]
        for leg in prebuilt:
            producer = st.PREBUILT[os_kind][leg]
            want += [f'{py} scripts/ci/shard_tests.py wait-lib macos-lib-tests "{prefix}{producer}"',
                     f'{py} scripts/ci/shard_tests.py run-prebuilt {os_kind} {leg} "$RUNNER_TEMP/lib-bin/lib-tests"',
                     f"{py} scripts/ci/shard_tests.py run {os_kind} {leg}"]
        calls = [s.get("run", "").strip() for s in shard.get("steps", []) if "shard_tests.py" in s.get("run", "")]
        # An OS whose legs may take a binary another job built (option E): option_e_problems checks its calls.
        if calls != want and not getattr(st, "XBUILT", {}).get(os_kind):
            out.append(f"{shard_key}: runner calls {calls}, want exactly {want!r}")
        # A duty pinned to one shard must name a shard that exists, or it
        # silently never runs (the UPGRADING, privileged and smoke steps).
        for s in shard.get("steps", []):
            for leg in PIN.findall(str(s.get("if", ""))):
                if leg not in (legs or []):
                    out.append(f"{shard_key}: step {s.get('name')!r} is pinned to {leg!r}, not a shard")
        if not name.startswith(prefix) or name in required or "Tests" in name:
            out.append(f"{shard_key}: name {name!r} must start {prefix!r}, not be a required name, not say Tests")
        if agg.get("name") != agg_name:
            out.append(f"{agg_key}: name {agg.get('name')!r} must stay {agg_name!r}")
        needs = agg.get("needs") or []
        needs = [needs] if isinstance(needs, str) else needs
        want = [shard_key, *EXTRA_NEEDS.get(agg_key, [])]
        if sorted(needs) != sorted(want):
            out.append(f"{agg_key}: needs {needs}, want {want}")
        guard = str(shard.get("if", "")).strip()
        if guard.startswith("${{") and guard.endswith("}}"):
            guard = guard[3:-2].strip()
        if str(agg.get("if", "")).replace(" ", "") != ("${{ !cancelled() && " + guard + " && " + TRAIN_SKIP + " }}").replace(" ", ""):
            out.append(f"{agg_key}: if must be !cancelled(), the shards' own guard and the merge-train skip, exactly")
        for extra in EXTRA_NEEDS.get(agg_key, []):
            if extra == shared_key:
                # It runs when the build failed too, so a failed build turns its legs red, never skipped.
                want_if = "${{ !cancelled() && " + guard + " }}"
                if str(jobs.get(extra, {}).get("if", "")).replace(" ", "") != want_if.replace(" ", ""):
                    out.append(f"{extra}: if must be !cancelled() and {shard_key}'s guard, exactly")
            elif str(jobs.get(extra, {}).get("if", "")) != str(shard.get("if", "")):
                out.append(f"{extra}: if must equal {shard_key}'s guard")
        if shared_key:
            sj = jobs.get(shared_key) or {}
            if sj.get("strategy", {}).get("matrix", {}).get("shard") != shared_legs:
                out.append(f"{shared_key}: matrix must be exactly {shared_legs}")
            if sj.get("strategy", {}).get("fail-fast") is not False:
                out.append(f"{shared_key}: fail-fast must be false, so one red shard does not cancel the rest")
            if sj.get("name") != name:
                out.append(f"{shared_key}: name {sj.get('name')!r} must equal {shard_key}'s {name!r}, so the check names stay")
            needs_s = sj.get("needs") or []
            if build_key not in ([needs_s] if isinstance(needs_s, str) else needs_s):
                out.append(f"{shared_key}: must need {build_key}")
            scalls = [s.get("run", "").strip() for s in sj.get("steps", []) if "shard_tests.py" in s.get("run", "")]
            swant = [f'{py} scripts/ci/shard_tests.py run-prebuilt {os_kind} ${{{{ matrix.shard }}}} "$RUNNER_TEMP/lib-bin/lib-tests"']
            if scalls != swant:
                out.append(f"{shared_key}: runner calls {scalls}, want exactly {swant!r}")
            for s in sj.get("steps", []):
                for leg in PIN.findall(str(s.get("if", ""))):
                    if leg not in shared_legs:
                        out.append(f"{shared_key}: step {s.get('name')!r} is pinned to {leg!r}, not a shard")
        steps = [s for s in agg.get("steps", []) if "scripts/ci/check_needs.py" in s.get("run", "")]
        # The verdict's command, without the shellcheck note above it.
        verdict = [" ".join(l.strip() for l in s.get("run", "").splitlines() if l.strip() and not l.strip().startswith("#"))
                   for s in steps]
        expects = [str((s.get("env") or {}).get("ROLLUP_EXPECTS", "")).split() for s in steps]
        if verdict != ["python3 scripts/ci/check_needs.py $ROLLUP_EXPECTS"] or expects != [want]:
            out.append(f"{agg_key}: verdict step {verdict} with ROLLUP_EXPECTS {expects} must pass exactly {want}")
        envs = [s.get("env", {}).get("NEEDS") for s in agg.get("steps", []) if "run" in s]
        if "${{ toJSON(needs) }}" not in envs:
            out.append(f"{agg_key}: verdict step must read NEEDS from toJSON(needs)")
    return out


# Option E: macos-shards' runner calls in order, each with its exact step gate and timeout (minutes).
SH, OL = "python3 scripts/ci/shard_tests.py", "python3 scripts/ci/obtain_lib.py"
B_TAKEN, INT_FOUND = "steps.obtain_b.outputs.found", "steps.obtain_int.outputs.found"
MACOS_E = [
    (f'{OL} lib-b "$RUNNER_TEMP/lib-xbuild"', "matrix.shard == 'lib-b' && env.MACOS_LIB_SOLO != 'true'", 80),
    (f'{SH} export-lib "$RUNNER_TEMP/lib-bin"', f"matrix.shard == 'lib-b' && {B_TAKEN} != 'true'", 120),
    (f"{SH} run macos lib-b", f"matrix.shard == 'lib-b' && {B_TAKEN} != 'true'", 45),
    (f'{SH} run-prebuilt macos lib-b "$LIB_BINARY"', f"matrix.shard == 'lib-b' && {B_TAKEN} == 'true'", 45),
    (f"{SH} run macos int", "matrix.shard == 'int'", 70),
    (f'{OL} int "$RUNNER_TEMP/lib-in"', "matrix.shard == 'int'", 215),
    (f'{SH} run-prebuilt macos lib-a "$LIB_BINARY"', f"(matrix.shard == 'int' && {INT_FOUND} == 'true') || "
     "(matrix.shard == 'lib-b' && env.MACOS_LIB_SOLO == 'true')", 40),
    (f"{SH} run macos lib-a", "matrix.shard == 'int' && steps.obtain_int.outputs.local_build == 'true'", 150),
]
XBUILD = ("macos-xbuild", "macOS lib test binary (cross-built)", "macos-lib-xbuild")  # job id, name, artifact
MACOS_LIMIT, XBUILD_LIMIT = 255, 65
UPLOAD = "actions/upload-artifact@"
REPORT = "Runner, swap and memory pressure during the build"


def obtain_module():
    spec = importlib.util.spec_from_file_location("obtain_lib", ROOT / "scripts/ci/obtain_lib.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def option_e_problems(jobs: dict, workflows: dict, ol) -> list[str]:
    """macOS legs, the Intel job and the advisory marker, against obtain_lib.py's tables (design r3 and its final
    amendment). `workflows` maps every workflow file to its jobs, for the advisory rules."""
    out = []
    shard, xb = jobs.get("macos-shards") or {}, jobs.get(XBUILD[0])
    if not xb:
        return [f"{XBUILD[0]} missing"]
    steps = shard.get("steps", [])
    runs = [s for s in steps if "scripts/ci/" in s.get("run", "") and ("shard_tests.py" in s.get("run", "")
                                                                         or "obtain_lib.py" in s.get("run", ""))]
    got = [(s.get("run", "").strip(), str(s.get("if", "")), s.get("timeout-minutes")) for s in runs]
    if got != MACOS_E:
        out.append(f"macos-shards: calls, gates and timeouts {got}, want exactly {MACOS_E}")
    if shard.get("timeout-minutes") != MACOS_LIMIT:
        out.append(f"macos-shards: timeout-minutes {shard.get('timeout-minutes')}, want {MACOS_LIMIT}")
    # The budget (amendment F5): each path's absolute cap plus every later step's limit fits the job's limit.
    t = {call: minutes for call, _, minutes in MACOS_E}
    uploads = [s for s in steps if UPLOAD in s.get("uses", "")]
    report = [s.get("timeout-minutes") for s in steps if s.get("name") == REPORT]
    up = uploads[0].get("timeout-minutes") if len(uploads) == 1 else None
    rep = report[0] if len(report) == 1 else None
    if not isinstance(up, int) or not isinstance(rep, int):
        return out + [f"macos-shards: one upload and one report step, each with a limit (got {up}, {rep})"]
    cap = {leg: ol.CAP[leg] // 60 for leg in ol.CAP}
    paths = {
        "lib-b fallback": cap["lib-b"] + t[MACOS_E[1][0]] + up + t[MACOS_E[2][0]] + rep,
        "lib-b found": cap["lib-b"] + t[MACOS_E[3][0]] + rep,
        "int found": cap["int"] + t[MACOS_E[6][0]] + rep,
        "int local build": ol.LOCAL_BUILD_BY // 60 + t[MACOS_E[7][0]] + rep,
    }
    for path, total in paths.items():
        if total > MACOS_LIMIT:
            out.append(f"macos-shards: the {path} path takes up to {total} min, over the job's {MACOS_LIMIT}")
    for (call, _, minutes), leg in ((MACOS_E[0], "lib-b"), (MACOS_E[5], "int")):
        if minutes != cap[leg] + 5:
            out.append(f"macos-shards: obtain {leg}'s step limit {minutes} is not its cap {cap[leg]} + 5")
    # Producers: obtain_lib's job and artifact names are the ones ci.yml gives them.
    lib_b_up = [s for s in uploads if (s.get("with") or {}).get("name") == ol.JOBS["lib-b"][1]]
    if ol.JOBS["lib-b"][0] != "macOS shard lib-b" or not lib_b_up:
        out.append(f"obtain_lib JOBS['lib-b'] {ol.JOBS['lib-b']} does not match macos-shards' name and upload")
    if ol.JOBS["xbuild"] != XBUILD[1:] or xb.get("name") != XBUILD[1]:
        out.append(f"{XBUILD[0]}: name {xb.get('name')!r} and obtain_lib JOBS['xbuild'] {ol.JOBS['xbuild']} "
                   f"must both be {XBUILD[1:]}")
    if ol.RUN_LIMIT["xbuild"] != XBUILD_LIMIT * 60 or xb.get("timeout-minutes") != XBUILD_LIMIT:
        out.append(f"{XBUILD[0]}: timeout-minutes and obtain_lib's RUN_LIMIT must both be {XBUILD_LIMIT} min")
    out += xbuild_job_problems(jobs, xb)
    out += advisory_problems(workflows)
    return out


def xbuild_job_problems(jobs: dict, xb: dict) -> list[str]:
    """The Intel job: runner, guard, advisory settings, step limits, the cross-build and its upload."""
    out = []
    alt = (" || (github.event_name == 'pull_request' && github.base_ref == 'docs/ranking-1-release-line'"
           " && " + LABELLED + ")")
    shards_if = str(jobs["macos-shards"].get("if", ""))
    if alt not in shards_if or str(xb.get("if", "")) != shards_if.replace(alt, ""):
        out.append(f"{XBUILD[0]}: if must be macos-shards' guard without the os-sensitive lane, exactly")
    if xb.get("runs-on") != "macos-15-intel":
        out.append(f"{XBUILD[0]}: runs-on {xb.get('runs-on')!r}, want 'macos-15-intel'")
    if xb.get("continue-on-error") is not True:
        out.append(f"{XBUILD[0]}: continue-on-error must be true, so a red Intel job never turns a run red")
    if (xb.get("env") or {}).get("MERGE_TRAIN_ADVISORY") != "true":
        out.append(f"{XBUILD[0]}: env MERGE_TRAIN_ADVISORY must be \"true\"")
    if xb.get("permissions") != {"contents": "read"}:
        out.append(f"{XBUILD[0]}: permissions must be contents: read only")
    limits = [s.get("timeout-minutes") for s in xb.get("steps", [])]
    if not all(isinstance(m, int) for m in limits) or sum(limits) > XBUILD_LIMIT:
        out.append(f"{XBUILD[0]}: step limits {limits} must all be set and sum to at most {XBUILD_LIMIT}")
    if any("continue-on-error" in s for s in xb.get("steps", [])):
        out.append(f"{XBUILD[0]}: no step-level continue-on-error (a failed step must stop the job)")
    export = [s for s in xb.get("steps", []) if "shard_tests.py" in s.get("run", "")]
    if ([s.get("run", "").strip() for s in export] != [f'{SH} export-lib "$RUNNER_TEMP/lib-bin"']
            or (export[0].get("env") or {}).get("CARGO_BUILD_TARGET") != "aarch64-apple-darwin"):
        out.append(f"{XBUILD[0]}: one export-lib call with CARGO_BUILD_TARGET aarch64-apple-darwin")
    up = [s.get("with") or {} for s in xb.get("steps", []) if UPLOAD in s.get("uses", "")]
    want = {"name": XBUILD[2], "path": "${{ runner.temp }}/lib-bin/lib-tests", "retention-days": 1,
            "overwrite": True, "if-no-files-found": "error"}
    if up != [want]:
        out.append(f"{XBUILD[0]}: upload {up}, want exactly [{want}]")
    return out


def advisory_problems(workflows: dict) -> list[str]:
    """MERGE_TRAIN_ADVISORY only on macos-xbuild, no other job under its name, no job needing it, in any file."""
    out = []
    for path, wf_jobs in workflows.items():
        for jid, job in (wf_jobs or {}).items():
            job = job or {}
            if jid == XBUILD[0] and path.endswith("/ci.yml"):
                continue
            if "MERGE_TRAIN_ADVISORY" in (job.get("env") or {}):
                out.append(f"{path} {jid}: MERGE_TRAIN_ADVISORY belongs to {XBUILD[0]} alone")
            if str(job.get("name", "")).strip() == XBUILD[1]:
                out.append(f"{path} {jid}: uses the advisory job's name {XBUILD[1]!r}")
            needs = job.get("needs") or []
            if XBUILD[0] in ([needs] if isinstance(needs, str) else needs):
                out.append(f"{path} {jid}: needs the advisory job {XBUILD[0]}")
    return out


def self_test(jobs: dict, st) -> None:
    """Each wiring rule fails on the mutation that breaks it."""
    import copy

    def broken(mutate) -> bool:
        j = copy.deepcopy(jobs)
        mutate(j)
        return bool(workflow_problems(j, st))

    mutations = {
        "bare !cancelled()": lambda j: j["test"].__setitem__("if", "${{ !cancelled() }}"),
        "always() runs it on a cancelled run": lambda j: j["test"].__setitem__(
            "if", str(j["test"]["if"]).replace("!cancelled()", "always()")),
        "no !cancelled()": lambda j: j["macos-check"].__setitem__("if", j["macos-shards"]["if"]),
        "dropped need": lambda j: j["windows-check"].__setitem__("needs", ["windows-shards"]),
        "renamed aggregate": lambda j: j["test"].__setitem__("name", "Tests (all)"),
        "shard named like the check": lambda j: j["macos-shards"].__setitem__("name", "macOS check"),
        "macOS shard without prefix": lambda j: j["macos-shards"].__setitem__("name", "mac shard x"),
        "verdict skips a job": lambda j: j["windows-check"]["steps"][-1]["env"].__setitem__(
            "ROLLUP_EXPECTS", "windows-shards"),
        "verdict ids typed into the run line": lambda j: j["windows-check"]["steps"][-1].__setitem__(
            "run", "python3 scripts/ci/check_needs.py windows-shards windows-clippy"),
        "merge-train skip dropped": lambda j: j["test"].__setitem__(
            "if", str(j["test"]["if"]).replace(" && " + TRAIN_SKIP, "")),
        "leg dropped": lambda j: j["test-shards"]["strategy"]["matrix"].__setitem__("shard", ["lib-a"]),
        "fail-fast": lambda j: j["windows-shards"]["strategy"].__setitem__("fail-fast", True),
        "clippy guard drift": lambda j: j["windows-clippy"].__setitem__("if", "${{ true }}"),
        "runner gets an extra argument": lambda j: next(
            s for s in j["windows-shards"]["steps"] if "shard_tests.py" in s.get("run", "")
        ).__setitem__("run", "python scripts/ci/shard_tests.py run windows ${{ matrix.shard }} --skip x"),
        "duty pinned to a missing shard": lambda j: next(
            s for s in j["test-shards"]["steps"] if "UPGRADING" in s.get("name", "")
        ).__setitem__("if", "matrix.shard == 'int-z'"),
        "shared leg dropped": lambda j: j["test-shards-lib"]["strategy"]["matrix"].__setitem__("shard", ["lib-a"]),
        "a shared leg also in the shard job": lambda j: j["test-shards"]["strategy"]["matrix"].__setitem__(
            "shard", ["int-a", "int-b", "lib-a"]),
        "shared legs skipped when the build fails": lambda j: j["test-shards-lib"].__setitem__(
            "if", j["test-shards"]["if"]),
        "shared legs build their own binary": lambda j: next(
            s for s in j["test-shards-lib"]["steps"] if "shard_tests.py" in s.get("run", "")
        ).__setitem__("run", "python3 scripts/ci/shard_tests.py run linux ${{ matrix.shard }}"),
        "shared legs renamed": lambda j: j["test-shards-lib"].__setitem__("name", "Linux lib shard ${{ matrix.shard }}"),
        "shared legs without the build need": lambda j: j["test-shards-lib"].__setitem__("needs", []),
        "shared legs fail-fast": lambda j: j["test-shards-lib"]["strategy"].__setitem__("fail-fast", True),
        "aggregate drops the shared legs": lambda j: j["test"].__setitem__(
            "needs", [n for n in j["test"]["needs"] if n != "test-shards-lib"]),
        "aggregate drops the shared build": lambda j: j["test"].__setitem__(
            "needs", [n for n in j["test"]["needs"] if n != "linux-lib-build"]),
        "shared duty pinned to a missing shard": lambda j: next(
            s for s in j["test-shards-lib"]["steps"] if "UPGRADING" in s.get("name", "")
        ).__setitem__("if", "matrix.shard == 'lib-z'"),
    }
    survived = [n for n, m in mutations.items() if not broken(m)]
    assert not survived, f"wiring mutations not caught: {survived}"
    # macOS takes exactly one of two forms: train-only (a static matrix, no label
    # clause), or labelled (fromJSON(cond && '["lib-b"]' || '<train list>') with the
    # label clause on both macOS jobs). Today's ci.yml may hold either.
    def bare(cond) -> str:
        cond = str(cond).strip()
        return cond[3:-2].strip() if cond.startswith("${{") and cond.endswith("}}") else cond

    # ci.yml's macOS guard ends in `(<not a PR> || <train>)`; labelled, the label's
    # alternative sits inside those parentheses.
    alt = (" || (github.event_name == 'pull_request' && github.base_ref == 'docs/ranking-1-release-line'"
           " && " + LABELLED + ")")
    train_guard = bare(jobs["macos-shards"]["if"]).replace(alt, "")
    labelled_guard = train_guard[:-1] + alt + ")"

    def labelled_form(j, a='["lib-b"]', b=None, clause_on=("macos-shards", "macos-check")):
        train = json.dumps(legs_of(st, "macos") if b is None else b)
        j["macos-shards"]["strategy"]["matrix"]["shard"] = (
            "${{ fromJson(" + LABELLED + " && '" + a + "' || '" + train + "') }}")
        shards = labelled_guard if "macos-shards" in clause_on else train_guard
        check = labelled_guard if "macos-check" in clause_on else train_guard
        j["macos-shards"]["if"] = "${{ " + shards + " }}"
        j["macos-check"]["if"] = "${{ !cancelled() && " + check + " && " + TRAIN_SKIP + " }}"

    def train_only(j):
        j["macos-shards"]["strategy"]["matrix"]["shard"] = legs_of(st, "macos")
        j["macos-shards"]["if"] = "${{ " + train_guard + " }}"
        j["macos-check"]["if"] = "${{ !cancelled() && " + train_guard + " && " + TRAIN_SKIP + " }}"

    for name, form in (("train-only", train_only), ("labelled", labelled_form)):
        j = copy.deepcopy(jobs)
        form(j)
        assert not workflow_problems(j, st), f"the {name} macOS form refused: {workflow_problems(j, st)}"
    mixtures = {
        "expression without the label clause": lambda j: labelled_form(j, clause_on=()),
        "label clause on a static matrix": lambda j: (train_only(j), j["macos-shards"].__setitem__(
            "if", "${{ " + labelled_guard + " }}"), j["macos-check"].__setitem__(
            "if", "${{ !cancelled() && " + labelled_guard + " && " + TRAIN_SKIP + " }}")),
        "label clause on one macOS job": lambda j: labelled_form(j, clause_on=("macos-shards",)),
        "train list missing a shard": lambda j: labelled_form(j, b=["lib-b"]),
        "labelled list without lib": lambda j: labelled_form(j, a='["int"]'),
    }
    survived = [n for n, m in mixtures.items() if not broken(m)]
    assert not survived, f"macOS form mixtures not caught: {survived}"
    for spelled in ("matrix.shard=='int-z'", 'matrix.shard == "int-z"', "matrix.shard  ==  'int-z'"):
        assert PIN.findall(spelled) == ["int-z"], spelled
    saved = st.SHARDS["linux"]["lib-b"]
    st.SHARDS["linux"]["lib-b"] = [("suite", ["--lib"], ["--skip", "other::"], 1)]
    try:
        assert table_problems(st), "a lib split that is not a complement passed"
    finally:
        st.SHARDS["linux"]["lib-b"] = saved
    # The library whole, in one unfiltered shard, is complete too; a second
    # lib shard beside it, filtered or not, would run some tests twice.
    linux = st.SHARDS["linux"]
    whole = [("suite", ["--lib"], [], 1)]
    try:
        st.SHARDS["linux"] = {k: v for k, v in linux.items() if k not in ("lib-a", "lib-b")} | {"lib": whole}
        assert not [p for p in table_problems(st) if "lib shards" in p], "one unfiltered lib shard refused"
        for extra in (whole, [("suite", ["--lib"], [st.LIB_SPLIT], 1)]):
            st.SHARDS["linux"] = {**st.SHARDS["linux"], "lib-x": extra}
            assert [p for p in table_problems(st) if "lib shards" in p], f"a whole lib plus {extra} passed"
            del st.SHARDS["linux"]["lib-x"]
    finally:
        st.SHARDS["linux"] = linux


def option_e_rows(jobs: dict, workflows: dict, ol) -> None:
    """Each option E rule fails on the mutation that breaks it, and the real files pass."""
    import copy
    import types

    def step(j, needle):
        return next(s for s in j["macos-shards"]["steps"] if needle in s.get("run", ""))

    def xstep(j, needle):
        return next(s for s in j[XBUILD[0]]["steps"] if needle in s.get("run", "") + s.get("uses", ""))

    def tables():
        return types.SimpleNamespace(CAP=dict(ol.CAP), LOCAL_BUILD_BY=ol.LOCAL_BUILD_BY, JOBS=dict(ol.JOBS),
                                     RUN_LIMIT=dict(ol.RUN_LIMIT))
    mutations = {
        "lib-b obtains in the solo lane": lambda j, w, o: step(j, "obtain_lib.py lib-b").__setitem__(
            "if", "matrix.shard == 'lib-b'"),
        "lib-b builds after taking a binary": lambda j, w, o: step(j, "export-lib").__setitem__(
            "if", "matrix.shard == 'lib-b'"),
        "obtain step limit not its cap + 5": lambda j, w, o: step(j, "obtain_lib.py lib-b").__setitem__(
            "timeout-minutes", 75),
        "job limit 240": lambda j, w, o: j["macos-shards"].__setitem__("timeout-minutes", 240),
        # Only the budget sum decides this one: the steps and their limits are untouched.
        "local build allowed past minute 100": lambda j, w, o: setattr(o, "LOCAL_BUILD_BY", 101 * 60),
        "lib-b's producer name drifts": lambda j, w, o: o.JOBS.__setitem__("lib-b", ("macOS lib-b", "macos-lib-tests")),
        "Intel job in the os-sensitive lane": lambda j, w, o: j[XBUILD[0]].__setitem__("if", j["macos-shards"]["if"]),
        "Intel job on an arm64 runner": lambda j, w, o: j[XBUILD[0]].__setitem__("runs-on", "macos-latest"),
        "Intel job turns a run red": lambda j, w, o: j[XBUILD[0]].pop("continue-on-error"),
        "advisory marker dropped": lambda j, w, o: j[XBUILD[0]]["env"].pop("MERGE_TRAIN_ADVISORY"),
        "Intel limit drifts from RUN_LIMIT": lambda j, w, o: j[XBUILD[0]].__setitem__("timeout-minutes", 70),
        "Intel step limits over the job's": lambda j, w, o: xstep(j, "export-lib").__setitem__("timeout-minutes", 60),
        "Intel step runs on after failing": lambda j, w, o: xstep(j, "export-lib").__setitem__("continue-on-error", True),
        "Intel build for its own arch": lambda j, w, o: xstep(j, "export-lib")["env"].pop("CARGO_BUILD_TARGET"),
        "Intel upload kept a week": lambda j, w, o: xstep(j, UPLOAD)["with"].__setitem__("retention-days", 7),
        "Intel job may write": lambda j, w, o: j[XBUILD[0]]["permissions"].__setitem__("actions", "write"),
        "Intel job renamed": lambda j, w, o: j[XBUILD[0]].__setitem__("name", "macOS lib (cross)"),
        "marker on another job": lambda j, w, o: j["macos-shards"]["env"].__setitem__("MERGE_TRAIN_ADVISORY", "true"),
        "another workflow uses the advisory name": lambda j, w, o: w.__setitem__(
            ".github/workflows/zz.yml", {"x": {"name": XBUILD[1]}}),
        "a job needs the advisory job": lambda j, w, o: j["macos-check"].__setitem__(
            "needs", ["macos-shards", XBUILD[0]]),
    }
    assert not option_e_problems(jobs, workflows, tables()), "the real files fail option E's rules"
    survived = []
    for name, mutate in mutations.items():
        j, w, o = copy.deepcopy(jobs), copy.deepcopy(workflows), tables()
        w[".github/workflows/ci.yml"] = j  # the advisory scan reads ci.yml's jobs through `workflows`
        mutate(j, w, o)
        if not option_e_problems(j, w, o):
            survived.append(name)
    assert not survived, f"option E mutations not caught: {survived}"


def cascade_rows() -> None:
    """The lib cascade rule accepts exact splits and refuses gaps and overlaps."""
    split = "gateway::"
    accepted = {
        "whole lib": [()],
        "one filter and its skip": [(split,), ("--skip", split)],
        "three-way cascade": [(split,), ("a::", "b::", "--skip", split), ("--skip", split, "--skip", "a::", "--skip", "b::")],
    }
    refused = {
        "skip of another filter (gap)": [(split,), ("--skip", "other::")],
        "catch-all forgets a group (overlap)": [(split,), ("a::", "--skip", split), ("--skip", split)],
        "middle shard does not skip the earlier group": [(split,), ("a::",), ("--skip", split, "--skip", "a::")],
        "a shard takes a group an earlier one took": [(split,), (split, "--skip", split), ("--skip", split)],
        "two catch-alls": [(split,), ("--skip", split), ("--skip", split)],
        # Every name containing x::gateway:: also contains gateway::, so the skip empties that shard.
        "a later filter contains an earlier one (selects nothing)": [
            (split,), ("x::" + split, "--skip", split), ("--skip", split, "--skip", "x::" + split)],
    }
    for name, filters in accepted.items():
        assert lib_cascade(filters), f"cascade rule refused a valid split: {name}"
    for name, filters in refused.items():
        assert not lib_cascade(filters), f"cascade rule accepted a broken split: {name}"


def main() -> int:
    st = runner()
    jobs = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text())["jobs"]
    workflows = {str(p.relative_to(ROOT)): (yaml.safe_load(p.read_text()) or {}).get("jobs") or {}
                 for p in sorted((ROOT / ".github" / "workflows").glob("*.y*ml"))}
    ol = obtain_module()
    problems = table_problems(st) + workflow_problems(jobs, st) + option_e_problems(jobs, workflows, ol)
    for p in problems:
        print(f"os-shards: {p}")
    if problems:
        return 1
    self_test(jobs, st)
    option_e_rows(jobs, workflows, ol)
    cascade_rows()
    print(f"os-shards: {sum(len(s) for s in st.SHARDS.values())} shards on 3 OSes are complete; wiring holds")
    return 0


if __name__ == "__main__":
    sys.exit(main())

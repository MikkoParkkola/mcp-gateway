#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Check that a *listening* gateway carries the merged security controls.

NFR.SEC.7, MIK-7265. Design:
`docs/design/2026-09-11-merged-versus-listening-drift-check.md`.

A green test suite cannot see this class of failure: every test in this
repository runs against a build made from the tree under test, and drift lives
in the distance between that tree and whatever is answering on a port.

Each probe has two halves and both decide. The negative half sends the request
the control exists to refuse and requires the refusal. The positive half sends a
legitimate request along the same path and requires it to succeed -- otherwise an
auth wall, a fronting proxy, or a wedged process reads as the control firing, and
the check goes green against exactly the install it exists to interrogate.

The probe decides; build provenance only corroborates, because a control can be
merged into a build and still disabled by configuration, shadowed by a refactor,
or wired behind a feature flag the install does not set.

    python3 scripts/dev/check-control-drift.py http://127.0.0.1:39401/mcp
"""

from __future__ import annotations

import argparse
import http.client
import json
import subprocess
import sys
import tomllib
from pathlib import Path
from urllib.parse import urlparse

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = REPO_ROOT / "security-controls.toml"
TIMEOUT_SECONDS = 5
FOREIGN_ORIGIN = "http://drift-check.invalid"
FOREIGN_HOST = "drift-check.invalid"
REQUEST_BODY = json.dumps(
    {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
).encode()
# Not parseable as JSON at all: the body ceiling and the JSON parse are the
# same early return, and an unclosed brace reaches it without sending 10 MiB.
MALFORMED_JSON_BODY = b'{"jsonrpc": "2.0", "id": 1, "method":'
# Parseable, and not a JSON-RPC request: no `method`, and no `result`/`error`
# either -- a frame with those two would be routed to the POST-back branch
# before the envelope check and would never reach the gate this probe names.
MALFORMED_ENVELOPE_BODY = json.dumps({"jsonrpc": "2.0", "id": 1}).encode()
# A null byte inside a string value. Valid JSON by construction, so it clears
# the parse and lands on the sanitizer, which refuses NUL by contract.
NULL_BYTE_BODY = json.dumps(
    {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        # chr(0), not an escape in this source file: a literal NUL here would
        # make the checker itself unparseable.
        "params": {"drift": "a" + chr(0) + "b"},
    }
).encode()


class Unreachable(Exception):
    """The endpoint never answered. Not a verdict about any control."""


class Unreadable(Exception):
    """An authority could not be read. Not a verdict about coverage either."""


def load_manifest(path):
    with open(path, "rb") as handle:
        return tomllib.load(handle).get("control", [])


def _post(endpoint, extra_headers=None, host_header=None, body=REQUEST_BODY):
    """POST one JSON-RPC request and return the HTTP status.

    Raises `Unreachable` rather than returning a status, because "nothing
    answered" must never be scored as a refusal.
    """
    parts = urlparse(endpoint)
    authority = parts.netloc
    path = parts.path or "/"
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "Content-Length": str(len(body)),
        "Host": host_header or authority,
    }
    headers.update(extra_headers or {})
    conn_class = (
        http.client.HTTPSConnection if parts.scheme == "https" else http.client.HTTPConnection
    )
    conn = conn_class(authority, timeout=TIMEOUT_SECONDS)
    try:
        # skip_host: the Host header above is the payload of the host probe.
        conn.putrequest("POST", path, skip_host=True, skip_accept_encoding=True)
        for name, value in headers.items():
            conn.putheader(name, value)
        conn.endheaders(body)
        response = conn.getresponse()
        # The body is deliberately left unread: a Streamable-HTTP server may
        # answer the legitimate request with an open `text/event-stream`, and
        # reading it would block until the timeout and report a live install as
        # unreachable. The status line is the whole verdict, and the connection
        # is closed below rather than reused.
        return response.status
    except (OSError, http.client.HTTPException) as exc:
        raise Unreachable(str(exc)) from exc
    finally:
        conn.close()


def probe_foreign_origin(endpoint, headers):
    negative = _post(endpoint, {**headers, "Origin": FOREIGN_ORIGIN})
    positive = _post(endpoint, headers)
    return negative, positive


def probe_foreign_host(endpoint, headers):
    negative = _post(endpoint, headers, host_header=FOREIGN_HOST)
    positive = _post(endpoint, headers)
    return negative, positive


def probe_malformed_json(endpoint, headers):
    return _post(endpoint, headers, body=MALFORMED_JSON_BODY), _post(endpoint, headers)


def probe_malformed_envelope(endpoint, headers):
    return _post(endpoint, headers, body=MALFORMED_ENVELOPE_BODY), _post(endpoint, headers)


def probe_null_byte(endpoint, headers):
    return _post(endpoint, headers, body=NULL_BYTE_BODY), _post(endpoint, headers)


PROBES = {
    "foreign-origin": probe_foreign_origin,
    "foreign-host": probe_foreign_host,
    "malformed-json": probe_malformed_json,
    "malformed-envelope": probe_malformed_envelope,
    "null-byte": probe_null_byte,
}


def _health_version(endpoint):
    """Best-effort read of the version the endpoint reports. None if absent."""
    parts = urlparse(endpoint)
    try:
        conn_class = (
            http.client.HTTPSConnection
            if parts.scheme == "https"
            else http.client.HTTPConnection
        )
        conn = conn_class(parts.netloc, timeout=TIMEOUT_SECONDS)
        try:
            conn.request("GET", "/health")
            response = conn.getresponse()
            payload = json.loads(response.read() or b"{}")
        finally:
            conn.close()
        return payload.get("version")
    except (OSError, http.client.HTTPException, ValueError):
        return None


def _provenance(commit, version, repo_root):
    """One sentence on whether `commit` is in the build, or why we cannot tell.

    Corroboration only. The reported version is the coarsest possible handle on
    the build -- it names a release, not a commit -- so a control merged after
    the release tag is reported as absent from the build and a control merged
    before it is reported as present *in the tag*, which the probe still has to
    confirm on the wire.
    """
    if not version:
        return "provenance unavailable: the endpoint reports no version"
    tag = f"v{version}"
    def git(*args):
        return subprocess.run(
            ["git", "-C", str(repo_root), *args],
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SECONDS,
        )

    try:
        if git("rev-parse", "--verify", f"{tag}^{{commit}}").returncode != 0:
            return f"provenance unavailable: {tag} is not a tag in this repository"
        if git("rev-parse", "--verify", f"{commit}^{{commit}}").returncode != 0:
            return f"provenance unavailable: {commit} is not a commit in this repository"
        if git("merge-base", "--is-ancestor", commit, tag).returncode == 0:
            return f"provenance: {commit} is in {tag}"
    except subprocess.TimeoutExpired:
        return "provenance unavailable: git did not answer within the timeout"
    return f"provenance: {commit} is NOT in {tag} -- the build predates the control"


def _section(text, heading_prefix):
    """Lines under the first `## ` heading with this prefix, up to the next one."""
    lines = text.splitlines()
    out = []
    inside = False
    for line in lines:
        if line.startswith("## "):
            if inside:
                break
            inside = line.startswith(f"## {heading_prefix}")
            continue
        if inside:
            out.append(line)
    return out


def _cells(line):
    if not line.startswith("|"):
        return None
    cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
    if all(set(cell) <= {"-", ":"} and cell for cell in cells):
        return None  # the separator row
    return cells


def read_inventory(path):
    """Authority 1: the NFR.SEC.1 request-path inventory, as `{key: label}`.

    Two tables, because the document keeps two: the numbered set of gates a
    3.5.0 caller met, and its own exclusion table of the controls 4.0.0 added.
    NFR.SEC.1 needs only the first; NFR.SEC.7 asks about every merged control,
    so it needs both.

    Raises `Unreadable` when either table yields nothing. A parser that
    silently reads zero rows out of a reformatted document would turn the whole
    coverage gate green, which is the failure this check exists to forbid.
    """
    text = Path(path).read_text(encoding="utf-8")
    found = {}
    for line in _section(text, "The set"):
        cells = _cells(line)
        if cells and len(cells) >= 2 and cells[0].isdigit():
            found[f"nfr-sec1:{cells[0]}"] = cells[1]
    numbered = len(found)
    for line in _section(text, "Controls that are NOT in the set"):
        cells = _cells(line)
        if cells and len(cells) >= 2 and cells[0] and cells[0] != "control":
            found[f"nfr-sec1-new:{cells[0]}"] = cells[0]
    if not numbered or len(found) == numbered:
        raise Unreadable(
            f"{path}: expected a numbered control table and an exclusion table;"
            f" read {numbered} numbered rows and {len(found) - numbered} excluded rows"
        )
    return found


def read_modules(repo_root, roots):
    """Authority 2: the security module inventory, at one level per root.

    Code, not a document: a module merged into a swept root is in the
    population whether or not anyone remembered to write it down. A directory
    counts as one module -- `firewall/` is one control with eight files, and
    splitting a control across more files is not a coverage change.
    """
    modules = []
    for root in roots:
        base = Path(repo_root) / root
        if not base.is_dir():
            raise Unreadable(f"{root}: swept root does not exist under {repo_root}")
        for entry in sorted(base.iterdir()):
            if entry.is_dir():
                modules.append(f"{root}/{entry.name}")
            elif entry.suffix == ".rs" and entry.stem != "mod" and not entry.stem.endswith(
                ("_tests", "_support")
            ):
                modules.append(f"{root}/{entry.name}")
    if not modules:
        raise Unreadable(f"no modules found under {roots}; the sweep read nothing")
    return modules


def check_coverage(manifest_path=DEFAULT_MANIFEST, repo_root=REPO_ROOT):
    """Return `(exit_code, report)` for the manifest's coverage of its authorities.

    The probes answer "is this control listening". This answers the question
    that makes those answers worth anything: "is this the set of controls".
    A manifest that defines its own population cannot be incomplete, and a
    check that cannot be incomplete proves nothing when it passes.
    """
    with open(manifest_path, "rb") as handle:
        data = tomllib.load(handle)
    controls = data.get("control", [])
    coverage = data.get("coverage", {})
    lines = []
    gaps = 0

    try:
        inventory = read_inventory(Path(repo_root) / coverage["inventory"])
        modules = read_modules(repo_root, coverage.get("module_roots", []))
    except (Unreadable, KeyError, OSError) as exc:
        return 1, f"FAIL: the authority could not be read ({exc}); coverage is undecided"

    claimed = {control["authority"] for control in controls if control.get("authority")}
    for key, label in sorted(inventory.items()):
        if key not in claimed:
            gaps += 1
            lines.append(f"COVERAGE GAP: the authority lists {key} ({label}); no control claims it")
    for stale in sorted(claimed - set(inventory)):
        gaps += 1
        lines.append(f"COVERAGE GAP: a control claims {stale}, which the authority does not list")

    sources = [control.get("source", "") for control in controls]
    excluded = {row["module"]: row["reason"] for row in coverage.get("not_a_control", [])}
    for module in modules:
        if module in excluded:
            continue
        if not any(src == module or src.startswith(f"{module}/") for src in sources):
            gaps += 1
            lines.append(
                f"COVERAGE GAP: {module} is a security module no control names"
                " -- add a control row, or record it under [[coverage.not_a_control]] with the reason"
            )
    for module, reason in sorted(excluded.items()):
        if module not in modules:
            gaps += 1
            lines.append(f"COVERAGE GAP: {module} is excluded ({reason}) but is not a module under a swept root")

    # A source that has moved is a control that may have moved with it, and the
    # row still names the old path: the manifest reads complete while the gate
    # it describes is somewhere else, or gone.
    for control in controls:
        source = control.get("source")
        if source and not (Path(repo_root) / source).exists():
            gaps += 1
            lines.append(f"COVERAGE GAP: {control['id']} names {source}, which does not exist")

    lines.append(
        f"{len(inventory)} authority rows, {len(modules)} security modules,"
        f" {len(controls)} manifest controls, {gaps} coverage gaps"
    )
    return (1 if gaps else 0), "\n".join(lines)


def run(manifest_path=DEFAULT_MANIFEST, endpoint=None, version=None, repo_root=REPO_ROOT, headers=None):
    """Return `(exit_code, report)`. Exit code is the verdict; report is text."""
    controls = load_manifest(manifest_path)
    headers = headers or {}
    if version is None:
        version = _health_version(endpoint)
    lines = []
    failures = 0
    probed = 0
    for control in controls:
        name = control["id"]
        probe = control.get("probe", "none")
        if probe == "none":
            reason = control.get("reason", "no reason recorded")
            lines.append(f"{name}: uncovered -- {reason}")
            continue
        if probe not in PROBES:
            failures += 1
            lines.append(f"{name}: FAIL -- manifest names probe '{probe}', which does not exist")
            continue
        note = _provenance(control["introduced_in"], version, repo_root)
        try:
            negative, positive = PROBES[probe](endpoint, headers)
        except Unreachable as exc:
            failures += 1
            lines.append(f"{name}: FAIL -- endpoint unreachable ({exc}); no verdict about the control")
            continue
        probed += 1
        expected = control.get("refusal_status")
        verdicts = []
        if negative < 400:
            failures += 1
            verdicts.append(f"FAIL: the refused request was answered {negative}")
        elif negative >= 500:
            failures += 1
            verdicts.append(
                f"FAIL: the refused request errored {negative}"
                " -- a broken handler answers every request that way; it is not"
                " evidence the control refused"
            )
        elif expected is not None and negative != expected:
            # 4xx is a refusal by someone. `refusal_status` is how a control
            # whose own answer is known says which someone: a fronting proxy
            # returning 413 for an oversized body, or 401 for a credential it
            # decided about, is not this gate firing.
            failures += 1
            verdicts.append(
                f"FAIL: refused {negative}, but this control refuses {expected}"
                " -- something ahead of it answered"
            )
        else:
            verdicts.append(f"refused {negative}")
        if positive >= 400:
            failures += 1
            verdicts.append(
                f"FAIL: the legitimate request was also refused {positive}"
                " -- an auth wall, a fronting proxy or a wedged process, not this control"
            )
        else:
            verdicts.append(f"legitimate request {positive}")
        lines.append(f"{name}: {'; '.join(verdicts)} [{note}]")

    if probed == 0:
        failures += 1
        lines.append(
            "FAIL: no control was probed -- a manifest of uncovered controls"
            " cannot report an absence of drift"
        )
    lines.append(f"{probed} probed, {len(controls) - probed} uncovered, {failures} failing")
    return (1 if failures else 0), "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "endpoint",
        nargs="?",
        help="MCP endpoint of the listening gateway, e.g. http://127.0.0.1:39401/mcp",
    )
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    parser.add_argument("--version", default=None, help="override the build version used for provenance")
    parser.add_argument(
        "--coverage-only",
        action="store_true",
        help="check the manifest against its authorities and stop; needs no listening install",
    )
    parser.add_argument(
        "--header",
        action="append",
        default=[],
        metavar="NAME: VALUE",
        help="extra request header, repeatable (use for credentials: the positive half must succeed)",
    )
    args = parser.parse_args(argv)
    if not args.endpoint and not args.coverage_only:
        parser.error("an endpoint is required unless --coverage-only is given")
    headers = {}
    for raw in args.header:
        name, _, value = raw.partition(":")
        headers[name.strip()] = value.strip()
    # Coverage first, and always: a probe report reads as a coverage claim, and
    # it is only one if the manifest is the set. Both run, so a coverage gap
    # never hides which controls are live.
    code, report = check_coverage(args.manifest)
    print(report)
    if args.coverage_only:
        return code
    probe_code, probe_report = run(args.manifest, args.endpoint, args.version, headers=headers)
    print(probe_report)
    return code or probe_code


if __name__ == "__main__":
    sys.exit(main())

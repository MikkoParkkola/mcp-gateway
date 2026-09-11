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


class Unreachable(Exception):
    """The endpoint never answered. Not a verdict about any control."""


def load_manifest(path):
    with open(path, "rb") as handle:
        return tomllib.load(handle).get("control", [])


def _post(endpoint, extra_headers=None, host_header=None):
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
        "Content-Length": str(len(REQUEST_BODY)),
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
        conn.endheaders(REQUEST_BODY)
        response = conn.getresponse()
        response.read()
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


PROBES = {
    "foreign-origin": probe_foreign_origin,
    "foreign-host": probe_foreign_host,
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
        conn.request("GET", "/health")
        response = conn.getresponse()
        payload = json.loads(response.read() or b"{}")
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
        )

    if git("rev-parse", "--verify", f"{tag}^{{commit}}").returncode != 0:
        return f"provenance unavailable: {tag} is not a tag in this repository"
    if git("rev-parse", "--verify", f"{commit}^{{commit}}").returncode != 0:
        return f"provenance unavailable: {commit} is not a commit in this repository"
    if git("merge-base", "--is-ancestor", commit, tag).returncode == 0:
        return f"provenance: {commit} is in {tag}"
    return f"provenance: {commit} is NOT in {tag} -- the build predates the control"


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
        verdicts = []
        if negative < 400:
            failures += 1
            verdicts.append(f"FAIL: the refused request was answered {negative}")
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
    parser.add_argument("endpoint", help="MCP endpoint of the listening gateway, e.g. http://127.0.0.1:39401/mcp")
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    parser.add_argument("--version", default=None, help="override the build version used for provenance")
    parser.add_argument(
        "--header",
        action="append",
        default=[],
        metavar="NAME: VALUE",
        help="extra request header, repeatable (use for credentials: the positive half must succeed)",
    )
    args = parser.parse_args(argv)
    headers = {}
    for raw in args.header:
        name, _, value = raw.partition(":")
        headers[name.strip()] = value.strip()
    code, report = run(args.manifest, args.endpoint, args.version, headers=headers)
    print(report)
    return code


if __name__ == "__main__":
    sys.exit(main())

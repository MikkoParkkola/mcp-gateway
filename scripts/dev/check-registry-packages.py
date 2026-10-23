#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Fail when a built-in registry entry points at something that does not exist.

`mcp-gateway add <name>` writes whatever src/registry/server_registry_entries.rs says.
On 2026-10-02, 30 of its 45 npx packages were 404 on npm and 7 more were
deprecated, and nothing noticed. Every entry must now be one of:

- `npx -y <package>@<exact version> [args]`: the version exists on npm and is
  not deprecated;
- `uvx <package>@<exact version> [args]`: the release exists on PyPI and is not
  yanked;
- an HTTP entry whose default URL answers (any status but 404/410/5xx; hosted
  MCP endpoints answer 401/400/405 to an unauthenticated GET).

Anything else, including an unpinned package or an unknown launcher, fails.
Network: one request per entry, retried; a registry outage fails the job
rather than passing it.

Usage: check-registry-packages.py [--offline | --start] [--integrity SIDECAR]
       [path-to-server_registry_entries.rs]

--offline applies the pin, launcher and sidecar rules without any network
lookup; it runs on every pull request. The live lookups run where the
registry changes, on pushes and daily (.github/workflows/registry-packages.yml).

MIK-8513: every pinned artifact has its reviewed digest in the sidecar
(default scripts/dev/registry-integrity.json); the live lookup compares it
with what npm or PyPI publishes. --start (needs Docker) has the package
manager fetch each artifact in a locked-down container and check its real
bytes, then starts every eligible stdio entry with its network off and
requires an answer to `initialize`.
"""

from __future__ import annotations

import json
import os
import re
import selectors
import subprocess
import sys
import time
import uuid
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

DEFAULT_SOURCE = Path(__file__).resolve().parents[2] / "src/registry/server_registry_entries.rs"
ENTRY_RE = re.compile(r"ServerCatalogEntry \{(.*?)\n    \},", re.S)
# `\s*` around the value: rustfmt moves a long string onto the next line.
FIELD_RE = {
    "name": re.compile(r'\bname:\s*"([^"]*)"'),
    "command": re.compile(r'\bcommand:\s*"([^"]*)"'),
    "url": re.compile(r'\bdefault_url:\s*"([^"]*)"'),
    "auth": re.compile(r"\bauth:\s*Auth::(\w+)"),
    # MIK-8513: what the start check needs to decide eligibility.
    "setup": re.compile(r"\bsetup:\s*Setup::(\w+)"),
    "hint": re.compile(r'\bhint:\s*"([^"]*)"'),
    "required_env": re.compile(r"\brequired_env:\s*&\[([^\]]*)\]"),
}
# Exact versions only: a range or a dist-tag resolves to something new later.
# npm reads `pkg@1` and `pkg@1.2` as ranges, so npm needs all three parts;
# `uvx pkg@1.2` pins `==1.2` exactly.
VERSION_RE = {
    "npm": re.compile(r"^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$"),
    "pypi": re.compile(r"^\d+(\.\d+)+([.-]?(a|b|rc|post|dev)\d+)*$"),
}


def parse_entries(source: str) -> list[dict[str, str]]:
    """Every `ServerCatalogEntry { .. }` block; one that yields no name is kept
    with a placeholder so `classify` fails it instead of the check skipping it."""
    entries = []
    for index, block in enumerate(ENTRY_RE.findall(source)):
        entry = {}
        for key, rx in FIELD_RE.items():
            m = rx.search(block)
            if m:
                entry[key] = m.group(1)
        if "name" not in entry:
            entry = {"name": f"<entry #{index + 1}>", "unparsed": "1"}
        entries.append(entry)
    return entries


def split_pinned(spec: str, kind: str) -> tuple[str, str] | None:
    """`@scope/pkg@1.2.3` -> (`@scope/pkg`, `1.2.3`); None when unpinned."""
    at = spec.rfind("@")
    if at <= 0:
        return None
    pkg, version = spec[:at], spec[at + 1 :]
    return (pkg, version) if VERSION_RE[kind].match(version) else None


def classify(entry: dict[str, str]) -> tuple[str, str, str] | str:
    """Return (kind, target, version) to probe, or an error string."""
    if entry.get("unparsed"):
        return "entry could not be parsed (no name field found)"
    if entry.get("url"):
        # The registry writes no client_id for an OAuth entry, so the endpoint
        # must offer dynamic client registration; a header entry must refuse
        # an unauthenticated request rather than serve it.
        kind = {"OAuth": "http-oauth", "Header": "http-header"}.get(entry.get("auth", ""), "http")
        return (kind, entry["url"], "")
    tokens = entry.get("command", "").split()
    if not tokens:
        return "no command and no default_url"
    if tokens[0] == "npx":
        rest = [t for t in tokens[1:] if t not in ("-y", "--yes")]
        kind = "npm"
    elif tokens[0] == "uvx":
        rest = tokens[1:]
        kind = "pypi"
    else:
        return f"unknown launcher '{tokens[0]}' (expected npx, uvx or an HTTP url)"
    if not rest or rest[0].startswith("-"):
        return "launcher has no package argument"
    pinned = split_pinned(rest[0], kind)
    if pinned is None:
        return f"'{rest[0]}' is not pinned to an exact version (<package>@<x.y.z>)"
    return (kind, pinned[0], pinned[1])


# MIK-8513: the reviewed digest of every pinned artifact. Outside `src/` so
# Cargo's `include = ["src/**"]` never publishes it; only Python reads it.
DEFAULT_INTEGRITY = Path(__file__).resolve().parent / "registry-integrity.json"
DIGEST_RE = {
    "npm": re.compile(r"^sha512-[A-Za-z0-9+/]{86}==$"),
    "pypi": re.compile(r"^[0-9a-f]{64}$"),
}


def record_key(kind: str, pkg: str, version: str) -> str:
    """The sidecar key for a pin: `pkg@ver` on npm, `pkg==ver` on PyPI."""
    return f"{pkg}@{version}" if kind == "npm" else f"{pkg}=={version}"


def load_integrity(path: Path) -> tuple[dict, list[str]]:
    """The sidecar's records and every format problem in it, as FAIL reasons."""
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError) as e:
        return {"npm": {}, "pypi": {}}, [f"integrity file {path}: {e}"]
    if not isinstance(data, dict) or not all(isinstance(data.get(k, {}), dict) for k in ("npm", "pypi")):
        return {"npm": {}, "pypi": {}}, [f"integrity file {path}: expected {{\"npm\": {{...}}, \"pypi\": {{...}}}}"]
    records = {"npm": data.get("npm") or {}, "pypi": data.get("pypi") or {}}
    errors = []
    for key, digest in records["npm"].items():
        if not isinstance(digest, str) or not DIGEST_RE["npm"].match(digest):
            errors.append(f"integrity record {key}: not a sha512- dist.integrity value")
    for key, files in records["pypi"].items():
        if not isinstance(files, dict) or not files:
            errors.append(f"integrity record {key}: not a {{filename: sha256}} map")
            continue
        for name, digest in files.items():
            if not isinstance(digest, str) or not DIGEST_RE["pypi"].match(digest):
                errors.append(f"integrity record {key} {name}: not a lowercase hex sha256")
    return records, errors


def integrity_failures(entries: list[dict[str, str]], records: dict) -> tuple[dict, list[str]]:
    """Per-entry missing records, and records no entry pins (orphans)."""
    missing, used = {}, set()
    for entry in entries:
        plan = classify(entry)
        if isinstance(plan, str) or plan[0] not in ("npm", "pypi"):
            continue
        key = record_key(*plan)
        used.add((plan[0], key))
        if key not in records[plan[0]]:
            missing[entry["name"]] = f"no integrity record for {key}"
    orphans = [
        f"integrity record {key}: orphan, no entry pins it"
        for kind in ("npm", "pypi")
        for key in records[kind]
        if (kind, key) not in used
    ]
    return missing, orphans

def fetch(url: str, body: bytes | None = None) -> tuple[int, bytes]:
    """GET `url`, or POST `body` as JSON when one is given."""
    last: Exception | None = None
    headers = {"User-Agent": "mcp-gateway-registry-check"}
    if body is not None:
        headers.update({"Content-Type": "application/json", "Accept": "application/json, text/event-stream"})
    for attempt in range(3):
        req = urllib.request.Request(url, data=body, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            if e.code < 500:
                return e.code, b""
            last = e
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            last = e
        time.sleep(2 * (attempt + 1))
    raise RuntimeError(f"unreachable after 3 attempts: {last}")


# An MCP `initialize` with no credential, for a header entry whose GET is 405.
UNAUTHENTICATED_INITIALIZE = json.dumps({
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "mcp-gateway-registry-check", "version": "1"},
    },
}).encode()


def well_known(base: str, suffix: str) -> str:
    """RFC 8414 path insertion, as `src/oauth/metadata.rs` `well_known_url` builds it."""
    parts = urlsplit(base)
    return f"{parts.scheme}://{parts.netloc}/.well-known/{suffix}{parts.path.rstrip('/')}"


def fetch_json(url: str) -> dict:
    try:
        status, body = fetch(url)
        return json.loads(body) if status == 200 else {}
    except (RuntimeError, ValueError):
        return {}


def registration_endpoint(url: str) -> str | None:
    """Discover the way the gateway's backend OAuth client does
    (`src/oauth/client/mod.rs` `initialize`): protected-resource metadata at
    the resource's origin, its FIRST authorization server (else the origin),
    that server's RFC 8414 metadata with its issuer checked, then the
    `registration_endpoint` the gateway registers at when it has no client_id."""
    parts = urlsplit(url)
    origin = f"{parts.scheme}://{parts.netloc}"
    servers = fetch_json(well_known(origin, "oauth-protected-resource")).get("authorization_servers") or []
    server, advertised = (servers[0], True) if servers else (origin, False)
    meta = fetch_json(well_known(server, "oauth-authorization-server"))
    issuer = meta.get("issuer", "")
    if (issuer if advertised else issuer.rstrip("/")) != server:
        return None
    return meta.get("registration_endpoint")


def probe(kind: str, target: str, version: str, expected=None) -> str | None:
    """Return None when the target resolves, else the reason it does not.

    `expected` is the sidecar record (MIK-8513): an npm `dist.integrity`, or a
    PyPI `{filename: sha256}` map that must equal the served file set exactly."""
    try:
        if kind == "npm":
            status, body = fetch(f"https://registry.npmjs.org/{target}/{version}")
            if status != 200:
                return f"npm {target}@{version}: HTTP {status}"
            doc = json.loads(body)
            deprecated = doc.get("deprecated")
            if deprecated:
                return f"npm {target}@{version} is deprecated: {deprecated}"
            served = (doc.get("dist") or {}).get("integrity")
            if expected is not None and served != expected:
                return f"npm {target}@{version}: integrity {served or 'missing'} is not the recorded {expected}"
            return None
        if kind == "pypi":
            status, body = fetch(f"https://pypi.org/pypi/{target}/{version}/json")
            if status != 200:
                return f"PyPI {target}=={version}: HTTP {status}"
            files = json.loads(body).get("urls", [])
            if not files:
                return f"PyPI {target}=={version} has no distribution files"
            if all(f.get("yanked") for f in files):
                return f"PyPI {target}=={version} is yanked"
            served = {f.get("filename"): (f.get("digests") or {}).get("sha256") for f in files}
            if expected is not None and served != expected:
                added_or_dropped = set(served) ^ set(expected)
                rehashed = {n for n in served if n in expected and served[n] != expected[n]}
                changed = sorted(added_or_dropped | rehashed)
                return f"PyPI {target}=={version}: integrity differs from the record for {', '.join(changed)}"
            return None
        status, _ = fetch(target)
        if status in (404, 410):
            return f"{target}: HTTP {status}"
        if kind == "http-header" and status == 405:
            # A streamable endpoint need not serve GET, so a 405 says nothing
            # about credentials: ask the way a client would (MIK-7817).
            status, _ = fetch(target, UNAUTHENTICATED_INITIALIZE)
            if status in (404, 405, 410):
                return f"{target}: HTTP {status} to POST as well; it does not serve MCP at this URL"
        if kind == "http-header" and status not in (401, 403):
            return f"{target}: HTTP {status} without a credential (a header entry must refuse it)"
        if kind == "http-oauth" and not registration_endpoint(target):
            return f"{target}: no dynamic client registration in its OAuth metadata"
        return None
    except RuntimeError as e:
        return f"{target}: {e}"


STDOUT_BUDGET = 1024 * 1024
STDERR_TAIL = 4096


def handshake(argv: list[str], timeout: float) -> str | None:
    """Start `argv`, send one `initialize`, and return None once a valid reply
    arrives, else why not. Reads in chunks against a byte budget, keeps only the
    last 4 KiB of stderr, and always kills the process before returning."""
    proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    sel = selectors.DefaultSelector()
    try:
        try:
            proc.stdin.write(UNAUTHENTICATED_INITIALIZE + b"\n")
            proc.stdin.flush()
        except OSError as e:
            return f"closed its input before the initialize request was written ({e.__class__.__name__})"
        sel.register(proc.stdout, selectors.EVENT_READ, "out")
        sel.register(proc.stderr, selectors.EVENT_READ, "err")
        out, err, seen = b"", b"", 0
        deadline = time.monotonic() + timeout
        while sel.get_map():
            left = deadline - time.monotonic()
            if left <= 0:
                return f"did not answer initialize within {timeout:g} s"
            for key, _ in sel.select(left):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    sel.unregister(key.fileobj)
                    continue
                if key.data == "err":
                    err = (err + chunk)[-STDERR_TAIL:]
                    continue
                seen += len(chunk)
                if seen > STDOUT_BUDGET:
                    return f"wrote over the {STDOUT_BUDGET} byte budget before answering initialize"
                out += chunk
                while b"\n" in out:
                    line, out = out.split(b"\n", 1)
                    verdict = judge_reply(line)
                    if verdict != "notification":
                        return verdict
        code = proc.wait(timeout=5)
        tail = err.decode(errors="replace").strip()
        return f"exited {code} before answering initialize" + (f"; stderr tail: {tail}" if tail else "")
    finally:
        sel.close()
        proc.kill()
        proc.wait()


def judge_reply(line: bytes) -> str | None:
    """None for a valid `initialize` result, "notification" for a message
    without an id (servers may log first), else the FAIL reason."""
    if not line.strip():
        return "notification"
    try:
        msg = json.loads(line)
    except ValueError:
        return "answered with malformed JSON"
    if not isinstance(msg, dict):
        return "answered with malformed JSON"
    if "id" not in msg:
        return "notification"
    if msg.get("jsonrpc") != "2.0":
        return "answered without a JSON-RPC 2.0 envelope"
    # `True == 1` in Python: the id must be the integer 1, not a boolean.
    if type(msg["id"]) is not int or msg["id"] != 1:
        return f"answered with id {msg['id']!r}, not 1"
    if "error" in msg:
        return f"answered initialize with an error: {str(msg['error'])[:200]}"
    result = msg.get("result")
    if not isinstance(result, dict):
        return "answered initialize without a result"
    if not isinstance(result.get("protocolVersion"), str) or not result["protocolVersion"]:
        return "answered initialize without protocolVersion"
    if not isinstance(result.get("capabilities"), dict):
        return "answered initialize without capabilities"
    info = result.get("serverInfo")
    if not isinstance(info, dict) or not isinstance(info.get("name"), str) or not info["name"]:
        return "answered initialize without serverInfo"
    if not isinstance(info.get("version"), str):
        return "answered initialize without serverInfo.version"
    return None


# MIK-8513 CONTENT.2: entries the start check skips although the registry
# calls them ready, with the reason printed. The product's `Setup` is unchanged.
START_SKIP = {"playwright": "needs a browser"}


def eligibility(entry: dict[str, str]) -> str | None:
    """None when the start check may start this entry, else why it is skipped."""
    plan = classify(entry)
    if isinstance(plan, str) or plan[0] not in ("npm", "pypi"):
        return "not an npx or uvx package"
    if entry["name"] in START_SKIP:
        return START_SKIP[entry["name"]]
    env = [v.strip().strip('"') for v in entry.get("required_env", "").split(",") if v.strip()]
    if env or entry.get("auth", "None") != "None":
        return f"needs credentials: {', '.join(env) or entry.get('auth')}"
    setup = entry.get("setup", "Ready")
    if setup == "NeedsArgs":
        return f"needs arguments: {entry.get('hint', '')}".rstrip(": ")
    if setup != "Ready":
        return f"needs a service: {entry.get('hint', '')}".rstrip(": ")
    return None


# ── MIK-8513 --start: served bytes and initialize, inside containers ────────
# Package code runs only in containers that get no runner environment and no
# host path, so the runner's Actions token and cache URLs stay out of reach.
# Images are multi-platform digests: one pin serves arm64 and amd64.
IMAGE = {
    "npm": "mirror.gcr.io/library/node:24-slim@sha256:55fb5f5a527ea2c5c4a95f963e48ef90aa38c7b346054fdc8ee9957a2b55d205",
    "pypi": "ghcr.io/astral-sh/uv:python3.12-trixie-slim@sha256:9b8477a5f2e2f96fa99eaecb7680c1c4c9f527926430f3b630bfb2c3641f8f20",
}
CAPS = {"fetch": 120, "prime": 180, "start": 60}
BASE_FLAGS = [
    "--rm", "--read-only", "--log-driver", "none", "-w", "/work", "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges", "--memory", "1g", "--pids-limit", "256", "--cpus", "1",
    "--tmpfs", "/tmp:exec,size=256m,uid=1000,gid=1000,mode=1777",
]
PACKAGE_ENV = {
    "HOME": "/work",
    "npm_config_cache": "/work/.npm",
    "UV_CACHE_DIR": "/work/.uv",
    "UV_TOOL_DIR": "/work/tools",
    "UV_TOOL_BIN_DIR": "/work/bin",
    "XDG_CACHE_HOME": "/work/.cache",
    # No install scripts for package code we did not write (lead ruling
    # 2026-10-23); a pinned server that needs them FAILs to start.
    "npm_config_ignore_scripts": "true",
    "PATH": "/work/bin:/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin",
}
# The one root step: no network, no environment, a constant command. Changing
# ownership is the only capability it gets back.
SETUP_COMMAND = ["sh", "-c", "mkdir -p /work/bin && chown -R 1000:1000 /work"]


def run_container(argv: list[str], stdin: bytes | None = None, timeout: float | None = None) -> tuple[int, bytes, bytes]:
    """The one seam for every non-streaming Docker call. Output is read as it
    arrives: stdout up to the budget (the process is killed past it), stderr
    as a 4 KiB tail. A timeout kills the process and raises TimeoutExpired."""
    proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    sel = selectors.DefaultSelector()
    try:
        try:
            proc.stdin.write(stdin or b"")
            proc.stdin.close()
        except OSError:
            pass  # the process exited before reading; its rc says why
        sel.register(proc.stdout, selectors.EVENT_READ, "out")
        sel.register(proc.stderr, selectors.EVENT_READ, "err")
        out, err = b"", b""
        deadline = None if timeout is None else time.monotonic() + timeout
        while sel.get_map():
            left = None if deadline is None else deadline - time.monotonic()
            if left is not None and left <= 0:
                raise subprocess.TimeoutExpired(argv, timeout)
            for key, _ in sel.select(left):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    sel.unregister(key.fileobj)
                elif key.data == "err":
                    err = (err + chunk)[-STDERR_TAIL:]
                elif len(out) + len(chunk) > STDOUT_BUDGET:
                    return -1, out, err + f" [stdout over the {STDOUT_BUDGET} byte budget]".encode()
                else:
                    out += chunk
        return proc.wait(timeout=30), out, err
    finally:
        sel.close()
        if proc.poll() is None:
            proc.kill()
        proc.wait()


def docker_run(kind: str, volume: str, command: list[str], *, name: str, interactive=False, offline=False) -> list[str]:
    """A package step: uid 1000, the fixed environment, the entry's volume."""
    argv = ["docker", "run", *BASE_FLAGS, "--user", "1000:1000"]
    for key, value in PACKAGE_ENV.items():
        argv += ["-e", f"{key}={value}"]
    argv += ["-v", f"{volume}:/work"]
    if interactive:
        argv.append("-i")
    if offline:
        argv += ["--network", "none"]
    argv += ["--name", name]
    return argv + [IMAGE[kind], *command]


def launch_args(entry: dict[str, str]) -> list[str]:
    """The entry's own arguments after the pinned package, as literal argv items."""
    tokens = [t for t in entry.get("command", "").split()[1:] if t not in ("-y", "--yes")]
    return tokens[1:]


def tail_text(err: bytes) -> str:
    return err.decode(errors="replace")[-300:].strip()


def bytes_verdict(kind: str, pkg: str, version: str, expected, volume: str, name: str) -> str | None:
    """The package manager fetches the artifact and checks its real bytes."""
    if kind == "npm":
        argv = docker_run(kind, volume, ["npm", "pack", "--json", "--pack-destination", "/work", f"{pkg}@{version}"], name=name, interactive=True)
        rc, out, err = run_container(argv, None, CAPS["fetch"])
        try:
            served = json.loads(out)[0]["integrity"]
        except (ValueError, LookupError, TypeError):
            return f"served bytes could not be fetched (npm pack exited {rc}): {tail_text(err)}"
        return None if served == expected else f"served bytes integrity {served} is not the recorded {expected}"
    hashes = " ".join(f"--hash=sha256:{digest}" for digest in sorted(expected.values()))
    argv = docker_run(kind, volume, ["pip", "download", "-d", "/work", "--no-deps", "--only-binary", ":all:", "--require-hashes", "-r", "/dev/stdin"], name=name, interactive=True)
    rc, _, err = run_container(argv, f"{pkg}=={version} {hashes}\n".encode(), CAPS["fetch"])
    return None if rc == 0 else f"served bytes do not match the recorded sha256 (pip exited {rc}): {tail_text(err)}"


def start_one(entry: dict[str, str], plan: tuple[str, str, str], expected) -> tuple[str | None, str | None]:
    """(failure, skip): fetch and verify every pinned entry; prime and start the eligible.

    Every container is named, and every name is removed on every exit path:
    killing a timed-out docker client does not stop its container."""
    kind, pkg, version = plan
    tag = uuid.uuid4().hex[:12]
    volume = f"mcpg-registry-{tag}"
    names = {step: f"mcpg-registry-{step}-{tag}" for step in ("setup", "fetch", "prime", "start")}
    launched = []
    try:
        run_container(["docker", "volume", "create", volume], None, 30)
        setup = ["docker", "run", *BASE_FLAGS, "--user", "0:0", "--cap-add", "CHOWN", "--network", "none",
                 "-v", f"{volume}:/work", "--name", names["setup"], IMAGE[kind], *SETUP_COMMAND]
        launched.append(names["setup"])
        rc, _, err = run_container(setup, None, 30)
        if rc != 0:
            return f"volume setup failed: {tail_text(err)}", None
        launched.append(names["fetch"])
        failure = bytes_verdict(kind, pkg, version, expected, volume, names["fetch"])
        if failure:
            return failure, None
        skip = eligibility(entry)
        if skip:
            return None, skip
        if kind == "npm":
            # An absolute path: a package `bin` named `true` must not run on this networked step.
            prime = ["npm", "exec", "--yes", "--package", f"{pkg}@{version}", "--", "/usr/bin/true"]
            launcher = ["npx", "--offline", "-y", f"{pkg}@{version}"]
        else:
            prime = ["uv", "tool", "install", "--no-build", f"{pkg}=={version}"]
            launcher = ["uvx", "--offline", "--no-build", f"{pkg}@{version}"]
        launched.append(names["prime"])
        rc, _, err = run_container(docker_run(kind, volume, prime, name=names["prime"]), None, CAPS["prime"])
        if rc != 0:
            return f"install failed (exit {rc}): {tail_text(err)}", None
        launched.append(names["start"])
        argv = docker_run(kind, volume, launcher + launch_args(entry), name=names["start"], interactive=True, offline=True)
        return handshake(argv, CAPS["start"]), None
    except subprocess.TimeoutExpired as e:
        return f"timed out after {e.timeout} s", None
    finally:
        for argv in [["docker", "rm", "-f", name] for name in launched] + [["docker", "volume", "rm", "-f", volume]]:
            try:
                rc, _, err = run_container(argv, None, 30)
                if rc != 0:
                    print(f"WARN cleanup {' '.join(argv)} exited {rc}: {tail_text(err)}")
            except subprocess.TimeoutExpired:
                print(f"WARN cleanup {' '.join(argv)} timed out")


def start_all(entries: list[dict[str, str]], records: dict, missing: dict) -> int:
    """`--start`: every pinned entry's bytes; every eligible entry's initialize."""
    failed, passed, eligible = 0, 0, 0
    kinds = {p[0] for p in map(classify, entries) if not isinstance(p, str) and p[0] in IMAGE}
    for kind in sorted(kinds):
        try:
            rc, _, err = run_container(["docker", "pull", IMAGE[kind]], None, 600)
        except subprocess.TimeoutExpired:
            rc, err = -1, b"timed out after 600 s"
        if rc != 0:
            print(f"FAIL image {IMAGE[kind]}: pull failed: {tail_text(err)}")
            return 1
    for entry in entries:
        plan = classify(entry)
        if isinstance(plan, str) or plan[0] not in ("npm", "pypi"):
            continue
        if entry["name"] in missing:
            print(f"FAIL {entry['name']}: {missing[entry['name']]}")
            failed += 1
            continue
        failure, skip = start_one(entry, plan, records[plan[0]][record_key(*plan)])
        if skip:
            print(f"SKIP {entry['name']}: {skip}")
            continue
        counted = eligibility(entry) is None
        eligible += counted
        if failure:
            print(f"FAIL {entry['name']}: {failure}")
            failed += 1
        elif counted:
            print(f"PASS {entry['name']}")
            passed += 1
    print(f"{passed}/{eligible} eligible entries start")
    return 1 if failed else 0


def parse_args(argv: list[str]) -> tuple[str, Path, Path]:
    """(mode, source, sidecar): mode is "offline", "live" or "start"."""
    args = list(argv[1:])
    integrity = DEFAULT_INTEGRITY
    if "--integrity" in args:
        i = args.index("--integrity")
        integrity = Path(args[i + 1])
        del args[i : i + 2]
    mode = "live"
    if "--offline" in args and "--start" in args:
        raise SystemExit("--offline and --start are mutually exclusive")
    for flag in ("--offline", "--start"):
        if flag in args:
            args.remove(flag)
            mode = flag[2:]
    return mode, (Path(args[0]) if args else DEFAULT_SOURCE), integrity


def main(argv: list[str]) -> int:
    mode, path, integrity = parse_args(argv)
    source = path.read_text()
    entries = parse_entries(source)
    if not entries:
        print(f"FAIL: no registry entries parsed from {path}")
        return 1
    # A block whose closing brace is indented differently is not matched by
    # ENTRY_RE; count the openings so it fails rather than goes unchecked.
    declared = len(re.findall(r"^\s*ServerCatalogEntry \{", source, re.M))
    if declared != len(entries):
        print(f"FAIL: {declared} ServerCatalogEntry blocks in {path}, {len(entries)} parsed")
        return 1
    records, errors = load_integrity(integrity)
    missing, orphans = integrity_failures(entries, records)
    for line in errors + orphans:
        print(f"FAIL {line}")
    if mode == "start":
        if errors:
            return 1
        return start_all(entries, records, missing) or (1 if orphans else 0)
    failures = []
    for entry in entries:
        plan = classify(entry)
        if isinstance(plan, str):
            reason = plan
        elif entry["name"] in missing:
            reason = missing[entry["name"]]
        elif mode == "offline":
            reason = None
        else:
            expected = records[plan[0]].get(record_key(*plan)) if plan[0] in records else None
            reason = probe(*plan, expected)
        if reason:
            failures.append(f"{entry['name']}: {reason}")
    for line in failures:
        print(f"FAIL {line}")
    verb = "are pinned (offline)" if mode == "offline" else "resolve"
    print(f"{len(entries) - len(failures)}/{len(entries)} registry entries {verb}")
    return 1 if failures or errors or orphans else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""No CI image pull goes to Docker Hub anonymously (MIK-8256).

Hosted runners share egress addresses, so anonymous Docker Hub pulls hit its
rate limit and fail merges. Every image CI pulls names a registry host
(mirror.gcr.io for Docker Hub content, same digests). This refuses, in
Dockerfiles, workflows and shell scripts:

- `FROM <ref>` whose first path part is not a registry host (`scratch`, a
  `$` variable and an earlier stage name are fine);
- a workflow `image:` value without a registry host;
- a `<ref>@sha256:<digest>` token without a registry host;
- an explicit `docker.io`, `registry-1.docker.io` or `index.docker.io`;
- a literal image argument of `docker pull|run|create` without a registry
  host, and a `FROM` written by a shell script (a heredoc or printf);
- a `helm/kind-action` step without a hosted `node_image` (kind's default
  node image is on Docker Hub);
- a `docker/setup-buildx-action` step without a hosted
  `driver-opts: image=` (buildx bootstraps BuildKit from Docker Hub).

Lexical, by design: a pull assembled at run time from variables is out of its
reach and is caught in review, not by more patterns.

Usage: check_docker_hub_pulls.py [--self-test] [<root>]
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

HUB = re.compile(r"\b(?:registry-1\.docker\.io|index\.docker\.io|docker\.io)/")
FROM = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?", re.I)
IMAGE_KEY = re.compile(r"^\s*(?:-\s+)?image:\s*['\"]?([^'\"\s#]+)")
DIGEST_REF = re.compile(r"(?<![\w./:-])([\w][\w./:-]*@sha256:[0-9a-f]{64})")
KIND = re.compile(r"uses:\s*helm/kind-action@")
BUILDX = re.compile(r"uses:\s*docker/setup-buildx-action@")
DOCKER_CMD = re.compile(r"\bdocker\s+(?:pull|run|create)\b(.*)")
SHELL_FROM = re.compile(r"\bFROM\s+([A-Za-z0-9$][^\s\\'\"]*)")
TAGGED = re.compile(r"^[a-z][\w./-]*(?::[\w.-]+)?(?:@sha256:[0-9a-f]{64})?$")


def has_registry(ref: str) -> bool:
    """Whether `ref` names its registry host explicitly: a first path part
    before a `/` that has a `.` or a `:` or is `localhost`. A bare
    `name:tag` or `name@digest` has no `/`, so it is Docker Hub."""
    first = ref.split("/", 1)[0]
    return "/" in ref and ("." in first or ":" in first or first == "localhost")


def code(line: str) -> str:
    """`line` without a shell or YAML comment (a `#` after whitespace)."""
    stripped = line.lstrip()
    if stripped.startswith("#"):
        return ""
    return re.split(r"\s#", line, maxsplit=1)[0]


def check_text(path: str, text: str) -> list[str]:
    problems = []
    is_dockerfile = Path(path).name.startswith("Dockerfile")
    is_workflow = path.startswith(".github/workflows/")
    stages: set[str] = set()
    for n, raw in enumerate(text.splitlines(), 1):
        line = code(raw)
        if not line.strip():
            continue
        where = f"{path}:{n}"
        if HUB.search(line):
            problems.append(f"{where}: names Docker Hub; use mirror.gcr.io")
        if is_dockerfile:
            m = FROM.match(line)
            if m:
                ref, stage = m.group(1), m.group(2)
                if not (
                    ref == "scratch"
                    or ref.startswith("$")
                    or ref in stages
                    or has_registry(ref)
                ):
                    problems.append(f"{where}: FROM {ref} pulls from Docker Hub")
                if stage:
                    stages.add(stage)
        if is_workflow:
            m = IMAGE_KEY.match(line)
            if m and not m.group(1).startswith("$") and not has_registry(m.group(1)):
                problems.append(f"{where}: image {m.group(1)} pulls from Docker Hub")
        for ref in DIGEST_REF.findall(line):
            if not has_registry(ref):
                problems.append(f"{where}: {ref} pulls from Docker Hub")
        m = DOCKER_CMD.search(line)
        if m:
            for token in m.group(1).split():
                if ("@sha256:" in token or ":" in token) and TAGGED.match(token) and not has_registry(token):
                    problems.append(f"{where}: docker pulls {token} from Docker Hub")
        if path.endswith(".sh") and not is_dockerfile:
            for ref in SHELL_FROM.findall(line):
                if ref != "scratch" and not ref.startswith("$") and not has_registry(ref):
                    problems.append(f"{where}: a script writes FROM {ref} (Docker Hub)")
    if is_workflow:
        problems.extend(check_steps(path, text))
    return problems


def check_steps(path: str, text: str) -> list[str]:
    """kind-action and setup-buildx-action steps name a hosted image."""
    problems = []
    lines = text.splitlines()
    for n, line in enumerate(lines):
        for pattern, key, what in (
            (KIND, "node_image:", "kind-action without a hosted node_image"),
            (BUILDX, "driver-opts:", "setup-buildx-action without a hosted driver-opts image"),
        ):
            if not pattern.search(line):
                continue
            indent = len(line) - len(line.lstrip(" -"))
            body = []
            for nxt in lines[n + 1 :]:
                if nxt.strip() and len(nxt) - len(nxt.lstrip(" -")) < indent:
                    break
                if nxt.lstrip().startswith("- "):
                    break
                body.append(nxt)
            value = next((b.split(key, 1)[1].strip() for b in body if key in b), "")
            ref = value.split("image=", 1)[1].split(",")[0] if "image=" in value else value
            if not has_registry(ref):
                problems.append(f"{path}:{n + 1}: {what}")
    return problems


def scanned(root: Path) -> list[Path]:
    files = [p for p in root.glob("Dockerfile*") if p.is_file()]
    files += sorted((root / ".github/workflows").glob("*.yml"))
    files += sorted((root / "scripts").rglob("*.sh"))
    return files


def problems(root: Path) -> list[str]:
    out = []
    for p in scanned(root):
        rel = p.relative_to(root).as_posix()
        out += check_text(rel, p.read_text(errors="replace"))
    return out


def self_test() -> list[str]:
    redis = "redis@sha256:" + "f" * 64
    refused = {
        "bare FROM": ("Dockerfile", "FROM rust:1.98-slim AS builder\n"),
        "bare services image": (".github/workflows/x.yml", "    services:\n      r:\n        image: registry:2\n"),
        "bare digest ref": ("scripts/x.sh", f"docker run -d {redis}\n"),
        "explicit docker.io": ("scripts/x.sh", "docker pull docker.io/library/busybox:1\n"),
        "kind without node_image": (".github/workflows/x.yml", "jobs:\n  k:\n    steps:\n      - uses: helm/kind-action@abc\n"),
        "buildx without driver image": (".github/workflows/x.yml", "      - uses: docker/setup-buildx-action@abc\n"),
        "literal docker pull": ("scripts/x.sh", "docker pull redis:7\n"),
        "script-written FROM": ("scripts/x.sh", "printf 'FROM busybox:1.36\\n' > Dockerfile\n"),
    }
    allowed = {
        "mirrored FROM and stage": ("Dockerfile", "FROM mirror.gcr.io/library/rust:1 AS b\nFROM b AS c\nFROM scratch\n"),
        "mirrored image": (".github/workflows/x.yml", "        image: mirror.gcr.io/library/registry:2\n"),
        "ghcr digest": ("scripts/x.sh", "docker pull ghcr.io/o/r@sha256:" + "a" * 64 + "\n"),
        "comment": ("scripts/x.sh", "# docker pull docker.io/library/x\n"),
        "kind with hosted node_image": (
            ".github/workflows/x.yml",
            "      - uses: helm/kind-action@abc\n        with:\n          node_image: mirror.gcr.io/kindest/node:v1\n",
        ),
        "buildx with hosted image": (
            ".github/workflows/x.yml",
            "      - uses: docker/setup-buildx-action@abc\n        with:\n          driver-opts: image=mirror.gcr.io/moby/buildkit:1\n",
        ),
        "port mapping and scratch": ("scripts/x.sh", "docker run --publish 127.0.0.1::6379 mirror.gcr.io/library/redis:7\nprintf 'FROM scratch\\n'\n"),
    }
    out = []
    for name, (path, text) in refused.items():
        if not check_text(path, text):
            out.append(f"self-test: {name} was not refused")
    for name, (path, text) in allowed.items():
        if found := check_text(path, text):
            out.append(f"self-test: {name} was refused: {found}")
    return out


def main(argv: list[str]) -> int:
    args = [a for a in argv if a != "--self-test"]
    errors = self_test()
    if "--self-test" not in argv:
        root = Path(args[0]) if args else Path(__file__).resolve().parents[2]
        errors += problems(root)
    for e in errors:
        print(e)
    if errors:
        print(f"docker-hub-pulls: {len(errors)} problem(s)")
        return 1
    print("docker-hub-pulls: no anonymous Docker Hub pull")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

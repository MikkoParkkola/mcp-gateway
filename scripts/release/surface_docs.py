#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""User docs, examples and the Helm chart list only KEEP keys (MIK-8044.SURF.2).

surface-4.0.md classes every config key and variable. An INTERNAL or AUTO key
is hidden: still honoured, but gone from what users read; a REMOVE key is a
load error. This check fails on any non-KEEP key or `MCP_GATEWAY_` variable in
the user docs, the shipped examples (commented blocks included) and the chart.

Lexical by design and stdlib only. A missed spelling is a one-line pattern fix.

Usage:
  surface_docs.py          scan the docs (CI: test_surface_docs.py)
  surface_docs.py --helm   render the chart per auth mode and scan the output
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import check_surface_inventory as inv

ROOT = inv.ROOT
# Class given to a key under a known parent that matches no row.
STRAY = "STRAY"

Seg = tuple[str, ...]


def segs(item_id: str) -> Seg:
    """`auth.api_keys[].key` -> ("auth", "api_keys", "[]", "key")."""
    return tuple(item_id.replace("[]", ".[]").split("."))


def show(path: Seg) -> str:
    return ".".join(path).replace(".[]", "[]")


def seg_match(pat: str, got: str) -> bool:
    if pat == got:
        return True
    return pat.startswith("<") and pat.endswith(">") and got != "[]"


@dataclass
class Rows:
    """The config and env classes of surface-4.0.md, indexed for matching."""

    config: dict[Seg, tuple[str, str]] = field(default_factory=dict)  # segs -> (class, id)
    env: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_doc(cls, text: str) -> Rows:
        out = cls()
        for r in inv.parse_doc(text):
            if r.surface == "config":
                out.config[segs(r.id)] = (r.cls, r.id)
            elif r.surface == "env":
                out.env[r.id] = r.cls
        return out

    def exact(self, path: Seg) -> tuple[str, str] | None:
        """The row `path` names. No two rows of different classes match one
        path today (checked when P4 landed), so the first match is the row."""
        for pat, row in self.config.items():
            if len(pat) == len(path) and all(map(seg_match, pat, path)):
                return row
        return None

    def is_prefix(self, path: Seg) -> bool:
        """Whether `path` is a strict prefix of some row: a known parent."""
        return any(
            len(pat) > len(path) and all(map(seg_match, pat[: len(path)], path))
            for pat in self.config
        )

    def has_children(self, row_id: str) -> bool:
        return self.is_prefix(segs(row_id))

    def top_level(self, key: str) -> bool:
        return any(pat[0] == key for pat in self.config)

    def leaf_classes(self, leaf: str) -> set[str]:
        return {cls for pat, (cls, _) in self.config.items() if pat[-1] == leaf}

    def classify(self, path: Seg) -> tuple[str, str] | None:
        """(class, row id) for `path`, or (STRAY, shown path), or None
        when `path` is free-form content no rule covers."""
        hit = self.exact(path)
        if hit:
            return hit
        for n in range(len(path) - 1, 0, -1):
            anc = self.exact(path[:n])
            if anc is None:
                continue
            cls, rid = anc
            if cls != "KEEP":
                return anc  # non-KEEP inheritance wins over free-form
            if self.is_prefix(path):
                return None
            return (STRAY, show(path)) if self.has_children(rid) else None
        return None if self.is_prefix(path) else (STRAY, show(path))


def message(file: str, line: int, hit: tuple[str, str]) -> str:
    cls, rid = hit
    if cls == STRAY:
        return f"{file}:{line}: {rid} is not a gateway config key"
    return f"{file}:{line}: {rid} is {cls} in surface-4.0.md; user docs list only KEEP keys"


# ── YAML: block walk plus a quote-aware flow parser ──────────────────────────

KEY = re.compile(r"""^(?P<dash>-\s+)?(?P<q>["']?)(?P<key>[a-z_][A-Za-z0-9_-]*)(?P=q)\s*:(?:\s+(?P<val>.*))?$""")
FLOW_ITEM = re.compile(r"^(?P<dash>-\s+)(?=[{\[])")
BLOCK_SCALAR = re.compile(r"^[|>][-+0-9]*\s*(#.*)?$")


def flow_paths(text: str) -> list[Seg]:
    """Key paths of a flow mapping or sequence: `{a: 1, b: {c: 2}}` -> a, b, b.c.
    Commas, colons and brackets inside quotes are content."""
    paths: list[Seg] = []
    i = 0

    def ws() -> None:
        nonlocal i
        while i < len(text) and text[i] in " \t\r\n":
            i += 1

    def scalar(stops: str) -> str:
        nonlocal i
        out, quote = [], None
        while i < len(text):
            ch = text[i]
            if quote:
                out.append(ch)
                if ch == "\\" and quote == '"' and i + 1 < len(text):
                    out.append(text[i + 1])
                    i += 1
                elif ch == quote:
                    quote = None
            elif ch in "\"'":
                quote = ch
                out.append(ch)
            elif ch in stops:
                break
            else:
                out.append(ch)
            i += 1
        return "".join(out).strip()

    def value(prefix: Seg) -> None:
        nonlocal i
        ws()
        if i < len(text) and text[i] == "{":
            i += 1
            mapping(prefix)
        elif i < len(text) and text[i] == "[":
            i += 1
            sequence(prefix + ("[]",))
        else:
            scalar(",}]")

    def mapping(prefix: Seg) -> None:
        nonlocal i
        while i < len(text):
            start = i
            ws()
            if i >= len(text) or text[i] == "}":
                i += 1
                return
            key = scalar(":,}").strip("\"'")
            if i < len(text) and text[i] == ":":
                i += 1
                if key:
                    paths.append(prefix + (key,))
                value(prefix + (key,))
            ws()
            if i < len(text) and text[i] == ",":
                i += 1
            if i == start:
                i += 1  # malformed flow: skip the character rather than loop

    def sequence(prefix: Seg) -> None:
        nonlocal i
        while i < len(text):
            start = i
            ws()
            if i >= len(text) or text[i] == "]":
                i += 1
                return
            value(prefix)
            ws()
            if i < len(text) and text[i] == ",":
                i += 1
            if i == start:
                i += 1  # malformed flow: skip the character rather than loop

    value(())
    return paths


def balanced(text: str) -> bool:
    depth, quote, escaped = 0, None, False
    for ch in text:
        if quote:
            if escaped:
                escaped = False
            elif ch == "\\" and quote == '"':
                escaped = True
            elif ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
        elif ch in "{[":
            depth += 1
        elif ch in "}]":
            depth -= 1
    return depth <= 0


def decomment(raw: str) -> tuple[int, str] | None:
    """(column, text) of a line, a commented one read as if `# ` were removed
    in place; None for a blank line."""
    body = raw.rstrip()
    text = body.lstrip()
    if not text:
        return None
    col = len(body) - len(text)
    if text.startswith("#"):
        rest = text[1:]
        rest = rest[1:] if rest.startswith(" ") else rest
        col += len(rest) - len(rest.lstrip())
        text = rest.lstrip()
    return col, text


def comment_shifts(lines: list[str]) -> tuple[list[int], list[int]]:
    """Per line, the columns to subtract from a commented line. Authors often
    indent an example inside a comment (`  #   key:`); within each run of
    commented lines the shallowest key is aligned to its `#`, and the run's
    other lines move with it, so their nesting is kept."""
    shifts = [0] * len(lines)
    runs = [-1] * len(lines)  # the comment run a line belongs to, -1 if active
    n = 0
    while n < len(lines):
        if not lines[n].lstrip().startswith("#"):
            n += 1
            continue
        start = n
        while n < len(lines) and lines[n].lstrip().startswith("#"):
            runs[n] = start
            n += 1
        keyed = []
        for i in range(start, n):
            got = decomment(lines[i])
            if got and KEY.match(got[1]):
                keyed.append((got[0], len(lines[i]) - len(lines[i].lstrip())))
        if keyed:
            key_col, hash_col = min(keyed)
            for i in range(start, n):
                shifts[i] = max(0, key_col - hash_col)
    return shifts, runs


def yaml_paths(text: str, line0: int = 1) -> list[tuple[Seg, int, int]]:
    """Every key path in `text` with its line, commented lines included.
    Keys start lowercase, so prose such as `# Usage:` never joins a path.
    Each path carries its comment run (-1 for an active line)."""
    out: list[tuple[Seg, int, int]] = []
    active: list[tuple[int, str]] = []  # (column, segment) of active lines
    commented: list[tuple[int, str]] = []  # the same for the current comment run
    run_seen = -1
    scalar_col: int | None = None
    lines = text.splitlines()
    shifts, runs = comment_shifts(lines)
    n = 0
    while n < len(lines):
        raw, lineno = lines[n], line0 + n
        n += 1
        got = decomment(raw)
        if got is None:
            continue
        col, body = got
        col -= shifts[n - 1]
        is_comment = runs[n - 1] >= 0
        if scalar_col is not None:
            if col > scalar_col and not is_comment:
                continue
            scalar_col = None
        if is_comment and runs[n - 1] != run_seen:
            commented, run_seen = list(active), runs[n - 1]
        stack = commented if is_comment else active
        m = KEY.match(body)
        item = None if m else FLOW_ITEM.match(body)
        if not m and not item:
            if body.startswith(("{", "[")) and not is_comment:
                flow = body
                while not balanced(flow) and n < len(lines):
                    flow += " " + (decomment(lines[n]) or (0, ""))[1]
                    n += 1
                base = tuple(s for _, s in stack)
                out += [(base + p, lineno, -1) for p in flow_paths(flow)]
            continue
        dash = (m.group("dash") if m else item.group("dash")) or ""
        if dash:
            while stack and (stack[-1][0] > col or (stack[-1][0] == col and stack[-1][1] == "[]")):
                stack.pop()
            stack.append((col, "[]"))
            col += len(dash)
        if item:
            flow = body[len(dash):]
            while not balanced(flow) and n < len(lines):
                flow += " " + (decomment(lines[n]) or (0, ""))[1]
                n += 1
            base = tuple(s for _, s in stack)
            out += [(base + p, lineno, runs[n - 1]) for p in flow_paths(flow)]
            continue
        while stack and stack[-1][0] >= col:
            stack.pop()
        key, val = m.group("key"), (m.group("val") or "").strip()
        path = tuple(s for _, s in stack) + (key,)
        run = runs[lineno - line0]
        out.append((path, lineno, run))
        stack.append((col, key))
        if val.startswith(("{", "[")):
            while not balanced(val) and n < len(lines):
                val += " " + (decomment(lines[n]) or (0, ""))[1]
                n += 1
            out += [(path + p, lineno, run) for p in flow_paths(val)]
        elif BLOCK_SCALAR.match(val) and not is_comment:
            scalar_col = col
    return out


# Root keys that name another file format outright: a capability file opens
# with its `fulcrum:` version, a Kubernetes manifest with `apiVersion`/`kind`.
FOREIGN_ROOTS = {"fulcrum", "apiVersion", "kind"}


def path_errors(found: list[tuple[Seg, int, int]], file: str, rows: Rows, whole_file: bool = False) -> list[str]:
    """Problems with key paths of one config. A markdown block with a top key
    that is no config section (a capability, a k8s manifest) is not a gateway
    config and is skipped. A whole file from the scanned set is always a
    gateway config, so a stray comment cannot switch its check off."""
    opens = {(p[0], r) for p, _, r in found if len(p) > 1}
    foreign_roots = {
        (p[0], r) for p, _, r in found
        if len(p) == 1 and not rows.top_level(p[0]) and ((p[0], r) in opens or p[0] in FOREIGN_ROOTS)
    }
    foreign_runs = {r for _, r in foreign_roots if r >= 0}
    # A commented run that opens a foreign block is an example of another
    # file; a lone commented `word:` is prose and is dropped alone.
    found = [
        f for f in found
        if f[2] not in foreign_runs and not (f[2] >= 0 and len(f[0]) == 1 and not rows.top_level(f[0][0]))
    ]
    if not whole_file:
        tops = {p[0] for p, _, _ in found if len(p) == 1}
        if not any(rows.top_level(k) for k in tops) or any(r < 0 for _, r in foreign_roots):
            return []
    errors: list[str] = []
    strays: list[Seg] = []
    for path, line, _ in found:
        if any(path[: len(s)] == s for s in strays):
            continue
        hit = rows.classify(path)
        if hit is None or hit[0] == "KEEP":
            continue
        if hit[0] == STRAY:
            strays.append(path)
        errors.append(message(file, line, hit))
    return errors


def comment_span_errors(text: str, file: str, rows: Rows, line0: int = 1) -> list[str]:
    """Backticked spans in YAML comments: the prose a reader follows."""
    errors = []
    for n, line in enumerate(text.splitlines()):
        hash_at = line.find("#")
        if hash_at < 0 or (hash_at and line[:hash_at].count('"') % 2):
            continue
        for m in SPAN.finditer(line[hash_at:]):
            errors += [message(file, line0 + n, h) for h in span_hits(m.group(1), rows)]
    return errors


def yaml_errors(text: str, file: str, rows: Rows, line0: int = 1, whole_file: bool = False) -> list[str]:
    errors = path_errors(yaml_paths(text, line0), file, rows, whole_file)
    if errors or whole_file or any(rows.top_level(p[0]) for p, _, r in yaml_paths(text, line0) if len(p) == 1 and r < 0):
        errors += comment_span_errors(text, file, rows, line0)
    return errors


def values_errors(text: str, file: str, rows: Rows) -> list[str]:
    """The chart's `values.yaml`: only its `config:` subtree is gateway config."""
    found = [(p[1:], ln, r) for p, ln, r in yaml_paths(text) if len(p) > 1 and p[0] == "config"]
    return path_errors(found, file, rows, whole_file=True)


# ── Markdown: fences, prose spans and variables ──────────────────────────────

FENCE = re.compile(r"^(?P<ind>\s*)(?P<run>`{3,}|~{3,})\s*(?P<lang>[A-Za-z0-9_+-]*)\s*$")
SPAN = re.compile(r"`([^`\n]+)`")
ENV = re.compile(r"MCP_GATEWAY_[A-Z0-9_]*")
DOTTED = re.compile(r"^[a-z_][a-z0-9_-]*(?:\.[a-z0-9_<>\[\]-]+)+$")
LEAF = re.compile(r"^(?P<leaf>[a-z_][a-z0-9_]*):?$")
CONFIG_LANGS = {"yaml", "yml", ""}
# A fenced block that opens with a comment naming a capability (for example
# `# capabilities/examples/linear_webhook.yaml`) is a capability file, whose
# `webhooks:` or `auth:` sections are not gateway config.
CAPABILITY_BLOCK = re.compile(r"^\s*#\s*(?:capabilities/\S+\.ya?ml|capability file\b)")


def fences(text: str) -> tuple[list[tuple[str, str, int]], set[int]]:
    """(lang, dedented body, line of its first body line) per fenced block,
    and the set of line numbers inside any fence, the fence lines included."""
    blocks, inside = [], set()
    lines = text.splitlines()
    n = 0
    while n < len(lines):
        m = FENCE.match(lines[n])
        if not m:
            n += 1
            continue
        ind, run, start = len(m.group("ind")), m.group("run"), n
        body: list[str] = []
        n += 1
        while n < len(lines):
            close = FENCE.match(lines[n])
            if close and close.group("run")[0] == run[0] and len(close.group("run")) >= len(run) and not close.group("lang"):
                break
            body.append(lines[n][ind:] if lines[n][:ind].strip() == "" else lines[n])
            n += 1
        blocks.append((m.group("lang").lower(), "\n".join(body) + "\n", start + 2))
        inside.update(range(start + 1, n + 2))
        n += 1
    return blocks, inside


def env_hit(name: str, rows: Rows) -> tuple[str, str] | None:
    """(class, id) for a variable, None when it is KEEP or the bare prefix."""
    if name == "MCP_GATEWAY_":
        return None
    if "__" in name:
        path = tuple(name[len("MCP_GATEWAY_"):].lower().split("__"))
        hit = rows.classify(path)
        if hit is None and not rows.exact(path) and not rows.is_prefix(path):
            hit = (STRAY, show(path))
        return None if hit is None or hit[0] == "KEEP" else hit
    cls = rows.env.get(name)
    if cls == "KEEP":
        return None
    return (cls or STRAY, name)


def span_hits(span: str, rows: Rows) -> list[tuple[str, str]]:
    """Non-KEEP config named by one backticked prose span."""
    span = span.strip()
    if ":" in span:
        found = yaml_paths(span)
        if any(rows.top_level(p[0]) for p, _, _ in found if len(p) == 1):
            return [h for p, _, _ in found if (h := rows.classify(p)) and h[0] not in ("KEEP", STRAY)]
        leaf = LEAF.match(span)
        return leaf_hits(leaf.group("leaf"), rows) if leaf else []
    if DOTTED.match(span):
        path = segs(span)
        if not rows.top_level(path[0]):
            return []
        hit = rows.classify(path)
        return [hit] if hit and hit[0] not in ("KEEP", STRAY) else []
    leaf = LEAF.match(span)
    return leaf_hits(leaf.group("leaf"), rows) if leaf else []


def leaf_hits(leaf: str, rows: Rows) -> list[tuple[str, str]]:
    """A bare key name counts only when every row ending in it is non-KEEP."""
    classes = rows.leaf_classes(leaf)
    if not classes or "KEEP" in classes:
        return []
    return [("/".join(sorted(classes)), leaf)]


def markdown_errors(text: str, file: str, rows: Rows, allowed: dict, used: set) -> list[str]:
    """Problems in one markdown page. Fenced config blocks are walked as YAML
    and never exempt; prose spans and variables outside them may be listed in
    `allowed` by (file, id)."""
    errors: list[str] = []
    blocks, inside = fences(text)
    config_lines: set[int] = set()
    for lang, body, line0 in blocks:
        if lang in CONFIG_LANGS and not CAPABILITY_BLOCK.match(body.lstrip("\n").split("\n", 1)[0]):
            errors += yaml_errors(body, file, rows, line0)
            config_lines.update(range(line0, line0 + body.count("\n")))

    def report(line: int, hit: tuple[str, str], exempt: bool) -> None:
        if exempt and (file, hit[1]) in allowed:
            used.add((file, hit[1]))
            return
        errors.append(message(file, line, hit))

    for n, line in enumerate(text.splitlines(), 1):
        if n not in inside:
            for m in SPAN.finditer(line):
                for hit in span_hits(m.group(1), rows):
                    report(n, hit, exempt=True)
        for m in ENV.finditer(line):
            if line[m.end(): m.end() + 1] == "<":
                continue
            hit = env_hit(m.group(), rows)
            if hit:
                report(n, hit, exempt=n not in config_lines)
    return errors


def stale_allowed(allowed: dict, used: set) -> list[str]:
    return [
        f"DOC_MENTIONS_ALLOWED lists {f} {i!r}, which no longer matches a mention; remove the entry"
        for (f, i) in sorted(set(allowed) - used)
    ]


# ── The scanned set and the repository run ───────────────────────────────────

# YAML files in examples/ that are not gateway configs: the same list
# tests/c1_unrecognised_config_keys.rs keeps (S1 checks they agree).
NOT_GATEWAY_CONFIGS = ("playbook-morning-briefing.yaml", "transform-example.yaml")

HELM_VALUES = ROOT / "deploy/helm/mcp-gateway/values.yaml"

# Prose mentions of a non-KEEP id that a user doc may keep, by (file, id), each
# with a reason a reviewer can check. YAML blocks are never exempt, and an entry
# that matches nothing fails the check. A new entry needs a review seat to see
# it (lead ruling 2026-10-11), so this list cannot become a quiet escape hatch.
_TEST_SCRIPT = (
    "variable of a repository test script, not read by the binary; surface-4.0.md: "
    "'a variable only a test script or an example reads is documented as such'"
)
DOC_MENTIONS_ALLOWED: dict[tuple[str, str], str] = {
    ("docs/runtime/provider_planner.md", "MCP_GATEWAY_RUNTIME_DOCKER_SMOKE"): _TEST_SCRIPT,
    ("docs/runtime/provider_planner.md", "MCP_GATEWAY_RUNTIME_DOCKER_IMAGE"): _TEST_SCRIPT,
    ("docs/runtime/provider_planner.md", "MCP_GATEWAY_RUNTIME_DOCKER_RESTART_IMAGE"): _TEST_SCRIPT,
    # A bare name in prose can belong to another schema; these two do.
    ("docs/control_plane.md", "schema_version"): "a field of the control-plane API response, not a gateway config key",
    ("docs/runtime/descriptor_spec.md", "max_entries"): "a field of the Hebb sandbox descriptor schema, not gateway config",
}


def doc_set() -> list:
    """Every user-facing file the check reads: the user docs the env surface
    already counts as published (ENV_DOC_GLOBS, deploy/ aside: the chart is
    checked through values.yaml and its renders), minus UPGRADING, release
    notes and CHANGELOG, which must name hidden and removed keys."""
    out = set()
    for glob in inv.ENV_DOC_GLOBS:
        if glob.startswith("deploy/"):
            continue
        for path in ROOT.glob(glob):
            if not path.is_file() or inv.ENV_DOC_SKIP.search(path.name):
                continue
            if path.suffix == ".md" or (path.suffix in (".yaml", ".yml") and path.name not in NOT_GATEWAY_CONFIGS):
                out.add(path)
    return sorted(out)


def file_errors(path, rows: Rows, used: set) -> list[str]:
    name = inv.rel(path)
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".md":
        return markdown_errors(text, name, rows, DOC_MENTIONS_ALLOWED, used)
    errors = yaml_errors(text, name, rows, whole_file=True)
    for n, line in enumerate(text.splitlines(), 1):
        for m in ENV.finditer(line):
            if line[m.end(): m.end() + 1] != "<" and (hit := env_hit(m.group(), rows)):
                errors.append(message(name, n, hit))
    return errors


def repo_errors(doc=None) -> list[str]:
    rows = Rows.from_doc((doc or inv.DOC).read_text(encoding="utf-8"))
    used: set = set()
    errors: list[str] = []
    for path in doc_set():
        errors += file_errors(path, rows, used)
    errors += values_errors(HELM_VALUES.read_text(encoding="utf-8"), inv.rel(HELM_VALUES), rows)
    errors += stale_allowed(DOC_MENTIONS_ALLOWED, used)
    return errors


# ── Helm: rendered output, not a hand-kept mapping ───────────────────────────

CHART = ROOT / "deploy/helm/mcp-gateway"
# Fixture files are named by auth mode; `bearer` is the chart's `credential`
# mode (a filename ending in credential.json is reserved for secrets).
FIXTURES = ROOT / "tests/fixtures/helm"
# Gateway keys each fixture must render, so a branch its values should reach
# cannot go dormant and pass by rendering nothing.
HELM_EXPECT: dict[str, list[str]] = {
    "bearer": [
        "auth.bearer_token",
        "server.cleartext_http",
        "server.metrics_token",
        "security.transparency_log.rotation.max_segment_age_secs",
    ],
    "api_keys": ["auth.api_keys[].key_sha256", "auth.api_keys[].rate_limit", "auth.api_keys[].expires_at"],
    "oidc": ["key_server.oidc[].jwks_uri", "key_server.oidc[].discovery_url", "key_server.policies[].scopes.rate_limit"],
    "mesh": ["server.host"],
}


def documents(manifest: str) -> list[str]:
    return [d for d in re.split(r"^---\s*$", manifest, flags=re.M) if d.strip()]


def rendered_config(manifest: str) -> tuple[str, int]:
    """The ConfigMap's `gateway.yaml` block scalar, dedented, and the manifest
    line it starts on; ("", 0) when the render has none."""
    lines = manifest.splitlines()
    for n, line in enumerate(lines):
        m = re.match(r"^(\s*)gateway\.yaml:\s*\|[-+]?\s*$", line)
        if not m:
            continue
        ind = len(m.group(1))
        body = []
        for nxt in lines[n + 1:]:
            if nxt.strip() and len(nxt) - len(nxt.lstrip()) <= ind:
                break
            body.append(nxt)
        cut = min((len(b) - len(b.lstrip()) for b in body if b.strip()), default=0)
        return "\n".join(b[cut:] for b in body) + "\n", n + 2
    return "", 0


def rendered_errors(manifest: str, label: str, rows: Rows) -> list[str]:
    """Problems in one `helm template` output: a non-KEEP or stray key in the
    rendered gateway.yaml, or a non-KEEP `MCP_GATEWAY_` variable the
    Deployment sets. Other variable names (HOME, GATEWAY_API_KEY_*) are the
    chart's credential wiring, checked by helm-chart-auth-modes.sh."""
    name = f"helm[{label}]"
    cfg, line0 = rendered_config(manifest)
    errors = yaml_errors(cfg, name, rows, line0, whole_file=True) if cfg else [f"{name}: no gateway.yaml rendered"]
    for doc in documents(manifest):
        if not re.search(r"^kind:\s*Deployment\s*$", doc, re.M):
            continue
        for m in re.finditer(r"-\s+name:\s*[\"']?(MCP_GATEWAY_[A-Z0-9_]*)", doc):
            if hit := env_hit(m.group(1), rows):
                errors.append(message(name, 0, hit))
    return errors


# Manifest text each fixture's non-gateway values must render, so a value
# that another setting suppresses cannot count as covered.
HELM_EXPECT_TEXT: dict[str, list[str]] = {
    "bearer": ["sizeLimit: 2Gi", "kind: ServiceMonitor", "kind: NetworkPolicy", "name: GITHUB_TOKEN"],
    "api_keys": ['claimName: "audit-pvc"'],
    "oidc": ["kind: PersistentVolumeClaim", 'storageClassName: "standard"', "storage: 2Gi"],
    "mesh": ['claimName: "gw-state"'],
}


def text_errors(manifest: str, label: str, expected: list[str]) -> list[str]:
    return [f"helm[{label}]: render lacks {t!r}; a fixture value is suppressed" for t in expected if t not in manifest]


def expected_errors(manifest: str, label: str, expected: list[str]) -> list[str]:
    cfg, _ = rendered_config(manifest)
    got = {show(p) for p, _, _ in yaml_paths(cfg)}
    return [f"helm[{label}]: renders no {e}; set the fixture value that reaches it" for e in expected if e not in got]


def schema_leaves(node: dict, prefix: Seg = ()) -> list[Seg]:
    out: list[Seg] = []
    for key, sub in (node.get("properties") or {}).items():
        path = prefix + (key,)
        if prefix == () and key == "config":
            continue  # free-form by design; config_schema_errors keeps it so
        items = sub.get("items") if isinstance(sub.get("items"), dict) else None
        if sub.get("properties"):
            out += schema_leaves(sub, path)
        elif items and items.get("properties"):
            out += schema_leaves(items, path + ("[]",))
        else:
            out.append(path)
    return out


def set_truthy(values, path: Seg) -> bool:
    """Whether `values` sets `path` to a value that renders: not false, "", 0,
    an empty list or map."""
    if not path:
        return bool(values)
    head, rest = path[0], path[1:]
    if head == "[]":
        return isinstance(values, list) and any(set_truthy(v, rest) for v in values)
    return isinstance(values, dict) and head in values and set_truthy(values[head], rest)


def coverage_errors(schema: dict, fixtures: dict[str, dict]) -> list[str]:
    return [
        f"values.schema.json: {show(leaf)} is set to a rendering value by no surface-all-values fixture"
        for leaf in schema_leaves(schema)
        if not any(set_truthy(v, leaf) for v in fixtures.values())
    ]


def config_schema_errors(schema: dict) -> list[str]:
    cfg = (schema.get("properties") or {}).get("config", {})
    if cfg.get("type") == "object" and set(cfg) <= {"type", "description"}:
        return []
    return ["values.schema.json: `config` must stay a free-form object; key-level schema belongs to surface-4.0.md"]


def helm_errors(helm: str = "helm") -> list[str]:
    """Render the chart once per auth-mode fixture and check each render."""
    import json
    import shutil
    import subprocess

    exe = shutil.which(helm) if "/" not in helm else (helm if Path(helm).is_file() else None)
    if exe is None:
        return [f"--helm needs helm on PATH ({helm} not found)"]
    rows = Rows.from_doc(inv.DOC.read_text(encoding="utf-8"))
    schema = json.loads((CHART / "values.schema.json").read_text(encoding="utf-8"))
    errors = config_schema_errors(schema)
    fixtures: dict[str, dict] = {}
    for mode, expected in HELM_EXPECT.items():
        path = FIXTURES / f"surface-all-values-{mode}.json"
        fixtures[mode] = json.loads(path.read_text(encoding="utf-8"))
        run = subprocess.run(
            [exe, "template", "t", str(CHART), "-f", str(path)],
            capture_output=True, text=True, check=False,
        )
        if run.returncode != 0:
            errors.append(f"helm[{mode}]: helm template failed: {run.stderr.strip()[-400:]}")
            continue
        errors += rendered_errors(run.stdout, mode, rows)
        errors += expected_errors(run.stdout, mode, expected)
        errors += text_errors(run.stdout, mode, HELM_EXPECT_TEXT.get(mode, []))
    errors += coverage_errors(schema, fixtures)
    return errors


def main(argv: list[str] | None = None) -> int:
    import argparse
    import os
    import sys

    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--helm", action="store_true", help="render the chart per auth mode and check the renders")
    args = ap.parse_args(argv)
    errors = helm_errors(os.environ.get("HELM") or "helm") if args.helm else repo_errors()
    for line in errors:
        print(line, file=sys.stderr)
    if errors:
        print(f"surface docs: {len(errors)} problem(s)", file=sys.stderr)
        return 1
    print("surface docs: user docs, examples and the chart list only KEEP keys")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

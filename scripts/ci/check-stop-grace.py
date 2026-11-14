#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Every shipped way to run the gateway gives it a stop grace of at least its stop timeout + 1 s.

The gateway's stop is bounded by server.shutdown_timeout (default 30 s), counted
from the stop signal. A service manager or container runtime that SIGKILLs
sooner cuts the saves and the backend stop short. This check fails closed on:

- systemd units (deploy/*.service, and fenced blocks in tracked Markdown that hold
  a [Service] section starting mcp-gateway): TimeoutStopSec below the timeout + 1 s,
  or KillMode other than mixed (control-group SIGTERMs the backends with the gateway);
- Compose files (deploy/, and fenced blocks): the gateway service's stop_grace_period;
- launchd plists: ExitTimeOut; static Kubernetes Deployments: terminationGracePeriodSeconds;
- `docker run` of the gateway image in fenced blocks and inline code spans of every
  tracked Markdown file: a serving run without --stop-timeout of at least the timeout + 1 s.
  A run is serving unless its first argument after the image is a one-shot command
  (ONE_SHOT); an unknown first word counts as serving.

The timeout is the artifact's own, in its native syntax (systemd Environment=, a
Compose environment list or map, plist EnvironmentVariables, docker run -e/--env, a
config `shutdown_timeout:` line); in Markdown, one set anywhere in an example's
section or a parent section applies to it. Else the default read from
src/config/server_config.rs. The duration grammar is the gateway's
(src/config/humantime_serde.rs); tests/fixtures/stop_grace_cases.txt holds the rows
this check, the Helm chart and the gateway's own parser share. The Helm chart is
checked by scripts/dev/helm-chart-smoke.sh, which reads --print-default.

Limits: a deploy artifact's timeout is read from its own folder only (a config kept
elsewhere, or a Kustomize overlay, is not followed); Setext headings are not sections
(none in tracked Markdown). SHIPPED and FLOORS keep both from hiding a lost artifact.

usage: check-stop-grace.py [ROOT] | --self-test | --print-default
"""
import pathlib
import re
import shlex
import subprocess
import sys
import tempfile

TABLE = "tests/fixtures/stop_grace_cases.txt"
DEFAULT_SRC = "src/config/server_config.rs"
CAP_SRC = "src/duration_bound.rs"
CLI_SRC = "src/cli/mod.rs"
# Every CLI subcommand is classified here, and the self-test fails until a new one
# is: a run whose first argument after the image is one of ONE_SHOT_COMMANDS exits
# without serving, so no stop grace applies. LONG_RUNNING_COMMANDS serve or loop
# (`kubernetes controller` runs a reconcile loop) and need the grace. A first word
# in neither set needs it too: a longer grace never cuts a stop short.
ONE_SHOT_COMMANDS = frozenset({
    "accounts", "add", "api", "audit", "cap", "dashboard-link", "doctor", "events", "get", "hash-key",
    "identity", "import", "init", "list", "provenance", "ranking", "remove", "runtime", "setup", "skills",
    "stats", "tls", "tool", "trust", "upgrade", "validate",
})
LONG_RUNNING_COMMANDS = frozenset({"serve", "kubernetes"})
# clap's own: the help subcommand and the help and version flags print and exit.
ONE_SHOT = tuple(sorted(ONE_SHOT_COMMANDS)) + ("help", "--help", "-h", "--version", "-V")
GATEWAY_IMAGE = re.compile(r"(?:^|/)mcp-gateway(?::[\w.-]+)?(?:@sha256:[0-9a-f]+)?$")
GRAMMAR = re.compile(r"\+?([0-9]+)(ms|s|m|h)?", re.ASCII)  # after a Unicode trim, as str::trim
SCALE = {"s": 1, "m": 60, "h": 3600}
ENV_NAME = "MCP_GATEWAY_SERVER__SHUTDOWN_TIMEOUT"


def read_fixed(root, rel, pattern, what):
    """One integer from a source file; exits (fails closed) when it is not found."""
    text = (pathlib.Path(root) / rel).read_text(encoding="utf-8")
    found = re.findall(pattern, text)
    if len(found) != 1:
        sys.exit(f"FAIL: cannot read {what} from {rel} ({len(found)} matches); update check-stop-grace.py")
    return int(found[0].replace("_", ""))


def default_timeout(root):
    return read_fixed(root, DEFAULT_SRC, r"shutdown_timeout: Duration::from_secs\(([0-9_]+)\)",
                      "the default server.shutdown_timeout")


def cap_seconds(root):
    return read_fixed(root, CAP_SRC, r"MAX_DURATION: Duration = Duration::from_secs\(([0-9_]+)\)",
                      "the 100-year duration cap")


def timeout_seconds(text, cap):
    """server.shutdown_timeout text -> whole seconds (rounded up), or None where the gateway refuses it."""
    m = GRAMMAR.fullmatch(text.strip())
    if not m:
        return None
    n, unit = int(m.group(1)), m.group(2) or "s"
    secs = -(-n // 1000) if unit == "ms" else n * SCALE[unit]
    return secs if secs <= cap else None


def table_rows(root):
    rows = []
    for line in (pathlib.Path(root) / TABLE).read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#"):
            value, want = line.split("\t")
            rows.append((value, want))
    return rows


# ── Where a timeout is set, in each native syntax ───────────────────────────
TIMEOUT_SETTINGS = (
    # systemd Environment=, Compose list or map, docker run -e/--env, a shell export
    re.compile(ENV_NAME + r"""\s*[=:]\s*["']?([^"'\s]+)"""),
    re.compile(r"<key>" + ENV_NAME + r"</key>\s*<string>([^<]*)</string>"),  # plist
    re.compile(r"""^\s*shutdown_timeout:\s*["']?([^"'\s#]+)""", re.M),  # a config block
)


def timeouts_in(text):
    return [m.group(1) for rule in TIMEOUT_SETTINGS for m in rule.finditer(text)]


# ── Markdown: sections, fenced blocks and inline code spans ─────────────────
FENCE = re.compile(r"^\s*(```|~~~)")
HEADING = re.compile(r"^(#{1,6})\s")
SPAN = re.compile(r"`([^`]+)`")


def markdown_units(text):
    """(line, body, chain) per fenced block, per inline code span, and per plain or indented
    line that runs docker (with its backslash continuations). `chain` is the ids of the
    section the unit sits in and of every parent section."""
    units, stack, next_id, fence, body, start = [], [], 0, None, [], 0
    lines = text.splitlines()
    for n, line in enumerate(lines, 1):
        # 0: the text before the first heading, a section of its own and parent of nothing.
        chain = tuple(i for _, i in stack) or (0,)
        if fence:
            if line.strip().startswith(fence):
                units.append((start, "\n".join(body), chain))
                fence = None
            else:
                body.append(line)
            continue
        opened = FENCE.match(line)
        if opened:
            fence, body, start = opened.group(1), [], n + 1
            continue
        heading = HEADING.match(line)
        if heading:
            level = len(heading.group(1))
            while stack and stack[-1][0] >= level:
                stack.pop()
            next_id += 1
            stack.append((level, next_id))
            continue
        for m in SPAN.finditer(line):
            units.append((n, m.group(1), chain))
        if "`" not in line and RUN_WORD.search(line):
            run, k = line, n
            while run.endswith("\\") and k < len(lines):
                run, k = run + "\n" + lines[k], k + 1
            units.append((n, run, chain))
    return units


# ── docker run ───────────────────────────────────────────────────────────────
RUN_WORD = re.compile(r"\bdocker\b")
# docker run flags that take no value; every other flag takes one (or has `=`).
BOOL_FLAGS = {"--detach", "--interactive", "--tty", "--rm", "--init", "--privileged", "--read-only",
              "--publish-all", "--no-healthcheck", "--oom-kill-disable", "--sig-proxy", "--help", "--quiet"}
SHORT_BOOL_CHARS = set("ditPq")
# docker's own options before `run` that take no value.
GLOBAL_BOOLS = {"--debug", "-D", "--tls", "--tlsverify"}
SHELL_STOP = {"|", "||", "&&", ";", "&", ">", ">>", "<", "2>&1"}
# Options whose value may name the gateway without being the image.
NAMING_FLAGS = {"--name", "--hostname", "-h", "--network-alias"}


def parse_run(tokens):
    """(image or None, args, stop_timeout or None, hidden) for the tokens after `docker`, or
    None when they are not a `run` (global options and `container` may come first). `hidden`:
    an option took a gateway image as its value, so the parse cannot be trusted."""
    i = 0
    while i < len(tokens) and tokens[i] != "run":
        tok = tokens[i]
        if tok == "container" or tok in GLOBAL_BOOLS or "=" in tok:
            i += 1
        elif tok.startswith("-"):
            i += 2
        else:
            return None
    if i >= len(tokens):
        return None
    image, args, stop, hidden, i = None, [], None, False, i + 1
    while i < len(tokens):
        tok = tokens[i]
        if tok in SHELL_STOP or tok.startswith((">", "2>")):
            break
        if image is not None:
            args.append(tok)
        elif tok == "--":
            image = tokens[i + 1] if i + 1 < len(tokens) else None
            i += 1
        elif tok.startswith("--"):
            name, eq, value = tok.partition("=")
            if not eq and name not in BOOL_FLAGS:
                i += 1
                value = tokens[i] if i < len(tokens) else ""
            if name == "--stop-timeout":
                stop = value
            hidden |= name not in NAMING_FLAGS and bool(GATEWAY_IMAGE.search(value))
        elif tok.startswith("-") and len(tok) > 1:
            # -d, -it: flags. -p, -dp: the last letter takes the next word. -p8080:80: self-contained.
            body = tok[1:]
            if not set(body) <= SHORT_BOOL_CHARS and set(body[:-1]) <= SHORT_BOOL_CHARS:
                i += 1
                value = tokens[i] if i < len(tokens) else ""
                hidden |= "-" + body[-1] not in NAMING_FLAGS and bool(GATEWAY_IMAGE.search(value))
        else:
            image = tok
        i += 1
    return image, args, stop, hidden


def docker_runs(body):
    """(line offset, image or None, args, stop_timeout or None, hidden) per `docker ... run`."""
    runs = []
    joined = re.sub(r"\\\n", " ", body)
    offsets = [0]
    for m in re.finditer(r"\\\n|\n", body):
        if m.group() == "\n":
            offsets.append(body[: m.end()].count("\n"))
    for idx, line in enumerate(joined.split("\n")):
        for m in RUN_WORD.finditer(line):
            text = re.sub(r"\$\([^)]*\)", "X", line[m.end():])
            try:
                tokens = shlex.split(text, comments=True)
            except ValueError:
                tokens = text.split()
            parsed = parse_run(tokens)
            if parsed is not None:
                runs.append((offsets[idx] if idx < len(offsets) else 0, *parsed))
    return runs


def serving(args):
    return not (args and args[0] in ONE_SHOT)


# ── Grace values, in each artifact's own syntax ─────────────────────────────
SYSTEMD_UNITS = {"us": 1e-6, "usec": 1e-6, "ms": 1e-3, "msec": 1e-3, "": 1, "s": 1, "sec": 1, "second": 1,
                 "seconds": 1, "m": 60, "min": 60, "minute": 60, "minutes": 60, "h": 3600, "hr": 3600,
                 "hour": 3600, "hours": 3600, "d": 86400, "day": 86400, "days": 86400,
                 "w": 604800, "week": 604800, "weeks": 604800}
GO_UNITS = {"ns": 1e-9, "us": 1e-6, "µs": 1e-6, "ms": 1e-3, "s": 1, "m": 60, "h": 3600}


def systemd_seconds(value):
    value = value.strip()
    if value == "infinity":
        return float("inf")
    parts = re.findall(r"([0-9]+(?:\.[0-9]+)?)\s*([a-z]*)", value)
    if not parts or re.sub(r"[0-9]+(?:\.[0-9]+)?\s*[a-z]*|\s", "", value) or any(u not in SYSTEMD_UNITS for _, u in parts):
        return None
    return sum(float(n) * SYSTEMD_UNITS[u] for n, u in parts)


def go_seconds(value):
    parts = re.findall(r"([0-9]+(?:\.[0-9]+)?)(ns|us|µs|ms|s|m|h)", value)
    if not parts or "".join(n + u for n, u in parts) != value:
        return None
    return sum(float(n) * GO_UNITS[u] for n, u in parts)


def first(pattern, text, flags=re.M):
    m = re.search(pattern, text, flags)
    return m.group(1) if m else None


def last(pattern, text, flags=re.M):
    """The effective setting where the platform lets a later assignment win."""
    found = re.findall(pattern, text, flags)
    return found[-1] if found else None


def grace_problem(what, raw, seconds, need):
    """None when the grace is enough; else what is wrong with it."""
    if raw is None:
        return f"{what} is unset; it needs at least {need} s"
    if seconds is None:
        return f"{what} {raw!r} cannot be read; it needs at least {need} s"
    if seconds < need:
        return f"{what} is {raw}; it needs at least {need} s"
    return None


def check_systemd(body, need):
    raw = last(r"^\s*TimeoutStopSec=(.*?)\s*$", body)
    problems = [grace_problem("TimeoutStopSec", raw, systemd_seconds(raw) if raw else None, need)]
    if last(r"^\s*KillMode=(\S+)\s*$", body) != "mixed":
        problems.append("KillMode is not mixed: control-group SIGTERMs every backend with the gateway")
    return [p for p in problems if p]


def compose_services(body):
    """(name, image, stop_grace_period) per service under `services:`, line by line."""
    lines = body.splitlines()
    out, si, sv, current = [], None, None, None
    for line in lines:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        if si is None:
            if re.fullmatch(r"\s*services:\s*(?:#.*)?", line):
                si = indent
            continue
        if indent <= si:
            break
        if sv is None:
            sv = indent
        if indent == sv:
            current = [line.strip().rstrip(":"), None, None]
            out.append(current)
        elif current is not None:
            current[1] = current[1] or first(r"""^\s*image:\s*["']?([^"'\s#]+)""", line)
            current[2] = first(r"""^\s*stop_grace_period:\s*["']?([^"'\s#]+)""", line) or current[2]
    return out


def gateway_service(name, image):
    """A service that runs the gateway: by its image, or by its name when the image comes
    from a build, an extends or a variable the line parser cannot resolve."""
    return bool(image and GATEWAY_IMAGE.search(image)) or "mcp-gateway" in name


def check_compose(body, need):
    problems = []
    for name, image, raw in compose_services(body):
        if gateway_service(name, image):
            p = grace_problem(f"service {name} stop_grace_period", raw, go_seconds(raw) if raw else None, need)
            problems += [p] if p else []
    return problems


def check_plist(body, need):
    raw = first(r"<key>ExitTimeOut</key>\s*<integer>([0-9]+)</integer>", body, re.S)
    p = grace_problem("ExitTimeOut", raw, int(raw) if raw else None, need)
    return [p] if p else []


def check_k8s(body, need):
    """Every pod template in the text: each terminationGracePeriodSeconds must be enough."""
    values = re.findall(r"^\s*terminationGracePeriodSeconds:\s*(\S+)\s*$", body, re.M) or [None]
    problems = [grace_problem("terminationGracePeriodSeconds", raw, int(raw) if raw and raw.isdigit() else None, need)
                for raw in values]
    return [p for p in problems if p]


def check_run(stop, need):
    if stop == "-1":  # docker's "wait for ever"
        return []
    p = grace_problem("serving docker run --stop-timeout", stop, int(stop) if stop and stop.isdigit() else None, need)
    return [p] if p else []


# ── The scan ─────────────────────────────────────────────────────────────────
KINDS = ("systemd", "compose", "launchd", "kubernetes", "docker run")
# Every shipped template, by path and kind: one the scan stops recognizing fails by name,
# even while another artifact of its kind is still found.
SHIPPED = {
    "deploy/single-node/mcp-gateway.service": "systemd",
    "deploy/single-node/docker-compose.yaml": "compose",
    "deploy/single-node/com.mikkoparkkola.mcp-gateway.plist": "launchd",
    "deploy/kubernetes/enterprise-alpha/base/deployment.yaml": "kubernetes",
}
# Today's counts, docs examples included. A count below its floor means the scan missed
# something; lowering a floor is a deliberate edit that a reviewer sees.
FLOORS = {"systemd": 2, "compose": 2, "launchd": 1, "kubernetes": 1, "docker run": 5}
CHECKS = {"systemd": check_systemd, "compose": check_compose, "launchd": check_plist, "kubernetes": check_k8s}
GATEWAY_EXEC = re.compile(r"^\s*ExecStart=\S*mcp-gateway\b", re.M)


def kinds_of(body):
    """The gateway artifact kinds a file or fenced block holds."""
    kinds = []
    if "[Service]" in body and GATEWAY_EXEC.search(body):
        kinds.append("systemd")
    if any(gateway_service(name, image) for name, image, _ in compose_services(body)):
        kinds.append("compose")
    if "<plist" in body and re.search(r"<string>[^<]*mcp-gateway[^<]*</string>", body):
        kinds.append("launchd")
    images = re.findall(r"""^\s*(?:-\s+)?image:\s*["']?([^"'\s#]+)""", body, re.M)
    if re.search(r"^\s*kind:\s*Deployment\s*$", body, re.M) and any(GATEWAY_IMAGE.search(i) for i in images):
        kinds.append("kubernetes")
    return kinds


def need_for(timeouts, default, cap):
    """The grace a set of timeouts needs (the largest + 1 s; the default's when none), or None
    when one of them is a value the gateway refuses at start."""
    secs = [timeout_seconds(t, cap) for t in timeouts]
    if None in secs:
        return None
    return (max(secs) if secs else default) + 1


def check_text(rel, line, body, need, counts, found, seen):
    for kind in kinds_of(body):
        counts[kind] += 1
        seen.add((rel, kind))
        found += [f"{rel}:{line}: {kind}: {p}" for p in CHECKS[kind](body, need)]
    for offset, image, args, stop, hidden in docker_runs(body):
        if image and GATEWAY_IMAGE.search(image):
            if serving(args):
                counts["docker run"] += 1
                found += [f"{rel}:{line + offset}: {p}" for p in check_run(stop, need)]
        elif hidden or any(GATEWAY_IMAGE.search(a) for a in args):
            # The gateway image after the word read as the image: an option the parser does
            # not know took a value it should not have, or none it should. Fail closed.
            found.append(f"{rel}:{line + offset}: a docker run of the gateway image the check cannot read "
                         f"(it took {image!r} for the image); fix the example or teach check-stop-grace.py the option")


def tracked(root):
    try:
        out = subprocess.run(["git", "-C", str(root), "ls-files", "-z"], capture_output=True, check=True).stdout
        files = [p for p in out.decode().split("\0") if p]
    except (OSError, subprocess.CalledProcessError):
        files = []
    # A planted tree (the self-test) is not a repository: every file in it counts.
    return sorted(files or (p.relative_to(root).as_posix() for p in pathlib.Path(root).rglob("*") if p.is_file()))


def violations(root, shipped=None, floors=None):
    """(offenders, per-kind counts) for every tracked deploy file and Markdown page. A kind
    that matched nothing is an offender too: a check that finds nothing has checked nothing."""
    root = pathlib.Path(root)
    default, cap = default_timeout(root), cap_seconds(root)
    counts, found, seen = dict.fromkeys(KINDS, 0), [], set()
    files = tracked(root)
    read = lambda rel: (root / rel).read_text(encoding="utf-8", errors="replace")  # noqa: E731
    for rel in files:
        if rel.endswith(".md"):
            units = markdown_units(read(rel))
            set_in = {}
            for _, body, chain in units:
                set_in.setdefault(chain[-1], []).extend(timeouts_in(body))
            for line, body, chain in units:
                need = need_for([t for s in chain for t in set_in.get(s, [])], default, cap)
                if need is None:
                    found.append(f"{rel}:{line}: its section sets a stop timeout the gateway refuses")
                else:
                    check_text(rel, line, body, need, counts, found, seen)
        elif rel.startswith("deploy/") and "/templates/" not in rel:
            # The artifact's own timeout: the file and its siblings (a Kubernetes base keeps the
            # gateway's config in a ConfigMap beside the Deployment). Helm templates are rendered
            # and checked by scripts/dev/helm-chart-smoke.sh.
            folder = rel.rpartition("/")[0] + "/"
            siblings = [f for f in files if f.startswith(folder) and "/" not in f[len(folder):]]
            need = need_for([t for f in siblings for t in timeouts_in(read(f))], default, cap)
            if need is None:
                found.append(f"{rel}:1: its folder sets a stop timeout the gateway refuses")
            else:
                check_text(rel, 1, read(rel), need, counts, found, seen)
    shipped = SHIPPED if shipped is None else shipped
    floors = FLOORS if floors is None else floors
    found += [f"{path}: the shipped {kind} artifact was not checked as one (moved, renamed or no longer "
              f"recognized); update SHIPPED in check-stop-grace.py"
              for path, kind in sorted(shipped.items()) if (path, kind) not in seen]
    found += [f"found {n} {kind} artifact(s), fewer than the {floors.get(kind, 1)} expected: the scan missed one, "
              f"or FLOORS in check-stop-grace.py must be lowered on purpose"
              for kind, n in counts.items() if n < floors.get(kind, 1)]
    return found, counts


def main(argv):
    if argv[1:] == ["--self-test"]:
        return self_test()
    here = pathlib.Path(__file__).resolve().parents[2]
    if argv[1:] == ["--print-default"]:
        print(default_timeout(here))
        return 0
    found, counts = violations(argv[1] if len(argv) > 1 else here)
    print("checked: " + ", ".join(f"{kind} {n}" for kind, n in counts.items()))
    for line in found:
        print(f"FAIL: {line}")
    if found:
        print("give the gateway its stop timeout + 1 s before any SIGKILL; see docs/DEPLOYMENT.md, Stop grace")
        return 1
    print("every shipped way to run the gateway gives it its stop timeout + 1 s")
    return 0


# ── Self-test ────────────────────────────────────────────────────────────────
IMG = "ghcr.io/mikkoparkkola/mcp-gateway:latest"
UNIT = "[Service]\nExecStart=/usr/local/bin/mcp-gateway --config /etc/c.yaml\n"
COMPOSE = "services:\n  gw:\n    image: " + IMG + "\n"
DEPLOYMENT = "kind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n        - image: " + IMG + "\n"
PLIST = "<plist><dict><key>ProgramArguments</key><array><string>/usr/local/bin/mcp-gateway</string></array>\n"
TIMEOUT_ENV = ENV_NAME + "=45s"


def fence(body):
    return "```\n" + body + "\n```\n"


def section(title, *blocks):
    return title + "\n\n" + "".join(fence(b) + "\n" for b in blocks)


RUN31 = "docker run --stop-timeout 31 " + IMG
# Every planted file must be flagged; nothing in CLEAN may be.
PLANTED = {
    "deploy/a/u.service": UNIT + "TimeoutStopSec=30s\nKillMode=mixed\n",  # the timeout itself is short
    "deploy/b/u.service": UNIT + "TimeoutStopSec=31s\n",  # KillMode left at control-group
    "deploy/c/u.service": UNIT + "KillMode=mixed\n",  # unset: the host's default is not ours
    "deploy/d/u.service": UNIT + "Environment=" + TIMEOUT_ENV + "\nTimeoutStopSec=31s\nKillMode=mixed\n",
    "deploy/e/docker-compose.yaml": COMPOSE,
    "deploy/f/gw.plist": PLIST + "<key>ExitTimeOut</key>\n<integer>30</integer>\n",
    "deploy/g/deployment.yaml": DEPLOYMENT + "      terminationGracePeriodSeconds: 30\n",
    "deploy/h/deployment.yaml": DEPLOYMENT + "      terminationGracePeriodSeconds: 31\n",
    "deploy/i/u.service": UNIT + "TimeoutStopSec=soon\nKillMode=mixed\n",
    "docs/run-inline.md": "| Docker | `docker run -p 1:1 " + IMG + " --config /c` |\n",
    "docs/run-multiline.md": fence("docker run --rm \\\n  -e A=1 \\\n  --stop-timeout 30 \\\n  " + IMG + " --config /c"),
    "docs/sec-systemd.md": section("## S", "[Service]\nEnvironment=" + TIMEOUT_ENV,
                                   UNIT + "TimeoutStopSec=31s\nKillMode=mixed"),
    "docs/sec-compose-list.md": section("## S", "environment:\n  - " + TIMEOUT_ENV,
                                        COMPOSE + "    stop_grace_period: 31s"),
    "docs/sec-compose-map.md": section("## S", "environment:\n  " + ENV_NAME + ": 45s",
                                       COMPOSE + "    stop_grace_period: 31s"),
    "docs/sec-plist.md": section("## S", "<key>" + ENV_NAME + "</key>\n<string>45s</string>", RUN31),
    "docs/sec-run-env.md": section("## S", "docker run -e " + TIMEOUT_ENV + " --stop-timeout 46 " + IMG, RUN31),
    "docs/sec-config.md": section("## S", "server:\n  shutdown_timeout: 45s", RUN31),
    "docs/parent.md": section("## Parent", "server:\n  shutdown_timeout: 50s") + section("### Child", RUN31),
    "docs/refused.md": section("## S", "server:\n  shutdown_timeout: 1d", RUN31),
    "docs/long-running.md": fence("docker run " + IMG + " kubernetes controller --file r.yaml"),
    # The effective setting is the last one; every pod template counts.
    "deploy/j/u.service": UNIT + "TimeoutStopSec=31s\nKillMode=mixed\nTimeoutStopSec=10s\n",
    "deploy/k/u.service": UNIT + "TimeoutStopSec=31s\nKillMode=mixed\nKillMode=control-group\n",
    "deploy/l/deployment.yaml": DEPLOYMENT + "      terminationGracePeriodSeconds: 31\n---\n"
                                + DEPLOYMENT + "      terminationGracePeriodSeconds: 10\n",
    # A commented `services:`, and a gateway service built from source (known by its name).
    "deploy/m/docker-compose.yaml": "services:  # the stack\n  mcp-gateway:\n    build: .\n",
    # docker run forms: a flag cluster ending in a value flag, global options, `--`, an
    # unknown option that swallows the image (unreadable), an indented code block.
    "docs/run-cluster.md": fence("docker run -dp 1:1 " + IMG),
    "docs/run-global.md": fence("docker --context prod run --quiet " + IMG),
    "docs/run-dashdash.md": fence("docker run --rm -- " + IMG),
    "docs/run-unreadable.md": fence("docker run --made-up " + IMG + " --config /c"),
    "docs/indented.md": "Run it:\n\n    docker run -d \\\n      " + IMG + "\n",
}
# Files a planted artifact reads, never flagged themselves.
SUPPORT = {
    "deploy/h/configmap.yaml": "data:\n  gateway.yaml: |\n    server:\n      shutdown_timeout: 60s\n",
}
CLEAN = {
    "deploy/c2/u.service": UNIT + "TimeoutStopSec=31s\nKillMode=mixed\n",
    "deploy/e2/docker-compose.yaml": COMPOSE + "    stop_grace_period: 31s\n  cache:\n    image: redis:7\n",
    "deploy/f2/gw.plist": PLIST + "<key>ExitTimeOut</key>\n<integer>31</integer>\n",
    "deploy/h2/deployment.yaml": DEPLOYMENT + "      terminationGracePeriodSeconds: 61\n",
    "deploy/h2/configmap.yaml": "data:\n  gateway.yaml: |\n    server:\n      shutdown_timeout: 60s\n",
    "docs/oneshot.md": fence("docker run " + IMG + " --version\ndocker run " + IMG + " doctor\n"
                             "docker run --rm -i grafana/k6 run - < k6.js\n"
                             "docker run --name mcp-gateway mcp-gateway:latest-full help"),
    "docs/sibling.md": section("## A", "server:\n  shutdown_timeout: 50s") + section("## B", RUN31),
    "docs/run-ok.md": fence("docker run -it --rm -e X=1 --stop-timeout=31 mcp-gateway:latest"),
    "docs/prose.md": "pass it to the process (`docker run -e MCP_GATEWAY_TOKEN`)\n",
    "docs/run-forever.md": fence("docker run --stop-timeout -1 " + IMG),
    "docs/run-name.md": fence("docker run --name mcp-gateway grafana/k6 run -"),
    # A timeout before the first heading is not a parent of the sections after it.
    "docs/preamble.md": fence("server:\n  shutdown_timeout: 50s") + "\n" + section("## B", RUN31),
}

# Every planted offender's diagnostic, exactly: a fixture flagged for the wrong reason fails.
EXPECTED = [
    'deploy/a/u.service:1: systemd: TimeoutStopSec is 30s; it needs at least 31 s',
    'deploy/b/u.service:1: systemd: KillMode is not mixed: control-group SIGTERMs every backend with the gateway',
    'deploy/c/u.service:1: systemd: TimeoutStopSec is unset; it needs at least 31 s',
    'deploy/d/u.service:1: systemd: TimeoutStopSec is 31s; it needs at least 46 s',
    'deploy/e/docker-compose.yaml:1: compose: service gw stop_grace_period is unset; it needs at least 31 s',
    'deploy/f/gw.plist:1: launchd: ExitTimeOut is 30; it needs at least 31 s',
    'deploy/g/deployment.yaml:1: kubernetes: terminationGracePeriodSeconds is 30; it needs at least 31 s',
    'deploy/h/deployment.yaml:1: kubernetes: terminationGracePeriodSeconds is 31; it needs at least 61 s',
    "deploy/i/u.service:1: systemd: TimeoutStopSec 'soon' cannot be read; it needs at least 31 s",
    'deploy/j/u.service:1: systemd: TimeoutStopSec is 10s; it needs at least 31 s',
    'deploy/k/u.service:1: systemd: KillMode is not mixed: control-group SIGTERMs every backend with the gateway',
    'deploy/l/deployment.yaml:1: kubernetes: terminationGracePeriodSeconds is 10; it needs at least 31 s',
    'deploy/m/docker-compose.yaml:1: compose: service mcp-gateway stop_grace_period is unset; it needs at least 31 s',
    'docs/indented.md:3: serving docker run --stop-timeout is unset; it needs at least 31 s',
    'docs/long-running.md:2: serving docker run --stop-timeout is unset; it needs at least 31 s',
    'docs/parent.md:11: serving docker run --stop-timeout is 31; it needs at least 51 s',
    'docs/refused.md:4: its section sets a stop timeout the gateway refuses',
    'docs/refused.md:9: its section sets a stop timeout the gateway refuses',
    'docs/run-cluster.md:2: serving docker run --stop-timeout is unset; it needs at least 31 s',
    'docs/run-dashdash.md:2: serving docker run --stop-timeout is unset; it needs at least 31 s',
    'docs/run-global.md:2: serving docker run --stop-timeout is unset; it needs at least 31 s',
    'docs/run-inline.md:1: serving docker run --stop-timeout is unset; it needs at least 31 s',
    'docs/run-multiline.md:2: serving docker run --stop-timeout is 30; it needs at least 31 s',
    'docs/run-unreadable.md:2: a docker run of the gateway image the check cannot read (it took None for the image); fix the example or teach check-stop-grace.py the option',
    'docs/sec-compose-list.md:9: compose: service gw stop_grace_period is 31s; it needs at least 46 s',
    'docs/sec-compose-map.md:9: compose: service gw stop_grace_period is 31s; it needs at least 46 s',
    'docs/sec-config.md:9: serving docker run --stop-timeout is 31; it needs at least 46 s',
    'docs/sec-plist.md:9: serving docker run --stop-timeout is 31; it needs at least 46 s',
    'docs/sec-run-env.md:8: serving docker run --stop-timeout is 31; it needs at least 46 s',
    'docs/sec-systemd.md:9: systemd: TimeoutStopSec is 31s; it needs at least 46 s',
]


def command_words(root):
    """The CLI's subcommand names: the Command enum's variants in kebab case."""
    text = (pathlib.Path(root) / CLI_SRC).read_text(encoding="utf-8")
    body = re.search(r"pub\(crate\) enum Command \{\n(.*?)\n\}", text, re.S)
    assert body, f"no Command enum in {CLI_SRC}"
    names = re.findall(r"^    ([A-Z][A-Za-z]*)\b", body.group(1), re.M)
    return {re.sub(r"(?<!^)([A-Z])", r"-\1", n).lower() for n in names}


def self_test():
    here = pathlib.Path(__file__).resolve().parents[2]
    cap, default = cap_seconds(here), default_timeout(here)
    rows = table_rows(here)
    assert len(rows) >= 20, f"{TABLE} lost its rows"
    for value, want in rows:
        secs = timeout_seconds(value, cap)
        got = "refused" if secs is None else str(secs + 1)
        assert got == want, f"{value!r}: grace {got}, the table says {want}"
    words = command_words(here)
    assert len(words) >= 20, f"the Command enum read as {sorted(words)}"
    classified = ONE_SHOT_COMMANDS | LONG_RUNNING_COMMANDS
    assert not ONE_SHOT_COMMANDS & LONG_RUNNING_COMMANDS, ONE_SHOT_COMMANDS & LONG_RUNNING_COMMANDS
    assert words <= classified, f"classify subcommands {sorted(words - classified)} in check-stop-grace.py"
    assert classified <= words, f"{sorted(classified - words)} are no longer subcommands; remove them"
    assert systemd_seconds("1min 30s") == 90 and systemd_seconds("31") == 31 and systemd_seconds("x") is None
    assert go_seconds("1m30s") == 90 and go_seconds("31") is None
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        for rel in (DEFAULT_SRC, CAP_SRC):
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text((here / rel).read_text(encoding="utf-8"), encoding="utf-8")
        found, counts = violations(root, shipped={}, floors={})
        assert sorted(found) == sorted(
            f"found 0 {k} artifact(s), fewer than the 1 expected: the scan missed one, "
            f"or FLOORS in check-stop-grace.py must be lowered on purpose" for k in KINDS), found
        for rel, text in {**PLANTED, **SUPPORT, **CLEAN}.items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(text, encoding="utf-8")
        found, counts = violations(root, shipped={}, floors={})
        # A shipped artifact the scan no longer recognizes, and a count below its floor.
        pinned, _ = violations(root, shipped={"deploy/c2/u.service": "systemd", "deploy/gone/u.service": "systemd"},
                               floors={"launchd": 3})
    assert sorted(found) == sorted(EXPECTED), (sorted(set(found) - set(EXPECTED)), sorted(set(EXPECTED) - set(found)))
    assert {line.split(":")[0] for line in found} == set(PLANTED), "every planted file is flagged, no clean one"
    assert all(counts.values()), counts
    assert sorted(set(pinned) - set(found)) == [
        "deploy/gone/u.service: the shipped systemd artifact was not checked as one (moved, renamed or no "
        "longer recognized); update SHIPPED in check-stop-grace.py",
        "found 2 launchd artifact(s), fewer than the 3 expected: the scan missed one, or FLOORS in "
        "check-stop-grace.py must be lowered on purpose",
    ], sorted(set(pinned) - set(found))
    assert set(SHIPPED.values()) <= set(KINDS) and set(FLOORS) == set(KINDS)
    print(f"check-stop-grace self-test: ok ({len(rows)} table rows, {len(PLANTED)} planted, {len(CLEAN)} clean)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

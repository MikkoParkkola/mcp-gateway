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
# One-shot first arguments after the image: they exit without serving, so the
# stop grace does not apply. Each word is checked against the CLI's Command enum
# by the self-test (the flags are clap's own). Anything else serves.
ONE_SHOT = ("doctor", "help", "--help", "-h", "--version", "-V")
GATEWAY_IMAGE = re.compile(r"(?:^|/)mcp-gateway(?::[\w.-]+)?(?:@sha256:[0-9a-f]+)?$")
GRAMMAR = re.compile(r"\s*\+?([0-9]+)(ms|s|m|h)?\s*", re.ASCII)
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
    m = GRAMMAR.fullmatch(text)
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
    """(line, body, chain) per fenced block and per inline code span. `chain` is the
    ids of the section the unit sits in and of every parent section."""
    units, stack, next_id, fence, body, start = [], [], 0, None, [], 0
    for n, line in enumerate(text.splitlines(), 1):
        chain = (0,) + tuple(i for _, i in stack)  # 0: the text before any heading
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
    return units


# ── docker run ───────────────────────────────────────────────────────────────
RUN = re.compile(r"\bdocker\s+(?:container\s+)?run\b")
# docker run flags that take no value; every other flag takes one (or has `=`).
BOOL_FLAGS = {"--detach", "--interactive", "--tty", "--rm", "--init", "--privileged", "--read-only",
              "--publish-all", "--no-healthcheck", "--oom-kill-disable", "--sig-proxy", "--help"}
SHORT_BOOLS = re.compile(r"-[ditP]+")
SHELL_STOP = {"|", "||", "&&", ";", "&", ">", ">>", "<", "2>&1"}


def docker_runs(body):
    """(line offset, image, args, stop_timeout or None) per `docker run` in a text."""
    runs = []
    joined = re.sub(r"\\\n", " ", body)
    offsets = [0]
    for m in re.finditer(r"\\\n|\n", body):
        if m.group() == "\n":
            offsets.append(body[: m.end()].count("\n"))
    for idx, line in enumerate(joined.split("\n")):
        for m in RUN.finditer(line):
            text = re.sub(r"\$\([^)]*\)", "X", line[m.end():])
            try:
                tokens = shlex.split(text, comments=True)
            except ValueError:
                tokens = text.split()
            image, args, stop, i = None, [], None, 0
            while i < len(tokens):
                tok = tokens[i]
                if tok in SHELL_STOP or tok.startswith((">", "2>")):
                    break
                if image is not None:
                    args.append(tok)
                elif tok.startswith("--"):
                    name, eq, value = tok.partition("=")
                    if not eq and name not in BOOL_FLAGS:
                        i += 1
                        value = tokens[i] if i < len(tokens) else ""
                    if name == "--stop-timeout":
                        stop = value
                elif tok.startswith("-") and len(tok) > 1:
                    if not SHORT_BOOLS.fullmatch(tok) and len(tok) == 2:
                        i += 1
                else:
                    image = tok
                i += 1
            if image is not None:
                runs.append((offsets[idx] if idx < len(offsets) else 0, image, args, stop))
    return runs


def serving(args):
    return not (args and args[0] in ONE_SHOT)


# ── Grace values, in each artifact's own syntax ─────────────────────────────
SYSTEMD_UNITS = {"us": 1e-6, "usec": 1e-6, "ms": 1e-3, "msec": 1e-3, "": 1, "s": 1, "sec": 1, "second": 1,
                 "seconds": 1, "m": 60, "min": 60, "minute": 60, "minutes": 60, "h": 3600, "hr": 3600,
                 "hour": 3600, "hours": 3600}
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
    raw = first(r"^\s*TimeoutStopSec=(.*?)\s*$", body)
    problems = [grace_problem("TimeoutStopSec", raw, systemd_seconds(raw) if raw else None, need)]
    if first(r"^\s*KillMode=(\S+)\s*$", body) != "mixed":
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
            if re.fullmatch(r"\s*services:\s*", line):
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
            current[2] = current[2] or first(r"""^\s*stop_grace_period:\s*["']?([^"'\s#]+)""", line)
    return out


def check_compose(body, need):
    problems = []
    for name, image, raw in compose_services(body):
        if image and GATEWAY_IMAGE.search(image):
            p = grace_problem(f"service {name} stop_grace_period", raw, go_seconds(raw) if raw else None, need)
            problems += [p] if p else []
    return problems


def check_plist(body, need):
    raw = first(r"<key>ExitTimeOut</key>\s*<integer>([0-9]+)</integer>", body, re.S)
    p = grace_problem("ExitTimeOut", raw, int(raw) if raw else None, need)
    return [p] if p else []


def check_k8s(body, need):
    raw = first(r"^\s*terminationGracePeriodSeconds:\s*([0-9]+)\s*$", body)
    p = grace_problem("terminationGracePeriodSeconds", raw, int(raw) if raw else None, need)
    return [p] if p else []


def check_run(stop, need):
    p = grace_problem("serving docker run --stop-timeout", stop, int(stop) if stop and stop.isdigit() else None, need)
    return [p] if p else []


# ── The scan ─────────────────────────────────────────────────────────────────
KINDS = ("systemd", "compose", "launchd", "kubernetes", "docker run")
CHECKS = {"systemd": check_systemd, "compose": check_compose, "launchd": check_plist, "kubernetes": check_k8s}
GATEWAY_EXEC = re.compile(r"^\s*ExecStart=\S*mcp-gateway\b", re.M)


def kinds_of(body):
    """The gateway artifact kinds a file or fenced block holds."""
    kinds = []
    if "[Service]" in body and GATEWAY_EXEC.search(body):
        kinds.append("systemd")
    if any(image and GATEWAY_IMAGE.search(image) for _, image, _ in compose_services(body)):
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


def check_text(rel, line, body, need, counts, found):
    for kind in kinds_of(body):
        counts[kind] += 1
        found += [f"{rel}:{line}: {kind}: {p}" for p in CHECKS[kind](body, need)]
    for offset, image, args, stop in docker_runs(body):
        if GATEWAY_IMAGE.search(image) and serving(args):
            counts["docker run"] += 1
            found += [f"{rel}:{line + offset}: {p}" for p in check_run(stop, need)]


def tracked(root):
    try:
        out = subprocess.run(["git", "-C", str(root), "ls-files", "-z"], capture_output=True, check=True).stdout
        files = [p for p in out.decode().split("\0") if p]
    except (OSError, subprocess.CalledProcessError):
        files = []
    # A planted tree (the self-test) is not a repository: every file in it counts.
    return sorted(files or (p.relative_to(root).as_posix() for p in pathlib.Path(root).rglob("*") if p.is_file()))


def violations(root):
    """(offenders, per-kind counts) for every tracked deploy file and Markdown page. A kind
    that matched nothing is an offender too: a check that finds nothing has checked nothing."""
    root = pathlib.Path(root)
    default, cap = default_timeout(root), cap_seconds(root)
    counts, found = dict.fromkeys(KINDS, 0), []
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
                    check_text(rel, line, body, need, counts, found)
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
                check_text(rel, 1, read(rel), need, counts, found)
    found += [f"no {kind} artifact found: the scan matched nothing to check" for kind, n in counts.items() if not n]
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
}


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
    assert "serve" in words and "doctor" in words, words
    for word in ONE_SHOT:
        assert word.startswith("-") or word == "help" or word in words, f"{word} is not a CLI subcommand"
    assert "serve" not in ONE_SHOT
    assert systemd_seconds("1min 30s") == 90 and systemd_seconds("31") == 31 and systemd_seconds("x") is None
    assert go_seconds("1m30s") == 90 and go_seconds("31") is None
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        for rel in (DEFAULT_SRC, CAP_SRC):
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text((here / rel).read_text(encoding="utf-8"), encoding="utf-8")
        found, counts = violations(root)
        assert sorted(found) == sorted(f"no {k} artifact found: the scan matched nothing to check" for k in KINDS), found
        for rel, text in {**PLANTED, **SUPPORT, **CLEAN}.items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(text, encoding="utf-8")
        found, counts = violations(root)
    flagged = {line.split(":")[0] for line in found}
    assert flagged == set(PLANTED), (sorted(set(PLANTED) - flagged), sorted(flagged - set(PLANTED)), found)
    assert all(counts.values()), counts
    expect = [
        "deploy/a/u.service:1: systemd: TimeoutStopSec is 30s; it needs at least 31 s",
        "deploy/b/u.service:1: systemd: KillMode is not mixed: control-group SIGTERMs every backend with the gateway",
        "deploy/c/u.service:1: systemd: TimeoutStopSec is unset; it needs at least 31 s",
        "deploy/d/u.service:1: systemd: TimeoutStopSec is 31s; it needs at least 46 s",
        "deploy/h/deployment.yaml:1: kubernetes: terminationGracePeriodSeconds is 31; it needs at least 61 s",
        "deploy/i/u.service:1: systemd: TimeoutStopSec 'soon' cannot be read; it needs at least 31 s",
        "docs/run-inline.md:1: serving docker run --stop-timeout is unset; it needs at least 31 s",
        "docs/run-multiline.md:2: serving docker run --stop-timeout is 30; it needs at least 31 s",
        "docs/parent.md:11: serving docker run --stop-timeout is 31; it needs at least 51 s",
    ]
    for line in expect:
        assert line in found, (line, found)
    print(f"check-stop-grace self-test: ok ({len(rows)} table rows, {len(PLANTED)} planted, {len(CLEAN)} clean)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""MIK-8513: offline rows for the registry content and start checks.

Each row is its own function; the runner at the bottom calls every one and
prints PASS/FAIL per row, so a run on a checker without the feature shows
every row failing for its own reason instead of stopping at the first.
The test plan is docs/internal/design/2026-10-23-mik-8513-test-plan.md.
"""

import contextlib
import importlib.util
import io
import json
import subprocess
import sys
import tempfile
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
REGISTRY = REPO / "src/registry/server_registry_entries.rs"
SIDECAR = HERE / "registry-integrity.json"


def load_checker():
    """A fresh module per row, so one row's stubs never leak into the next."""
    spec = importlib.util.spec_from_file_location("crp", HERE / "check-registry-packages.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


NPM_A = "sha512-" + "A" * 86 + "=="
NPM_B = "sha512-" + "B" * 86 + "=="
SHA_A = "a" * 64
SHA_B = "b" * 64


def entry_block(name, command, *, setup="Setup::Ready", env="&[]", auth="Auth::None"):
    return (
        "    ServerCatalogEntry {\n"
        f'        name: "{name}",\n'
        f'        command: "{command}",\n'
        f"        required_env: {env},\n"
        "        transport: Transport::Stdio,\n"
        f"        auth: {auth},\n"
        f"        setup: {setup},\n"
        "    },\n"
    )


def write_case(tmp, blocks, sidecar):
    """A registry source and its sidecar in `tmp`; returns both paths."""
    src = Path(tmp) / "registry.rs"
    src.write_text("static CATALOG: &[ServerCatalogEntry] = &[\n" + "".join(blocks) + "];\n")
    side = Path(tmp) / "registry.integrity.json"
    side.write_text(sidecar if isinstance(sidecar, str) else json.dumps(sidecar))
    return src, side


def run_main(crp, *args):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = crp.main(["check-registry-packages.py", *map(str, args)])
    return rc, out.getvalue()


def expect(cond, message):
    if not cond:
        raise AssertionError(message)


def raiser(name):
    def fail(*_args, **_kwargs):
        raise AssertionError(f"{name} was called")
    return fail


# ── CONTENT.1 / CONTENT.3: the sidecar, offline ─────────────────────────────

def o1_sidecar_required():
    crp = load_checker()
    with tempfile.TemporaryDirectory() as tmp:
        src, side = write_case(tmp, [entry_block("a", "npx -y p@1.0.0")], {"npm": {}, "pypi": {}})
        rc, out = run_main(crp, "--offline", src, "--integrity", side)
    expect(rc == 1 and "FAIL a: no integrity record" in out, out)


def o2_sidecar_orphan():
    crp = load_checker()
    with tempfile.TemporaryDirectory() as tmp:
        src, side = write_case(
            tmp, [entry_block("a", "npx -y p@1.0.0")],
            {"npm": {"p@1.0.0": NPM_A, "gone@2.0.0": NPM_B}, "pypi": {}},
        )
        rc, out = run_main(crp, "--offline", src, "--integrity", side)
    expect(rc == 1 and "gone@2.0.0" in out and "orphan" in out, out)


def o3_sidecar_format():
    cases = {
        "short sha512": {"npm": {"p@1.0.0": "sha512-" + "A" * 40 + "=="}, "pypi": {}},
        "not base64": {"npm": {"p@1.0.0": "sha512-" + "!" * 86 + "=="}, "pypi": {}},
        "wrong prefix": {"npm": {"p@1.0.0": "sha256-" + "A" * 86 + "=="}, "pypi": {}},
        "non-hex sha256": {"npm": {"p@1.0.0": NPM_A}, "pypi": {"q==1.0": {"q-1.0.tar.gz": "z" * 64}}},
        "uppercase sha256": {"npm": {"p@1.0.0": NPM_A}, "pypi": {"q==1.0": {"q-1.0.tar.gz": "A" * 64}}},
        "not json": "{ this is not json",
    }
    blocks = [entry_block("a", "npx -y p@1.0.0"), entry_block("b", "uvx q@1.0")]
    for label, sidecar in cases.items():
        crp = load_checker()
        with tempfile.TemporaryDirectory() as tmp:
            src, side = write_case(tmp, blocks, sidecar)
            rc, out = run_main(crp, "--offline", src, "--integrity", side)
        expect(rc == 1 and "FAIL" in out, f"{label}: {out}")


def o4_offline_is_offline():
    crp = load_checker()
    crp.fetch = raiser("fetch")
    crp.run_container = raiser("run_container")
    saved = (subprocess.run, subprocess.Popen)
    subprocess.run, subprocess.Popen = raiser("subprocess.run"), raiser("subprocess.Popen")
    try:
        rc, out = run_main(crp, "--offline", REGISTRY, "--integrity", SIDECAR)
    finally:
        subprocess.run, subprocess.Popen = saved
    expect(rc == 0, out)


def npm_doc(integrity):
    dist = {} if integrity is None else {"integrity": integrity}
    return (200, json.dumps({"dist": dist}).encode())


def o5_npm_metadata():
    crp = load_checker()
    answers = {}
    crp.fetch = lambda url, body=None: answers[url]
    url = "https://registry.npmjs.org/p/1.0.0"
    for served, ok in ((NPM_B, False), (None, False), (NPM_A, True)):
        answers[url] = npm_doc(served)
        reason = crp.probe("npm", "p", "1.0.0", NPM_A)
        expect((reason is None) == ok, f"served {served}: {reason}")
        expect(ok or "integrity" in reason, reason)


def pypi_doc(files):
    urls = [{"filename": name, "digests": {"sha256": digest}, "yanked": False} for name, digest in files.items()]
    return (200, json.dumps({"urls": urls}).encode())


def o6_pypi_fileset():
    crp = load_checker()
    answers = {}
    crp.fetch = lambda url, body=None: answers[url]
    url = "https://pypi.org/pypi/q/1.0/json"
    recorded = {"q-1.0-py3-none-any.whl": SHA_A, "q-1.0.tar.gz": SHA_B}
    served_cases = {
        "changed": {"q-1.0-py3-none-any.whl": SHA_B, "q-1.0.tar.gz": SHA_B},
        "extra": {**recorded, "q-1.0-cp312-manylinux.whl": SHA_A},
        "missing": {"q-1.0.tar.gz": SHA_B},
    }
    for label, served in served_cases.items():
        answers[url] = pypi_doc(served)
        reason = crp.probe("pypi", "q", "1.0", recorded)
        expect(reason is not None and "integrity" in reason, f"{label}: {reason}")
    answers[url] = pypi_doc(recorded)
    expect(crp.probe("pypi", "q", "1.0", recorded) is None, "equal map must pass")


# ── CONTENT.1 bytes and the CONTENT.2 pipeline, with Docker stubbed ─────────

def step_of(argv):
    """Which design step a recorded Docker argv belongs to."""
    text = " ".join(argv)
    if "chown" in text:
        return "setup"
    if " pack " in f" {text} ":
        return "fetch-npm"
    if " download " in f" {text} ":
        return "fetch-pypi"
    if "npm exec" in text or ("uv" in argv and "tool" in argv and "install" in argv):
        return "prime"
    if argv[:2] in (["docker", "rm"], ["docker", "volume"]):
        return "admin"
    return "other"


class Recorder:
    """Stands in for `run_container` and `handshake`; answers by step."""

    def __init__(self, npm_served=None, pip_refuses=False):
        self.calls = []
        self.npm_served = npm_served
        self.pip_refuses = pip_refuses

    def run_container(self, argv, stdin=None, timeout=None):
        self.calls.append((step_of(argv), list(argv), stdin, timeout))
        step = step_of(argv)
        if step == "fetch-npm":
            return 0, json.dumps([{"integrity": self.npm_served}]).encode(), b""
        if step == "fetch-pypi" and self.pip_refuses:
            return 1, b"", b"ERROR: THESE PACKAGES DO NOT MATCH THE HASHES FROM THE REQUIREMENTS FILE."
        return 0, b"", b""

    def handshake(self, argv, timeout=None):
        self.calls.append(("start", list(argv), None, timeout))
        return None

    def steps(self):
        return [c[0] for c in self.calls]


def live_case(crp, tmp, blocks, sidecar, metadata, recorder):
    """Run `--start` on a synthetic registry with the network and Docker stubbed."""
    crp.fetch = lambda url, body=None: metadata[url]
    crp.run_container = recorder.run_container
    crp.handshake = recorder.handshake
    src, side = write_case(tmp, blocks, sidecar)
    return run_main(crp, "--start", src, "--integrity", side)


NPM_URL = "https://registry.npmjs.org/p/1.0.0"
PYPI_URL = "https://pypi.org/pypi/q/1.0/json"
PYPI_FILES = {"q-1.0-py3-none-any.whl": SHA_A, "q-1.0.tar.gz": SHA_B}


def o7_npm_served_bytes():
    for served, ok in ((NPM_B, False), (NPM_A, True)):
        crp = load_checker()
        rec = Recorder(npm_served=served)
        with tempfile.TemporaryDirectory() as tmp:
            rc, out = live_case(
                crp, tmp, [entry_block("a", "npx -y p@1.0.0")],
                {"npm": {"p@1.0.0": NPM_A}, "pypi": {}}, {NPM_URL: npm_doc(NPM_A)}, rec,
            )
        expect("fetch-npm" in rec.steps(), f"no npm pack ran: {rec.steps()}")
        expect(ok == ("served bytes" not in out), f"served {served}: {out}")


def o8_pypi_served_bytes():
    for refuses in (True, False):
        crp = load_checker()
        rec = Recorder(pip_refuses=refuses)
        with tempfile.TemporaryDirectory() as tmp:
            rc, out = live_case(
                crp, tmp, [entry_block("b", "uvx q@1.0")],
                {"npm": {}, "pypi": {"q==1.0": PYPI_FILES}}, {PYPI_URL: pypi_doc(PYPI_FILES)}, rec,
            )
        fetches = [c for c in rec.calls if c[0] == "fetch-pypi"]
        expect(len(fetches) == 1, f"pip download calls: {rec.steps()}")
        _, argv, stdin, _ = fetches[0]
        tail = argv[argv.index("pip"):]
        expect(tail == ["pip", "download", "-d", "/work", "--no-deps", "--require-hashes", "-r", "/dev/stdin"], tail)
        line = (stdin or b"").decode().strip().split()
        want = ["q==1.0"] + sorted(f"--hash=sha256:{d}" for d in PYPI_FILES.values())
        expect([line[0]] + sorted(line[1:]) == want, f"requirement line {line}")
        expect(refuses == ("served bytes" in out), f"refuses={refuses}: {out}")


def o17_skip_pipeline():
    crp = load_checker()
    crp.START_SKIP = {**getattr(crp, "START_SKIP", {}), "s-npm": "needs a browser"}
    rec = Recorder(npm_served=NPM_A)
    blocks = [
        entry_block("e-npm", "npx -y p@1.0.0"),
        entry_block("e-pypi", "uvx q@1.0"),
        entry_block("s-npm", "npx -y r@1.0.0"),
        entry_block("s-pypi", "uvx t@1.0", setup="Setup::NeedsService { hint: \"a db\" }"),
    ]
    sidecar = {"npm": {"p@1.0.0": NPM_A, "r@1.0.0": NPM_A},
               "pypi": {"q==1.0": PYPI_FILES, "t==1.0": PYPI_FILES}}
    metadata = {NPM_URL: npm_doc(NPM_A), "https://registry.npmjs.org/r/1.0.0": npm_doc(NPM_A),
                PYPI_URL: pypi_doc(PYPI_FILES), "https://pypi.org/pypi/t/1.0/json": pypi_doc(PYPI_FILES)}
    with tempfile.TemporaryDirectory() as tmp:
        rc, out = live_case(crp, tmp, blocks, sidecar, metadata, rec)
    steps = rec.steps()
    expect(steps.count("fetch-npm") == 2 and steps.count("fetch-pypi") == 2, f"fetch for all four: {steps}")
    expect(steps.count("prime") == 2 and steps.count("start") == 2, f"prime/start for eligible only: {steps}")
    expect(steps.count("setup") == 4, f"a prepared volume per entry: {steps}")
    starts = " ".join(" ".join(c[1]) for c in rec.calls if c[0] in ("prime", "start"))
    expect("r@1.0.0" not in starts and "t" not in starts.split(), f"a skipped entry was primed or started: {starts}")


def o18_caps():
    crp = load_checker()
    rec = Recorder(npm_served=NPM_A)
    with tempfile.TemporaryDirectory() as tmp:
        live_case(crp, tmp, [entry_block("a", "npx -y p@1.0.0")],
                  {"npm": {"p@1.0.0": NPM_A}, "pypi": {}}, {NPM_URL: npm_doc(NPM_A)}, rec)
    caps = {c[0]: c[3] for c in rec.calls if c[0] in ("fetch-npm", "prime", "start")}
    expect(caps == {"fetch-npm": 120, "prime": 180, "start": 60}, caps)


# ── CONTENT.2: who is eligible ───────────────────────────────────────────────

def parsed(crp, block):
    return crp.parse_entries(block)[0]


def o9_eligibility():
    crp = load_checker()
    crp.START_SKIP = {"skipme": "needs a browser"}
    eligible = parsed(crp, entry_block("ok", "npx -y p@1.0.0"))
    expect(crp.eligibility(eligible) is None, crp.eligibility(eligible))
    cases = {
        "env": (entry_block("env", "npx -y p@1.0.0", env='&["API_KEY"]'), "needs credentials"),
        "auth": (entry_block("auth", "npx -y p@1.0.0", auth="Auth::EnvVars"), "needs credentials"),
        "args": (entry_block("args", "npx -y p@1.0.0", setup='Setup::NeedsArgs {\n            hint: "the folders",\n        }'), "needs arguments"),
        "service": (entry_block("service", "npx -y p@1.0.0", setup='Setup::NeedsService { hint: "a db" }'), "needs a service"),
        "skipme": (entry_block("skipme", "npx -y p@1.0.0"), "needs a browser"),
    }
    for label, (block, reason) in cases.items():
        got = crp.eligibility(parsed(crp, block))
        expect(got is not None and reason in got, f"{label}: {got}")


def o10_real_registry_eligible():
    crp = load_checker()
    entries = crp.parse_entries(REGISTRY.read_text())
    eligible = {e["name"] for e in entries if "command" in e and crp.eligibility(e) is None}
    expect(eligible == {"memory", "sequential-thinking", "fetch", "time"}, sorted(eligible))
    by_name = {e["name"]: e for e in entries}
    expect("needs a browser" in (crp.eligibility(by_name["playwright"]) or ""), "playwright")
    expect("the directories it may access" in (crp.eligibility(by_name["filesystem"]) or ""), "filesystem hint")


# ── CONTENT.2: isolation flags and cleanup, read from the argv sent ─────────

ALLOWED_ENV = {
    "HOME": "/work",
    "npm_config_cache": "/work/.npm",
    "UV_CACHE_DIR": "/work/.uv",
    "UV_TOOL_DIR": "/work/tools",
    "UV_TOOL_BIN_DIR": "/work/bin",
    "XDG_CACHE_HOME": "/work/.cache",
}
COMMON_FLAGS = [
    "--rm", "--read-only", "--log-driver", "none", "-w", "/work", "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges", "--memory", "1g", "--pids-limit", "256", "--cpus", "1",
    "--tmpfs", "/tmp:exec,size=256m,uid=1000,gid=1000,mode=1777",
]


def env_of(argv):
    names = {}
    for i, arg in enumerate(argv):
        if arg == "-e":
            name, _, value = argv[i + 1].partition("=")
            names[name] = value
    return names


def volume_of(argv):
    for i, arg in enumerate(argv):
        if arg in ("-v", "--volume") and argv[i + 1].endswith(":/work"):
            return argv[i + 1].rsplit(":", 1)[0]
        if arg == "--mount" and "dst=/work" in argv[i + 1]:
            return dict(kv.split("=", 1) for kv in argv[i + 1].split(","))["src"]
    return None


def has_seq(argv, seq):
    return any(argv[i:i + len(seq)] == seq for i in range(len(argv)))


def o11_argv_isolation():
    crp = load_checker()
    rec = Recorder(npm_served=NPM_A)
    hostile = "npx -y p@1.0.0 --x;touch /tmp/pwn $(id)"
    blocks = [entry_block("a", hostile), entry_block("b", "uvx q@1.0")]
    with tempfile.TemporaryDirectory() as tmp:
        live_case(crp, tmp, blocks, {"npm": {"p@1.0.0": NPM_A}, "pypi": {"q==1.0": PYPI_FILES}},
                  {NPM_URL: npm_doc(NPM_A), PYPI_URL: pypi_doc(PYPI_FILES)}, rec)
    package_steps = [c for c in rec.calls if c[0] in ("fetch-npm", "fetch-pypi", "prime", "start")]
    setups = [c for c in rec.calls if c[0] == "setup"]
    expect(package_steps and setups, f"steps: {rec.steps()}")
    volumes = set()
    for step, argv, _, _ in package_steps + setups:
        expect(argv[:2] == ["docker", "run"], f"{step} is not an exec-form docker run: {argv[:3]}")
        for flag in COMMON_FLAGS:
            expect(flag in argv, f"{step} lacks {flag}")
        expect(any("@sha256:" in a for a in argv), f"{step} image not pinned by digest")
        vol = volume_of(argv)
        expect(vol and not vol.startswith("/"), f"{step} must mount a named volume at /work, got {vol}")
        volumes.add(vol)
        expect(not any(a.startswith("/") and ":" in a and not a.endswith(":/work") for a in argv if a != COMMON_FLAGS[-1]),
               f"{step} has a host bind mount")
        if step == "setup":
            caps_added = [argv[i + 1] for i, a in enumerate(argv) if a == "--cap-add"]
            expect(caps_added == ["CHOWN"], f"setup may get back CHOWN only, got {caps_added}")
            expect(env_of(argv) == {}, f"setup passes environment: {env_of(argv)}")
            expect(has_seq(argv, ["--network", "none"]), "setup must have no network")
            expect("pwn" not in " ".join(argv) and "p@1.0.0" not in " ".join(argv), "setup argv carries entry data")
            text = " ".join(argv)
            expect(text.index("mkdir") < text.index("chown"), "setup must mkdir before chown")
        else:
            expect(has_seq(argv, ["--user", "1000:1000"]), f"{step} not uid 1000")
            expect("--cap-add" not in argv, f"{step} gets a capability back; only setup may")
            env = env_of(argv)
            expect({k: v for k, v in env.items() if k != "PATH"} == ALLOWED_ENV, f"{step} env {env}")
            expect(env.get("PATH", "").startswith("/work/bin:"), f"{step} PATH {env.get('PATH')}")
            expect("sh" not in argv and "-c" not in argv and "bash" not in argv, f"{step} goes through a shell")
    expect(len(volumes) == 2, f"one fresh volume per entry, got {volumes}")
    for step, argv, _, _ in package_steps:
        expect(("-i" in argv) == (step in ("fetch-npm", "fetch-pypi", "start")), f"{step} -i")
        expect(has_seq(argv, ["--network", "none"]) == (step == "start"), f"{step} network")
    hostile_start = [c[1] for c in package_steps if c[0] == "start" and "p@1.0.0" in " ".join(c[1])]
    for argv in hostile_start:
        expect("--x;touch" in argv and "$(id)" in argv, "the entry's args must reach the server as literal argv items")


def o12_cleanup():
    outcomes = ("success", "nonzero", "handshake", "timeout-fetch", "timeout-prime", "timeout-start")
    for outcome in outcomes:
        crp = load_checker()
        rec = Recorder(npm_served=NPM_A)
        base_run, base_hs = rec.run_container, rec.handshake

        def run(argv, stdin=None, timeout=None, outcome=outcome):
            step = step_of(argv)
            if outcome == "nonzero" and step == "prime":
                rec.calls.append((step, list(argv), stdin, timeout))
                return 2, b"", b"boom"
            if outcome == f"timeout-{step.split('-')[0]}":
                rec.calls.append((step, list(argv), stdin, timeout))
                raise subprocess.TimeoutExpired(argv, timeout)
            return base_run(argv, stdin, timeout)

        def hs(argv, timeout=None, outcome=outcome):
            if outcome == "handshake":
                rec.calls.append(("start", list(argv), None, timeout))
                return "replied with an error"
            if outcome == "timeout-start":
                rec.calls.append(("start", list(argv), None, timeout))
                raise subprocess.TimeoutExpired(argv, timeout)
            return base_hs(argv, timeout)

        rec.run_container, rec.handshake = run, hs
        with tempfile.TemporaryDirectory() as tmp:
            live_case(crp, tmp, [entry_block("a", "npx -y p@1.0.0")],
                      {"npm": {"p@1.0.0": NPM_A}, "pypi": {}}, {NPM_URL: npm_doc(NPM_A)}, rec)
        mounted = {volume_of(c[1]) for c in rec.calls if c[0] in ("setup", "fetch-npm", "prime", "start")} - {None}
        admin = [" ".join(c[1]) for c in rec.calls if c[0] == "admin"]
        for vol in mounted:
            expect(any(a.startswith("docker volume rm") and vol in a for a in admin), f"{outcome}: volume {vol} not removed: {admin}")
        starts = [c[1] for c in rec.calls if c[0] == "start"]
        for argv in starts:
            name = argv[argv.index("--name") + 1] if "--name" in argv else None
            expect(name and any(a.startswith("docker rm -f") and name in a for a in admin), f"{outcome}: start container not removed: {admin}")


# ── CONTENT.2: the initialize handshake, against local fake servers ─────────
# The one deliberate exception to "every process is stubbed": tiny Python
# servers started directly, no Docker, no network.

FAKE_PRELUDE = """
import json, sys, time
line = sys.stdin.readline()
req = json.loads(line)
ok_request = (
    line.endswith("\\n") and line.count("\\n") == 1 and req.get("jsonrpc") == "2.0"
    and req.get("id") == 1 and req.get("method") == "initialize"
    and isinstance(req.get("params", {}).get("protocolVersion"), str)
    and req["params"].get("capabilities") == {}
    and isinstance(req["params"].get("clientInfo"), dict)
)
def send(obj):
    sys.stdout.write(json.dumps(obj) + "\\n"); sys.stdout.flush()
GOOD = {"protocolVersion": "2025-06-18", "capabilities": {}, "serverInfo": {"name": "fake", "version": "1"}}
"""

FAKES = {
    "pass_and_stay": "send({'jsonrpc': '2.0', 'id': 1, 'result': GOOD} if ok_request else {'jsonrpc': '2.0', 'id': 1, 'error': {'code': -1, 'message': 'bad request'}})\ntime.sleep(30)",
    "timeout": "time.sleep(30)",
    "malformed": "sys.stdout.write('{not json\\n'); sys.stdout.flush(); time.sleep(30)",
    "wrong_id": "send({'jsonrpc': '2.0', 'id': 2, 'result': GOOD}); time.sleep(30)",
    "error_reply": "send({'jsonrpc': '2.0', 'id': 1, 'error': {'code': -32600, 'message': 'no'}}); time.sleep(30)",
    "exit3": "sys.exit(3)",
    "no_result": "send({'jsonrpc': '2.0', 'id': 1}); time.sleep(30)",
    "no_protocol": "send({'jsonrpc': '2.0', 'id': 1, 'result': {'serverInfo': GOOD['serverInfo']}}); time.sleep(30)",
    "no_server_info": "send({'jsonrpc': '2.0', 'id': 1, 'result': {'protocolVersion': '2025-06-18'}}); time.sleep(30)",
    "huge_line": "sys.stdout.write('x' * (2 * 1024 * 1024)); sys.stdout.flush(); time.sleep(30)",
    "many_frames": "[sys.stdout.write(json.dumps({'jsonrpc': '2.0', 'method': 'notifications/message', 'params': {'pad': 'y' * 1000}}) + '\\n') for _ in range(1200)]; sys.stdout.flush(); time.sleep(30)",
    "stderr_flood": "sys.stderr.write('E' * (1024 * 1024) + 'TAIL-MARKER'); sys.stderr.flush(); sys.exit(4)",
}


def fake_argv(tmp, name):
    path = Path(tmp) / f"{name}.py"
    path.write_text(FAKE_PRELUDE + FAKES[name] + "\n")
    return [sys.executable, "-I", str(path)]


def o13_handshake_pass():
    import time
    crp = load_checker()
    with tempfile.TemporaryDirectory() as tmp:
        started = time.monotonic()
        reason = crp.handshake(fake_argv(tmp, "pass_and_stay"), timeout=5)
        elapsed = time.monotonic() - started
    expect(reason is None, f"a valid reply from a server that stays up must pass: {reason}")
    expect(elapsed < 4, f"PASS must come on the reply, not at the cap: {elapsed:.1f}s")


def o14_handshake_fails():
    expected = {
        "timeout": "within", "malformed": "malformed", "wrong_id": "id",
        "error_reply": "error", "exit3": "exited 3", "no_result": "result",
        "no_protocol": "protocolVersion", "no_server_info": "serverInfo",
        "huge_line": "budget", "many_frames": "budget",
    }
    with tempfile.TemporaryDirectory() as tmp:
        for name, word in expected.items():
            crp = load_checker()
            reason = crp.handshake(fake_argv(tmp, name), timeout=3)
            expect(reason is not None and word in reason, f"{name}: {reason!r}")


def o19_stderr_tail():
    crp = load_checker()
    with tempfile.TemporaryDirectory() as tmp:
        reason = crp.handshake(fake_argv(tmp, "stderr_flood"), timeout=5) or ""
    expect("TAIL-MARKER" in reason, "the stderr tail must reach the FAIL line")
    expect(len(reason.encode()) <= 4096 + 256, f"stderr kept beyond the 4 KiB tail: {len(reason)} bytes")


def o16_frame():
    crp = load_checker()
    with tempfile.TemporaryDirectory() as tmp:
        # pass_and_stay answers with an error unless the request has the exact
        # initialize shape, so a PASS here proves the frame.
        reason = crp.handshake(fake_argv(tmp, "pass_and_stay"), timeout=5)
    expect(reason is None, f"the request is not a single-line JSON-RPC initialize: {reason}")


def o15_summary():
    crp = load_checker()
    rec = Recorder(npm_served=NPM_A)
    blocks = [entry_block(n, f"npx -y {n}@1.0.0") for n in ("p1", "p2", "p3", "p4")]
    blocks.append(entry_block("skipped", "npx -y p5@1.0.0", setup='Setup::NeedsService { hint: "a db" }'))
    sidecar = {"npm": {f"p{i}@1.0.0": NPM_A for i in range(1, 6)}, "pypi": {}}
    metadata = {f"https://registry.npmjs.org/p{i}/1.0.0": npm_doc(NPM_A) for i in range(1, 6)}
    rec.handshake = lambda argv, timeout=None: (rec.calls.append(("start", list(argv), None, timeout)),
                                                 "exited 1 before answering initialize" if "p2@1.0.0" in " ".join(argv) else None)[1]
    with tempfile.TemporaryDirectory() as tmp:
        rc, out = live_case(crp, tmp, blocks, sidecar, metadata, rec)
    expect(rc == 1, f"rc {rc}: {out}")
    expect("3/4 eligible entries start" in out, out)
    expect("SKIP skipped:" in out, out)


ROWS = [
    o1_sidecar_required, o2_sidecar_orphan, o3_sidecar_format, o4_offline_is_offline,
    o5_npm_metadata, o6_pypi_fileset, o7_npm_served_bytes, o8_pypi_served_bytes,
    o9_eligibility, o10_real_registry_eligible, o17_skip_pipeline, o11_argv_isolation,
    o18_caps, o12_cleanup, o13_handshake_pass, o14_handshake_fails, o19_stderr_tail,
    o15_summary, o16_frame,
]


def main():
    failed = 0
    for row in ROWS:
        try:
            row()
            print(f"PASS {row.__name__}")
        except Exception as exc:  # each row reports its own failure; the run continues
            failed += 1
            last = traceback.extract_tb(exc.__traceback__)[-1]
            print(f"FAIL {row.__name__}: {type(exc).__name__}: {str(exc)[:300]} (line {last.lineno})")
    print(f"{len(ROWS) - failed}/{len(ROWS)} registry content rows pass")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

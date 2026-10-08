#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""EVENTS.8 operator run: a separate gateway, an OAuth shim and a tunnel.

  up --gateway BIN   start gateway (port 39561), shim (39560) and a cloudflared
                     quick tunnel; print the connector URL; stay in front
  fire               post one signed GitHub-style push to the gateway
  evidence           check the run against the criterion; write evidence.json

Everything lives under --dir (default ~/events8-run). It never touches the
live gateway: separate ports, separate HOME, separate store. Stdlib only.
"""
import argparse, hashlib, hmac, json, os, re, secrets, signal, socket, stat, subprocess, sys, time
import urllib.request
from datetime import datetime
from pathlib import Path

# Overridable so tests on a shared host can use ports nothing else holds.
GW_PORT = int(os.environ.get("EVENTS8_GW_PORT", "39561"))
SHIM_PORT = int(os.environ.get("EVENTS8_SHIM_PORT", "39560"))
EVENT = "webhook.github.push.received"
SCRIPTS = Path(__file__).resolve().parent
CAPABILITY = """name: github
description: GitHub push webhooks
schema:
  input: { type: object, properties: {} }
  output: { type: object }
providers: {}
webhooks:
  push:
    path: /github/push
    method: POST
    secret: "{env.EVENTS8_WEBHOOK_SECRET}"
    signature_header: "X-Hub-Signature-256"
    transform:
      event_type: "github.{action}"
      data: { repo: "{repository.full_name}", ref: "{ref}" }
    event:
      description: "A push to a repository the gateway receives webhooks for."
      filters: [repo, ref]
      delivery_id_header: X-GitHub-Delivery
"""


OWNER = "events8_run"  # names this script in state.json: the only directory up empties


def state_path(d):
    return d / "state.json"


def owned(d):
    """True only when d/state.json is this script's: a generic state.json
    written by anything else is not a licence to empty the directory, and a
    symlink or hard link cannot lend another directory's marker. A symlinked
    d is never owned: its target is somebody else's directory."""
    fd = open_run_dir(d)
    if fd is None:
        return False
    try:
        return owned_at(fd)
    finally:
        os.close(fd)


def open_run_dir(d):
    """A handle on d itself, never on what a symlink at d points to."""
    try:
        return os.open(d, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        return None


def owned_at(fd):
    """`owned`, judged through the directory handle fd."""
    try:
        # O_NONBLOCK: a FIFO marker is refused by the type check, not waited on.
        mfd = os.open("state.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    except OSError:
        return False
    with os.fdopen(mfd) as marker:
        st = os.fstat(marker.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            return False
        try:
            state = json.loads(marker.read())
        except (OSError, ValueError):
            return False
    return isinstance(state, dict) and state.get("owner") == OWNER


def clear_owned(d):
    """Empty d if it is this script's run directory, else remove nothing.

    One handle, opened without following a symlink, carries the ownership
    check and every removal, so d cannot be swapped between them (MIK-7945).
    """
    fd = open_run_dir(d)
    if fd is None:
        return False
    try:
        if not owned_at(fd):
            return False
        for name in os.listdir(fd):
            remove_at(fd, name)
        return True
    finally:
        os.close(fd)


def remove_at(fd, name):
    """Remove name under the directory handle fd, never following a symlink.

    Hand-rolled rather than shutil.rmtree(dir_fd=), which needs Python 3.11."""
    if stat.S_ISDIR(os.stat(name, dir_fd=fd, follow_symlinks=False).st_mode):
        sub = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
        try:
            for child in os.listdir(sub):
                remove_at(sub, child)
        finally:
            os.close(sub)
        os.rmdir(name, dir_fd=fd)
    else:
        os.unlink(name, dir_fd=fd)


def digest(key):
    return "sha256:" + hashlib.sha256(key.encode()).hexdigest()


def write_config(d, key):
    caps = d / "caps"
    caps.mkdir(parents=True, exist_ok=True)
    (caps / "github.yaml").write_text(CAPABILITY)
    cfg = {
        "server": {"host": "127.0.0.1", "port": GW_PORT, "modern_protocol": True},
        "cache": {"enabled": False},
        "tasks": {"store_dir": str(d / "tasks")},
        "auth": {"enabled": True, "api_keys": [
            {"name": "chatgpt", "key_sha256": digest(key), "backends": ["hooks"]}]},
        "capabilities": {"enabled": True, "name": "hooks", "directories": [str(caps)]},
        "webhooks": {"enabled": True, "require_signature": True},
        "security": {"transparency_log": {"enabled": True, "path": str(d / "audit.jsonl")}},
        "events": {"enabled": True, "store_dir": str(d / "events")},
    }
    path = d / "gateway.yaml"
    path.write_text(json.dumps(cfg, indent=2))
    path.chmod(0o600)
    return path


def wait_http(url, seconds=60):
    end = time.time() + seconds
    while time.time() < end:
        try:
            urllib.request.urlopen(url, timeout=2)
            return True
        except Exception:
            time.sleep(0.5)
    return False


def start_tunnel(d, children):
    log = d / "tunnel.log"
    # An explicit empty config: a default ~/.cloudflared or /etc/cloudflared
    # config.yml would otherwise supply its own ingress and answer 404.
    (d / "cloudflared-empty.yml").write_text("")
    proc = subprocess.Popen(
        ["cloudflared", "tunnel", "--config", str(d / "cloudflared-empty.yml"),
         "--no-autoupdate", "--url", f"http://127.0.0.1:{SHIM_PORT}"],
        stdout=subprocess.DEVNULL, stderr=open(log, "w"))
    children.append(proc)
    end = time.time() + 60
    while time.time() < end:
        m = re.search(r"https://[a-z0-9-]+\.trycloudflare\.com", log.read_text())
        if m:
            return proc, m.group(0)
        time.sleep(0.5)
    sys.exit("no tunnel URL from cloudflared; see " + str(log))


def cmd_up(a):
    sys.stdout.reconfigure(line_buffering=True)
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt))
    d = Path(a.dir).expanduser()
    # Ownership first: a foreign directory is refused whatever holds the ports.
    # A symlink at d is refused even when its target is empty: up writes there.
    if d.is_symlink() or (d.exists() and any(d.iterdir()) and not owned(d)):
        sys.exit(f"{d} is not an events8 run directory; pass an empty --dir")
    for port in (GW_PORT, SHIM_PORT):
        with socket.socket() as probe:
            if probe.connect_ex(("127.0.0.1", port)) == 0:
                sys.exit(f"port {port} is already in use; stop the previous run first")
    # Judged again, through the handle the removal uses: the directory may
    # have changed during the probes. A previous run's files only.
    if d.is_symlink() or (d.exists() and any(d.iterdir()) and not clear_owned(d)):
        sys.exit(f"{d} is not an events8 run directory; pass an empty --dir")
    d.mkdir(parents=True, exist_ok=True)
    d.chmod(0o700)
    state_path(d).write_text(json.dumps({"owner": OWNER}))  # marks the directory as ours
    key = "events8-" + secrets.token_hex(24)
    secret = secrets.token_hex(24)
    cfg = write_config(d, key)
    env = {"PATH": os.environ["PATH"], "HOME": str(d), "EVENTS8_WEBHOOK_SECRET": secret,
           "MCP_GATEWAY_TEST_HOME_DIR": str(d)}
    children = []

    def alive(name, proc):
        if proc.poll() is not None:
            sys.exit(f"{name} exited early; see the logs in {d}")

    try:
        gw = subprocess.Popen([a.gateway, "--config", str(cfg), "serve"], env=env,
                              stdout=open(d / "gateway.log", "w"), stderr=subprocess.STDOUT)
        children.append(gw)
        if not wait_http(f"http://127.0.0.1:{GW_PORT}/health"):
            sys.exit("gateway did not come up; see " + str(d / "gateway.log"))
        alive("gateway", gw)
        tunnel, public = start_tunnel(d, children)
        shim = subprocess.Popen([sys.executable, str(SCRIPTS / "mcp_events_oauth_shim.py"),
                                 "--port", str(SHIM_PORT), "--upstream", str(GW_PORT),
                                 "--public", public, "--log", str(d / "shim.jsonl")],
                                env={**os.environ, "EVENTS8_API_KEY": key})
        children.append(shim)
        state = {"owner": OWNER, "public": public, "webhook_secret": secret, "started": time.time(),
                 "pids": [c.pid for c in children]}
        state_path(d).write_text(json.dumps(state))
        state_path(d).chmod(0o600)
        if not wait_http(f"http://127.0.0.1:{SHIM_PORT}/.well-known/oauth-protected-resource"):
            sys.exit("shim did not come up")
        for name, proc in (("gateway", gw), ("tunnel", tunnel), ("shim", shim)):
            alive(name, proc)
        if not wait_http(public + "/.well-known/oauth-protected-resource", 120):
            sys.exit("the tunnel URL does not answer yet; see " + str(d / "tunnel.log"))
        print(f"CONNECTOR URL (ChatGPT, OAuth, no client id needed): {public}/mcp")
        print(f"evidence directory: {d}")
        print("leave this running; Ctrl-C ends the run and closes the tunnel")
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        for p in children:
            p.terminate()


def cmd_fire(a):
    d = Path(a.dir).expanduser()
    st = json.loads(state_path(d).read_text())
    sub_rows = [r for r in lines(d / "shim.jsonl") if r.get("rpc") and "events/subscribe" in r["rpc"]
                and r.get("status") == 200 and r.get("result_has_id") and r.get("error_code") is None]
    if not sub_rows:
        sys.exit("no accepted events/subscribe yet: subscribe in the ChatGPT chat first")
    ref = a.ref or "refs/heads/events8-" + secrets.token_hex(3)
    delivery = "events8-" + secrets.token_hex(6)
    body = json.dumps({"action": "opened", "repository": {"full_name": a.repo},
                       "ref": ref}).encode()
    sig = "sha256=" + hmac.new(st["webhook_secret"].encode(), body, hashlib.sha256).hexdigest()
    req = urllib.request.Request(
        f"http://127.0.0.1:{GW_PORT}/webhooks/github/push", data=body, method="POST",
        headers={"content-type": "application/json", "X-Hub-Signature-256": sig,
                 "X-GitHub-Delivery": delivery})
    with urllib.request.urlopen(req, timeout=10) as r:
        status = r.status
    (d / "fire.json").write_text(json.dumps({
        "ts": time.time(), "signed": True, "hmac_checked_by_gateway": True, "signature_header": "X-Hub-Signature-256",
        "delivery_id": delivery, "ref": ref, "repo": a.repo, "status": status,
        "body_sha256": hashlib.sha256(body).hexdigest()}, indent=1))
    print("inbound signed webhook answered", status)
    print("ChatGPT should now report this ref:", ref)


def lines(path):
    if not Path(path).exists():
        return []
    out = []
    for line in Path(path).read_text().splitlines():
        try:
            out.append(json.loads(line))
        except ValueError:
            pass
    return out


def has(node, key, value):
    if isinstance(node, dict):
        return any((k == key and v == value) or has(v, key, value) for k, v in node.items())
    if isinstance(node, list):
        return any(has(v, key, value) for v in node)
    return False


def find(node, key):
    if isinstance(node, dict):
        for k, v in node.items():
            if k == key and isinstance(v, str):
                return v
            hit = find(v, key)
            if hit:
                return hit
    elif isinstance(node, list):
        for v in node:
            hit = find(v, key)
            if hit:
                return hit
    return None


def first(rows, test, after=-1):
    for i, row in enumerate(rows):
        if i > after and test(row):
            return i
    return None


def epoch(row):
    if "ts" in row:
        return row["ts"]
    text = re.sub(r"(\.\d{6})\d+", r"\1", str(row.get("timestamp", "")).replace("Z", "+00:00"))
    try:
        return datetime.fromisoformat(text).timestamp()
    except ValueError:
        return None


def cmd_evidence(a):
    d = Path(a.dir).expanduser()
    st = json.loads(state_path(d).read_text())
    start = st.get("started", 0)
    shim = [r for r in lines(d / "shim.jsonl") if r.get("ts", 0) >= start]
    audit = [r for r in lines(d / "audit.jsonl") if (epoch(r) or 0) >= start]
    fire = json.loads((d / "fire.json").read_text()) if (d / "fire.json").exists() else {}

    def rpc(m):
        return lambda r: (r.get("kind") == "http" and m in (r.get("rpc") or [])
                          and r.get("status") == 200 and r.get("error_code") is None
                          and r.get("reply_ok") is True and not r.get("parse_error"))

    def act(name, **kw):
        return lambda r: has(r, "action", name) and all(has(r, k, v) for k, v in kw.items())

    results, ok, last, sub_id = [], True, 0.0, None

    def step(name, rows, test, newer=True):
        nonlocal ok, last, sub_id
        hit = next((r for r in rows if test(r) and (not newer or (epoch(r) or 0) >= last - 1)), None)
        good = hit is not None
        if good:
            last = max(last, epoch(hit) or 0)
        ok &= good
        results.append({"check": name, "pass": good})
        return hit

    step("oauth token issued", shim, lambda r: r.get("step") == "token")
    step("server/discover or initialize", shim, lambda r: rpc("server/discover")(r) or rpc("initialize")(r))
    step("events/list", shim, rpc("events/list"))
    ver = step("verification handshake passed (gateway audit)", audit,
               act("events.verification", detail="verified", outcome="ok"))
    def named(method, r):
        return [p for p in r.get("rpc_params") or [] if p.get("method") == method]

    def wanted(r):
        # The param the criterion is about: this event, filtered to the repo fired at.
        return next((p for p in named("events/subscribe", r) if p.get("name") == EVENT and fire.get("repo")
                     and (p.get("arguments") or {}).get("repo") == fire["repo"]), None)

    def subscribed(r):
        # A single call: a batch reply's id may be another call's (MIK-7892).
        return (rpc("events/subscribe")(r) and r.get("rpc") == ["events/subscribe"]
                and bool(r.get("result_id")) and wanted(r) is not None)

    # Several subscribes may be filtered to the repo (ChatGPT retries): take the
    # one whose delivery the gateway audited, else the first, so a later complete
    # chain is not rejected for an earlier incomplete one.
    def first_seen(r):
        # When the gateway first audited this event: a retried older event was seen before the fire.
        ev = find(r, "event_id")
        times = [epoch(a) or 0 for a in audit if ev and has(a, "event_id", ev)]
        return min(times) if times else -1

    # Only deliveries for THIS fire count: an earlier run's subscription,
    # delivered before it or retrying an event seen before it, must not be
    # picked over this one (MIK-7945).
    delivered = {r.get("subscription_id") for r in audit
                 if has(r, "action", "events.delivery_outcome") and has(r, "delivered", True)
                 and (epoch(r) or 0) >= fire.get("ts", 1e18) - 1
                 and first_seen(r) >= fire.get("ts", 1e18) - 1}
    sub = step("events/subscribe answered with an id for this event and repo", shim,
               lambda r: subscribed(r) and r.get("result_id") in delivered) \
        if any(subscribed(r) and r.get("result_id") in delivered for r in shim) else \
        step("events/subscribe answered with an id for this event and repo", shim, subscribed)
    # Delivery and removal are bound to THIS subscription's id. The verification
    # handshake is not: the gateway reuses an earlier verified callback.
    sub_id = (sub or {}).get("result_id")
    sub_param = wanted(sub or {}) or {}
    sub_args, sub_key = sub_param.get("arguments") or {}, sub_param.get("key")
    step("signed inbound webhook accepted (fire.json)", [fire] if fire else [],
         lambda r: r.get("signed") and r.get("status") == 200 and (r.get("ts", 0) >= last - 1))
    step("signed delivery accepted 2xx for the same subscription (gateway audit)", audit,
         lambda r: has(r, "action", "events.delivery_outcome") and has(r, "delivered", True)
         and bool(sub_id) and has(r, "subscription_id", sub_id)
         and (epoch(r) or 0) >= fire.get("ts", 1e18) - 1
         and first_seen(r) >= fire.get("ts", 1e18) - 1)
    # The gateway reads no id on unsubscribe; it derives one from name, delivery
    # url and arguments, so the call must carry this subscription's key (MIK-7892).
    step("events/unsubscribe sent for the same subscription", shim,
         lambda r: rpc("events/unsubscribe")(r) and r.get("rpc") == ["events/unsubscribe"] and any(
             p.get("name") == EVENT and p.get("arguments") == sub_args and bool(sub_args)
             and bool(sub_key) and p.get("key") == sub_key
             for p in named("events/unsubscribe", r)))
    step("gateway removed that subscription (gateway audit)", audit,
         lambda r: has(r, "action", "events.unsubscribe") and has(r, "detail", "removed")
         and bool(sub_id) and has(r, "subscription_id", sub_id)
         and (epoch(r) or 0) >= fire.get("ts", 1e18) - 1, newer=False)
    for r in results:
        print("PASS" if r["pass"] else "FAIL", r["check"])
    print("AUTOMATED CHECKS:", "PASS" if ok else "FAIL",
          "- also send ChatGPT's chat reply (it must state the ref in fire.json)")
    (d / "evidence.json").write_text(json.dumps({
        "checks": results, "pass": ok, "fire_ref": fire.get("ref"),
        "subscription_id": sub_id, "fire_ts": fire.get("ts"), "last_ts": last,
        "shim_rows": len(shim), "audit_rows": len(audit)}, indent=1))
    return 0 if ok else 1


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--dir", default="~/events8-run")
    sub = p.add_subparsers(dest="cmd", required=True)
    up = sub.add_parser("up")
    up.add_argument("--gateway", required=True)
    fire = sub.add_parser("fire")
    fire.add_argument("--repo", default="demo/repo")
    fire.add_argument("--ref", default=None, help="default: a fresh ref per run")
    sub.add_parser("evidence")
    a = p.parse_args()
    return {"up": cmd_up, "fire": cmd_fire, "evidence": cmd_evidence}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())

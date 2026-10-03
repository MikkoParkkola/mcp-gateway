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
import argparse, hashlib, hmac, json, os, re, secrets, signal, subprocess, sys, time
import urllib.request
from pathlib import Path

GW_PORT, SHIM_PORT = 39561, 39560
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


def state_path(d):
    return d / "state.json"


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


def start_tunnel(d):
    log = d / "tunnel.log"
    # An explicit empty config: a default ~/.cloudflared or /etc/cloudflared
    # config.yml would otherwise supply its own ingress and answer 404.
    (d / "cloudflared-empty.yml").write_text("")
    proc = subprocess.Popen(
        ["cloudflared", "tunnel", "--config", str(d / "cloudflared-empty.yml"),
         "--no-autoupdate", "--url", f"http://127.0.0.1:{SHIM_PORT}"],
        stdout=subprocess.DEVNULL, stderr=open(log, "w"))
    end = time.time() + 60
    while time.time() < end:
        m = re.search(r"https://[a-z0-9-]+\.trycloudflare\.com", log.read_text())
        if m:
            return proc, m.group(0)
        time.sleep(0.5)
    proc.kill()
    sys.exit("no tunnel URL from cloudflared; see " + str(log))


def cmd_up(a):
    sys.stdout.reconfigure(line_buffering=True)
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt))
    d = Path(a.dir).expanduser()
    d.mkdir(parents=True, exist_ok=True)
    d.chmod(0o700)
    key = "events8-" + secrets.token_hex(24)
    secret = secrets.token_hex(24)
    cfg = write_config(d, key)
    env = {"PATH": os.environ["PATH"], "HOME": str(d), "EVENTS8_WEBHOOK_SECRET": secret,
           "MCP_GATEWAY_TEST_HOME_DIR": str(d)}
    gw = subprocess.Popen([a.gateway, "--config", str(cfg), "serve"], env=env,
                          stdout=open(d / "gateway.log", "w"), stderr=subprocess.STDOUT)
    if not wait_http(f"http://127.0.0.1:{GW_PORT}/health"):
        gw.kill()
        sys.exit("gateway did not come up; see " + str(d / "gateway.log"))
    tunnel, public = start_tunnel(d)
    shim = subprocess.Popen([sys.executable, str(SCRIPTS / "mcp_events_oauth_shim.py"),
                             "--port", str(SHIM_PORT), "--upstream", str(GW_PORT),
                             "--public", public, "--api-key", key, "--log", str(d / "shim.jsonl")])
    state = {"public": public, "webhook_secret": secret, "started": time.time(),
             "pids": [gw.pid, tunnel.pid, shim.pid]}
    state_path(d).write_text(json.dumps(state))
    state_path(d).chmod(0o600)
    if not wait_http(f"http://127.0.0.1:{SHIM_PORT}/.well-known/oauth-protected-resource"):
        sys.exit("shim did not come up")
    if not wait_http(public + "/.well-known/oauth-protected-resource", 120):
        sys.exit("the tunnel URL does not answer yet; see " + str(d / "tunnel.log"))
    print(f"CONNECTOR URL (ChatGPT, OAuth, no client id needed): {public}/mcp")
    print(f"evidence directory: {d}")
    print("leave this running; Ctrl-C ends the run and closes the tunnel")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        for p in (shim, tunnel, gw):
            p.terminate()


def cmd_fire(a):
    d = Path(a.dir).expanduser()
    st = json.loads(state_path(d).read_text())
    body = json.dumps({"action": "opened", "repository": {"full_name": a.repo},
                       "ref": a.ref}).encode()
    sig = "sha256=" + hmac.new(st["webhook_secret"].encode(), body, hashlib.sha256).hexdigest()
    req = urllib.request.Request(
        f"http://127.0.0.1:{GW_PORT}/webhooks/github/push", data=body, method="POST",
        headers={"content-type": "application/json", "X-Hub-Signature-256": sig,
                 "X-GitHub-Delivery": "events8-" + secrets.token_hex(6)})
    with urllib.request.urlopen(req, timeout=10) as r:
        print("inbound signed webhook answered", r.status)


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


def first(rows, test, after=-1):
    for i, row in enumerate(rows):
        if i > after and test(row):
            return i
    return None


def cmd_evidence(a):
    d = Path(a.dir).expanduser()
    shim, audit = lines(d / "shim.jsonl"), lines(d / "audit.jsonl")
    rpc = lambda m: (lambda r: r.get("kind") == "http" and m in (r.get("rpc") or []) and r["status"] < 300)
    act = lambda name, **kw: (lambda r: has(r, "action", name) and all(has(r, k, v) for k, v in kw.items()))
    checks = [
        ("oauth token issued", shim, lambda r: r.get("step") == "token"),
        ("server/discover or initialize", shim, lambda r: rpc("server/discover")(r) or rpc("initialize")(r)),
        ("events/list", shim, rpc("events/list")),
        ("events/subscribe answered with an id", shim,
         lambda r: rpc("events/subscribe")(r) and r.get("result_has_id")),
        ("verification handshake passed (gateway audit)", audit, act("events.verification", detail="verified", outcome="ok")),
        ("signed delivery accepted 2xx (gateway audit)", audit, act("events.delivery_outcome", delivered=True)),
        ("events/unsubscribe answered", shim, rpc("events/unsubscribe")),
    ]
    results, ok, pos = [], True, {}
    for name, rows, test in checks:
        key = id(rows)
        i = first(rows, test, pos.get(key, -1))
        results.append({"check": name, "pass": i is not None})
        ok &= i is not None
        if i is not None:
            pos[key] = i
    for r in results:
        print("PASS" if r["pass"] else "FAIL", r["check"])
    print("AUTOMATED CHECKS:", "PASS" if ok else "FAIL",
          "- also paste ChatGPT's chat reply (it must state the pushed ref)")
    (d / "evidence.json").write_text(json.dumps({"checks": results, "pass": ok,
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
    fire.add_argument("--ref", default="refs/heads/main")
    sub.add_parser("evidence")
    a = p.parse_args()
    return {"up": cmd_up, "fire": cmd_fire, "evidence": cmd_evidence}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Every test starts the gateway binary through tests/common/gateway_bin.rs (MIK-7637).

A spawned gateway is not built with `cfg(test)`, so only its environment keeps
it off the developer's real home and task store. The helper isolates that
environment on every OS; this check fails closed on anything else that could
start the binary or undo the isolation, in every `.rs` file under `tests/`
except the helper. `src/` is out of scope: only an integration test can name
the binary, in-crate tests run under the `cfg(test)` store guard, and product
code clears a backend child's environment on purpose:

- naming the binary (`CARGO_BIN_EXE_mcp-gateway`, `cargo_bin("mcp-gateway")`);
- `Command::new(...)` of the helper's `path()`, which bypasses `command()`;
- `env_clear()`;
- setting or removing an isolation variable (HOME, USERPROFILE,
  MCP_GATEWAY_TEST_HOME_DIR, APPDATA, LOCALAPPDATA);
- `.envs(...)` whose argument is not `gateway_bin::checked_env(...)`, which
  refuses isolation variables at run time (`Inherit::Nothing` already keeps
  `SystemRoot` and a coverage profile path).

In a file that builds a gateway command, every `.spawn()` sits inline inside
`gateway_bin::Reaped::new(...)`, which stops the gateway with a drain and
removes its folders only after it exited (a gateway that outlives its test
writes its home back into a removed folder). A spawn that is not the gateway,
or a gateway whose test waits for its exit itself, carries
`// spawn-check: not the gateway: <reason>` or
`// spawn-check: waits for exit: <reason>` on the `.spawn()` line. Files not
converted yet are listed in PENDING, which may only shrink: a listed file
with no unwrapped spawn left fails until it is removed from the list.

A test may still point the XDG directories elsewhere inside its own fixture;
those only relocate state the helper already moved off the real home.

A line that sets one of those for a process that is not the gateway carries
`// spawn-check: not the gateway: <reason>` on the same line; the reason is
required. Indirection (a variable holding `path()`) is not followed: this is a
guard against forgetting, not against intent.

usage: check-gateway-spawns.py [ROOT] | --self-test
"""
import pathlib
import re
import sys
import tempfile

HELPER = "tests/common/gateway_bin.rs"
ISOLATION = r"(?:HOME|USERPROFILE|MCP_GATEWAY_TEST_HOME_DIR|APPDATA|LOCALAPPDATA)"
RULES = [
    ("names the gateway binary", re.compile(r'CARGO_BIN_EXE_mcp-gateway|cargo_bin\(\s*"mcp-gateway"\s*\)')),
    ("spawns the binary path around the helper", re.compile(r"Command::new\(\s*(?:(?:\w+::)*gateway_bin::)?path\(\)")),
    ("clears a child environment", re.compile(r"\.env_clear\(\s*\)")),
    ("sets or removes an isolation variable",
     re.compile(r'\.env(?:_remove)?\(\s*"' + ISOLATION + r'"')),
    ("sets a variable list around checked_env", re.compile(r"\.envs\((?!\s*gateway_bin::checked_env\()")),
]
OPT_OUT = re.compile(r"//\s*spawn-check:\s*not the gateway:\s*\S")
GATEWAY_COMMAND = re.compile(
    r"gateway_bin::(?:command|command_with_env_home|wrapped)\(|\bchild_command\(|\.command\(\)")
SPAWN = re.compile(r"\.spawn\(\)")
SPAWN_OPT_OUT = re.compile(r"//\s*spawn-check:\s*(?:not the gateway|waits for exit):\s*\S")
# Files that still spawn a gateway outside Reaped; this list may only shrink.
PENDING = frozenset({
    "tests/b2_single_replica_state.rs",
    "tests/cli_broken_pipe.rs",
    "tests/cli_writer_lock.rs",
    "tests/clock_before_epoch_startup.rs",
    "tests/common/journey.rs",
    "tests/common/stdio_session.rs",
    "tests/cost_persistence_http.rs",
    "tests/d1_audit_required.rs",
    "tests/discovered_config_reload.rs",
    "tests/discovery_adopt_route.rs",
    "tests/discovery_listing_route.rs",
    "tests/e2e_add_url_streamable.rs",
    "tests/e2e_code_mode_journey.rs",
    "tests/e4_hash_key_cli.rs",
    "tests/f24_advertised_capabilities.rs",
    "tests/message_signing_nonce_schema.rs",
    "tests/message_signing_stdio_coverage.rs",
    "tests/message_signing_stdio_reload.rs",
    "tests/mik_7268_readiness_waits_for_capabilities.rs",
    "tests/mik_7272_owner2_stdio_tasks/helper.rs",
    "tests/mik_7272_sub2b_acs.rs",
    "tests/mik_7630_events/gateway.rs",
    "tests/mik_8398_provenance_cli.rs",
    "tests/mik_8783_window_flag.rs",
    "tests/nfr_compat_2_stdio_client_session.rs",
    "tests/shadow_scan_docs.rs",
    "tests/signature_chain_sites.rs",
    "tests/stderr_undrained_stdio.rs",
    "tests/stdio_account_startup.rs",
    "tests/stdio_exit_bounded.rs",
    "tests/stdio_sigterm_telemetry.rs",
    "tests/stdio_stop_drains_backend.rs",
    "tests/stdio_tests.rs",
    "tests/structured_stdout.rs",
    "tests/sub2b/http_harness.rs",
    "tests/task_expiry_http_lifecycle/helper.rs",
    "tests/task_upstream_recovery_sdk/helper.rs",
    "tests/task_upstream_recovery/helper.rs",
    "tests/u1_window_crash.rs",
})
# Written out, not derived: a file added to PENDING fails the self-test.
PENDING_CEILING = 39


def violations(root):
    root = pathlib.Path(root)
    if not (root / "tests").is_dir():
        raise SystemExit(f"FAIL: {root / 'tests'} is not a directory; nothing was checked")
    found = []
    for base in ("tests",):
        for path in sorted((root / base).rglob("*.rs")):
            relative = path.relative_to(root).as_posix()
            if relative == HELPER:
                continue
            text = path.read_text(encoding="utf-8")
            lines = text.splitlines()
            unwrapped = unwrapped_spawns(text, lines) if GATEWAY_COMMAND.search(text) else []
            if relative in PENDING:
                if not unwrapped:
                    found.append(f"{relative}:1: listed in PENDING with no unwrapped spawn left; remove it")
            else:
                found.extend(f"{relative}:{n}: spawns outside gateway_bin::Reaped" for n in unwrapped)
            for what, rule in RULES:
                for match in rule.finditer(text):
                    number = text.count("\n", 0, match.start()) + 1
                    if what.startswith("sets") and OPT_OUT.search(lines[number - 1]):
                        continue
                    found.append(f"{relative}:{number}: {what}")
    return sorted(found)


def unwrapped_spawns(text, lines):
    """Line numbers of `.spawn()` calls whose statement does not pass them
    to `Reaped::new(` and whose line carries no opt-out."""
    numbers = []
    for match in SPAWN.finditer(text):
        statement = text[text.rfind(";", 0, match.start()) + 1:match.start()]
        number = text.count("\n", 0, match.start()) + 1
        if "Reaped::new(" in statement or SPAWN_OPT_OUT.search(lines[number - 1]):
            continue
        numbers.append(number)
    return numbers


def self_test():
    planted = {
        "tests/raw.rs": 'let c = std::process::Command::new(env!("CARGO_BIN_EXE_mcp-gateway"));\n',
        "tests/clear.rs": "command.env_clear();\n",
        "tests/home.rs": 'command.env(\n    "HOME", dir);\n',
        "tests/bypass.rs": "let c = Command::new(gateway_bin::path());\n",
        "tests/qualified.rs": "let c = Command::new(signing_gateway::gateway_bin::path());\n",
        "tests/rooted.rs": "let c = Command::new(crate::gateway_bin::path());\n",
        "tests/no_reason.rs": 'node.env("HOME", dir); // spawn-check: not the gateway:\n',
        "tests/bulk.rs": "command.envs(vars.iter().copied());\n",
        "tests/bulk_home.rs": 'command.envs(std::env::var_os("HOME").map(|h| ("HOME", h)));\n',
        "tests/bulk_renamed.rs": 'command.envs(std::env::var_os("UserProfile").map(|p| ("MCP_GATEWAY_TEST_HOME_DIR", p)));\n',
        "tests/bare_spawn.rs": "let c = gateway_bin::command(h, i);\nlet child = c.spawn().unwrap();\n",
        "tests/spawn_no_reason.rs": "let c = gateway_bin::command(h, i);\nc.spawn() // spawn-check: waits for exit:\n;\n",
        sorted(PENDING)[0]: "let c = gateway_bin::command(h, i);\nlet r = gateway_bin::Reaped::new(c.spawn().unwrap());\n",
    }
    clean = {
        HELPER: 'pub fn path() -> &\'static str { env!("CARGO_BIN_EXE_mcp-gateway") }\ncommand.env_clear();\n',
        "tests/ok.rs": "let c = gateway_bin::command(home, gateway_bin::Inherit::Nothing);\n",
        "tests/node.rs": 'node.env("HOME", dir); // spawn-check: not the gateway: the node verifier\n',
        "tests/config.rs": 'let line = format!("{} serve --stdio", gateway_bin::path());\n',
        "tests/checked.rs": "command.envs(gateway_bin::checked_env(vars.iter().copied()));\n",
        "tests/checked_multiline.rs": "command.envs(\n    gateway_bin::checked_env(vars));\n",
        "src/transport/stdio.rs": "command.env_clear();\n",
        "tests/reaped.rs": "let mut c = gateway_bin::command(h, i);\nlet r = gateway_bin::Reaped::new(\n    c.arg(\"serve\")\n        .spawn()\n        .unwrap(),\n);\n",
        "tests/backend.rs": "let c = gateway_bin::command(h, i);\nlet b = py.spawn() // spawn-check: not the gateway: a python backend\n;\n",
        "tests/waits.rs": "let c = gateway_bin::command(h, i);\nlet g = c.spawn() // spawn-check: waits for exit: the row reaps it\n;\n",
        "tests/no_gateway.rs": "let child = node.spawn().unwrap();\n",
    }
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        (root / "src").mkdir()
        for name, text in {**planted, **clean}.items():
            (root / name).parent.mkdir(parents=True, exist_ok=True)
            (root / name).write_text(text, encoding="utf-8")
        got = violations(root)
    flagged = {line.split(":")[0] for line in got}
    assert flagged == set(planted), got
    assert "tests/home.rs:1: sets or removes an isolation variable" in got, got
    assert "tests/bare_spawn.rs:2: spawns outside gateway_bin::Reaped" in got, got
    assert f"{sorted(PENDING)[0]}:1: listed in PENDING with no unwrapped spawn left; remove it" in got, got
    assert len(PENDING) <= PENDING_CEILING, "PENDING may only shrink"
    with tempfile.TemporaryDirectory() as tmp:
        try:
            violations(tmp)
        except SystemExit as refused:
            assert "nothing was checked" in str(refused), refused
        else:
            raise AssertionError("a root with no tests/ directory passed")
    print("check-gateway-spawns self-test: ok")
    return 0


def main(argv):
    if argv[1:] == ["--self-test"]:
        return self_test()
    root = argv[1] if len(argv) > 1 else "."
    found = violations(root)
    for line in found:
        print(f"FAIL: {line}")
    if found:
        print(f"start the gateway through {HELPER} (gateway_bin::command); see its module docs")
        return 1
    print("every gateway spawn goes through tests/common/gateway_bin.rs")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

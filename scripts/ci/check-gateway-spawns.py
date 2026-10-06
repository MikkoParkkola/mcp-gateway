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
  MCP_GATEWAY_TEST_HOME_DIR, APPDATA, LOCALAPPDATA).

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
    ("spawns the binary path around the helper", re.compile(r"Command::new\(\s*(?:gateway_bin::)?path\(\)")),
    ("clears a child environment", re.compile(r"\.env_clear\(\s*\)")),
    ("sets or removes an isolation variable",
     re.compile(r'\.env(?:_remove)?\(\s*"' + ISOLATION + r'"')),
]
OPT_OUT = re.compile(r"//\s*spawn-check:\s*not the gateway:\s*\S")


def violations(root):
    root = pathlib.Path(root)
    found = []
    for base in ("tests",):
        for path in sorted((root / base).rglob("*.rs")):
            relative = path.relative_to(root).as_posix()
            if relative == HELPER:
                continue
            text = path.read_text(encoding="utf-8")
            lines = text.splitlines()
            for what, rule in RULES:
                for match in rule.finditer(text):
                    number = text.count("\n", 0, match.start()) + 1
                    if what.startswith("sets") and OPT_OUT.search(lines[number - 1]):
                        continue
                    found.append(f"{relative}:{number}: {what}")
    return sorted(found)


def self_test():
    planted = {
        "tests/raw.rs": 'let c = std::process::Command::new(env!("CARGO_BIN_EXE_mcp-gateway"));\n',
        "tests/clear.rs": "command.env_clear();\n",
        "tests/home.rs": 'command.env(\n    "HOME", dir);\n',
        "tests/bypass.rs": "let c = Command::new(gateway_bin::path());\n",
        "tests/no_reason.rs": 'node.env("HOME", dir); // spawn-check: not the gateway:\n',
    }
    clean = {
        HELPER: 'pub fn path() -> &\'static str { env!("CARGO_BIN_EXE_mcp-gateway") }\ncommand.env_clear();\n',
        "tests/ok.rs": "let c = gateway_bin::command(home, gateway_bin::Inherit::Nothing);\n",
        "tests/node.rs": 'node.env("HOME", dir); // spawn-check: not the gateway: the node verifier\n',
        "tests/config.rs": 'let line = format!("{} serve --stdio", gateway_bin::path());\n',
        "src/transport/stdio.rs": "command.env_clear();\n",
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

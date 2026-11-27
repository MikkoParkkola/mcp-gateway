// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The rows of the leaves the second half of the work converts. Each forces one local failure with
//! only its named input broken, or runs a leaf that has no local failure to force.

use super::{Case, Expect, Pin, config_at, config_case, missing_input, strings, text, write};

/// One entry per leaf.
#[allow(clippy::too_many_lines, reason = "one entry per leaf")]
pub(super) fn rows() -> Vec<(&'static str, Expect)> {
    vec![
        (
            "accounts init-store",
            Expect::TwoLines(|p| {
                config_at(
                    &p.join("missing.yaml"),
                    &["accounts", "init-store"],
                    "--config",
                )
            }),
        ),
        (
            "accounts migrate-credentials",
            Expect::TwoLines(|p| {
                let leaf = [
                    "accounts",
                    "migrate-credentials",
                    "--descriptor-id",
                    "d",
                    "--legacy-issuer",
                    "https://issuer.test",
                ];
                config_at(&p.join("missing.yaml"), &leaf, "--config")
            }),
        ),
        (
            "add",
            Expect::TwoLines(|p| config_case(p, &["add", "x", "--command", "echo"], "--config")),
        ),
        (
            "remove",
            Expect::TwoLines(|p| config_case(p, &["remove", "x"], "--config")),
        ),
        (
            "list",
            Expect::TwoLines(|p| config_case(p, &["list"], "--config")),
        ),
        (
            "get",
            Expect::TwoLines(|p| config_case(p, &["get", "x"], "--config")),
        ),
        (
            "audit verify",
            Expect::TwoLines(|p| {
                let log = text(&p.join("log.jsonl"));
                config_at(
                    &p.join("missing.yaml"),
                    &["audit", "verify", "--path", &log],
                    "--config",
                )
            }),
        ),
        (
            "audit show",
            Expect::TwoLines(|p| {
                missing_input(
                    p,
                    &["audit", "show", "--session", "s", "--path"],
                    "missing.jsonl",
                    &[],
                )
            }),
        ),
        (
            "cap validate",
            Expect::TwoLines(|p| missing_input(p, &["cap", "validate"], "missing.yaml", &[])),
        ),
        (
            "cap pin",
            Expect::TwoLines(|p| missing_input(p, &["cap", "pin"], "missing.yaml", &[])),
        ),
        (
            "cap list",
            // An empty config loads, so the folder is what fails.
            Expect::TwoLines(|p| {
                write(&p.join("empty.yaml"), "");
                missing_input(
                    p,
                    &["cap", "list"],
                    "missing-dir",
                    &["--config", "{p}/empty.yaml"],
                )
            }),
        ),
        (
            "cap import",
            Expect::TwoLines(|p| {
                missing_input(p, &["cap", "import"], "missing.json", &["-o", "{p}/out"])
            }),
        ),
        (
            "cap test",
            Expect::TwoLines(|p| missing_input(p, &["cap", "test"], "missing.yaml", &[])),
        ),
        (
            "cap discover",
            // No program on PATH keeps the host's processes out; one server comes from the environment, so the
            // config write is reached and fails on a config that does not load.
            Expect::TwoLines(|p| {
                let none = p.join("no-programs");
                std::fs::create_dir_all(&none).expect("dir");
                Case {
                    stdout: "🔍 Discovering MCP servers...\n\nDiscovered 1 MCP server(s):\n\n📦 probe\n   \
                             Description: MCP server from environment variable MCP_SERVER_PROBE_URL\n   \
                             Source: Environment\n   Transport: http\n   URL: http://127.0.0.1:9\n\n\n📝 \
                             Writing discovered servers to config...\n"
                        .to_owned(),
                    env: vec![
                        ("PATH", text(&none)),
                        ("XDG_CONFIG_HOME", text(&p.join("xdg"))),
                        ("MCP_SERVER_PROBE_URL", "http://127.0.0.1:9/mcp".to_owned()),
                    ],
                    ..config_case(p, &["cap", "discover", "--write-config"], "--config-path")
                }
            }),
        ),
        (
            "cap install",
            Expect::CannotFail(
                |_| strings(&["cap", "install", "x"]),
                "without --from-github it prints the install hint; with it the first step is a network fetch",
            ),
        ),
        (
            "cap search",
            Expect::CannotFail(
                |p| strings(&["cap", "search", "x", "-C", &text(p)]),
                "the index skips unreadable and invalid files instead of failing",
            ),
        ),
        (
            "cap registry-list",
            Expect::CannotFail(
                |p| strings(&["cap", "registry-list", "-C", &text(p)]),
                "the index skips unreadable and invalid files instead of failing",
            ),
        ),
        (
            "hash-key",
            // No key on stdin: a wrong invocation, exit 2 (it is 2 today).
            Expect::TwoLines(|_| Case {
                args: strings(&["hash-key"]),
                exit: 2,
                stdout: String::new(),
                first: Pin::Exact("error: the key is empty".to_owned()),
                second: Pin::Exact("Run 'mcp-gateway hash-key --help' for usage.".to_owned()),
                env: Vec::new(),
            }),
        ),
        (
            "kubernetes plan",
            Expect::TwoLines(|p| missing_input(p, &["kubernetes", "plan"], "missing.yaml", &[])),
        ),
        (
            "kubernetes controller",
            Expect::TwoLines(|p| {
                missing_input(p, &["kubernetes", "controller"], "missing.yaml", &[])
            }),
        ),
        (
            "kubernetes apply-plan",
            // Never with --execute: that runs the cluster programs.
            Expect::TwoLines(|p| {
                missing_input(p, &["kubernetes", "apply-plan"], "missing.yaml", &[])
            }),
        ),
        (
            "skills generate",
            Expect::TwoLines(|p| {
                missing_input(p, &["skills", "generate", "-C"], "missing-dir", &[])
            }),
        ),
        (
            "skills import",
            Expect::TwoLines(|p| {
                missing_input(
                    p,
                    &["skills", "import"],
                    "missing.md",
                    &["--registry", "{p}/reg.json"],
                )
            }),
        ),
        // A missing registry reads as empty, so the skills rows give one that is not JSON.
        (
            "skills list",
            Expect::TwoLines(|p| {
                write(&p.join("reg.json"), "{");
                missing_input(p, &["skills", "list", "--registry"], "reg.json", &[])
            }),
        ),
        (
            "skills search",
            Expect::TwoLines(|p| {
                write(&p.join("reg.json"), "{");
                missing_input(p, &["skills", "search", "q", "--registry"], "reg.json", &[])
            }),
        ),
        (
            "skills show",
            Expect::TwoLines(|p| {
                write(&p.join("reg.json"), "{");
                missing_input(p, &["skills", "show", "x", "--registry"], "reg.json", &[])
            }),
        ),
        (
            "skills remove",
            Expect::TwoLines(|p| {
                write(&p.join("reg.json"), "{");
                missing_input(p, &["skills", "remove", "x", "--registry"], "reg.json", &[])
            }),
        ),
        (
            "tool list",
            Expect::TwoLines(|p| config_at(&p.join("missing.yaml"), &["tool", "list"], "--config")),
        ),
        (
            "tool completions",
            Expect::TwoLines(|p| {
                config_at(
                    &p.join("missing.yaml"),
                    &["tool", "completions", "bash"],
                    "--config",
                )
            }),
        ),
        (
            "tool inspect",
            Expect::TwoLines(|p| {
                missing_input(p, &["tool", "inspect", "t", "-C"], "missing-dir", &[])
            }),
        ),
        (
            "tool invoke",
            Expect::TwoLines(|p| {
                missing_input(p, &["tool", "invoke", "t", "-C"], "missing-dir", &[])
            }),
        ),
        (
            "trust generate",
            Expect::TwoLines(|p| {
                missing_input(p, &["trust", "generate", "-C"], "missing-dir", &[])
            }),
        ),
        (
            "trust inspect",
            Expect::TwoLines(|p| {
                missing_input(p, &["trust", "inspect", "x", "-C"], "missing-dir", &[])
            }),
        ),
        (
            "trust validate",
            Expect::TwoLines(|p| {
                missing_input(p, &["trust", "validate", "--file"], "missing.json", &[])
            }),
        ),
        (
            "trust lab evaluate",
            Expect::TwoLines(|p| {
                missing_input(p, &["trust", "lab", "evaluate", "-C"], "missing-dir", &[])
            }),
        ),
        (
            "validate",
            // No capability file in the paths named: a wrong invocation, exit 2 (it is 2 today).
            Expect::TwoLines(|p| Case {
                args: strings(&["validate", &text(p)]),
                exit: 2,
                stdout: String::new(),
                first: Pin::Exact(
                    "error: No YAML capability files found in the given paths.".to_owned(),
                ),
                second: Pin::Exact("Run 'mcp-gateway validate --help' for usage.".to_owned()),
                env: Vec::new(),
            }),
        ),
        (
            "provenance public-key",
            Expect::TwoLines(|p| {
                config_at(
                    &p.join("missing.yaml"),
                    &["provenance", "public-key"],
                    "--config",
                )
            }),
        ),
        (
            "provenance verify",
            Expect::CannotFail(
                |p| {
                    let file = |name| super::provenance_fixture::fixture(p, name);
                    let (trust, receipt, result) = (
                        file("jwk.json"),
                        file("provenance.json"),
                        file("result.json"),
                    );
                    strings(&[
                        "provenance",
                        "verify",
                        "--trust",
                        &trust,
                        &receipt,
                        "--result",
                        &result,
                    ])
                },
                "every unreadable or malformed input is the verdict INVALID on stdout, exit 1",
            ),
        ),
    ]
}

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use std::{fs, path::PathBuf};

fn read_repo_file(path: &str) -> String {
    let path_buf = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path);
    fs::read_to_string(path_buf).unwrap_or_else(|err| panic!("failed to read {path}: {err}"))
}

/// Mirrors the MCP Registry's cargo ownership check (registry
/// `internal/validators/registries/mcpname.go`) against the README as crates.io
/// renders it: crates.io drops HTML comments, an unclosed comment runs to the end,
/// and the name must not continue with a server-name character.
fn readme_declares_registry_name(readme: &str, server_name: &str) -> bool {
    let mut visible = String::with_capacity(readme.len());
    let mut rest = readme;
    while let Some(start) = rest.find("<!--") {
        visible.push_str(&rest[..start]);
        rest = rest[start + 4..]
            .find("-->")
            .map_or("", |end| &rest[start + 4 + end + 3..]);
    }
    visible.push_str(rest);

    let token = format!("mcp-name: {server_name}");
    visible.match_indices(&token).any(|(at, _)| {
        visible[at + token.len()..]
            .bytes()
            .next()
            .is_none_or(|next| !(next.is_ascii_alphanumeric() || b"._/-".contains(&next)))
    })
}

#[test]
fn readme_carries_the_registry_ownership_line_for_the_cargo_package() {
    let server_json: serde_json::Value = serde_json::from_str(&read_repo_file("server.json"))
        .expect("server.json should be valid JSON");
    let lists_cargo = server_json["packages"]
        .as_array()
        .is_some_and(|packages| packages.iter().any(|p| p["registryType"] == "cargo"));
    if !lists_cargo {
        return;
    }
    let name = server_json["name"]
        .as_str()
        .expect("server.json should declare a name");
    assert!(
        readme_declares_registry_name(&read_repo_file("README.md"), name),
        "README.md needs a visible `mcp-name: {name}` line outside any HTML comment: the MCP \
         Registry refuses the cargo package without it, and a published crate README cannot \
         change"
    );
}

#[test]
fn registry_name_matcher_follows_the_registry_rules() {
    let name = "io.github.MikkoParkkola/mcp-gateway";
    let accepted = [
        "Registry name: `mcp-name: io.github.MikkoParkkola/mcp-gateway`",
        "mcp-name: io.github.MikkoParkkola/mcp-gateway",
        "`mcp-name: io.github.MikkoParkkola/mcp-gateway-x` then \
         `mcp-name: io.github.MikkoParkkola/mcp-gateway`",
    ];
    let refused = [
        "",
        "<!-- mcp-name: io.github.MikkoParkkola/mcp-gateway -->",
        "<!--\nmcp-name: io.github.MikkoParkkola/mcp-gateway\n-->",
        "<!-- unclosed\nmcp-name: io.github.MikkoParkkola/mcp-gateway",
        "`mcp-name: io.github.MikkoParkkola/mcp-gateway-x`",
        "`mcp-name: io.github.Someone/mcp-gateway`",
    ];
    for readme in accepted {
        assert!(
            readme_declares_registry_name(readme, name),
            "should accept: {readme:?}"
        );
    }
    for readme in refused {
        assert!(
            !readme_declares_registry_name(readme, name),
            "should refuse: {readme:?}"
        );
    }
}

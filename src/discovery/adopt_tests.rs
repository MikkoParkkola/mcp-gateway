// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The shared adopt rule: what a client config entry may hold and still
//! become a backend the gateway runs exactly as the client does.

use std::collections::HashSet;
use std::path::Path;

use serde_json::{Value, json};

use super::*;
use crate::discovery::DiscoverySource;
use crate::discovery::shadow::{ShadowRemediationAction, ShadowScanReport};

fn find(entry: &Value) -> DiscoveredServer {
    crate::discovery::client_entry::parse(
        "srv",
        entry,
        &DiscoverySource::ClaudeDesktop,
        Path::new("/client/config.json"),
    )
    .expect("the entry parses")
}

fn refused(entry: &Value) -> Vec<(AdoptRefusal, String)> {
    refusals(&find(entry))
}

fn one(reason: AdoptRefusal, field: &str) -> Vec<(AdoptRefusal, String)> {
    vec![(reason, field.to_string())]
}

#[test]
fn a_plain_stdio_entry_with_a_literal_secret_is_adoptable() {
    let entry = json!({"command": "npx", "args": ["-y", "srv"], "env": {"API_KEY": "sk-test"}});
    assert_eq!(refused(&entry), vec![]);
}

#[test]
fn a_client_input_variable_refuses_naming_the_env_field() {
    let entry =
        json!({"command": "npx", "args": ["-y", "srv"], "env": {"TOKEN": "${input:token}"}});
    assert_eq!(
        refused(&entry),
        one(AdoptRefusal::NeedsClientOnlySecret, "env.TOKEN")
    );
}

#[test]
fn a_client_input_header_refuses_naming_the_header() {
    let entry = json!({
        "url": "https://mcp.example.test/mcp",
        "headers": {"Authorization": "Bearer ${input:token}"},
    });
    assert_eq!(
        refused(&entry),
        one(AdoptRefusal::NeedsClientOnlySecret, "headers.Authorization")
    );
}

#[test]
fn a_non_string_env_value_refuses_rather_than_dropping() {
    let entry = json!({"command": "srv", "env": {"PORT": 3000}});
    assert_eq!(
        refused(&entry),
        one(AdoptRefusal::NeedsClientOnlySecret, "env.PORT")
    );
}

#[test]
fn a_variable_in_a_command_argument_or_cwd_refuses() {
    // The gateway expands `${...}` only in env and headers.
    let entry = json!({
        "command": "srv",
        "args": ["--root", "${HOME}/data", 7],
        "cwd": "${workspaceFolder}",
    });
    assert_eq!(
        refused(&entry),
        vec![
            (AdoptRefusal::NeedsClientOnlySecret, "args[1]".to_string()),
            (AdoptRefusal::NeedsClientOnlySecret, "args[2]".to_string()),
            (AdoptRefusal::NeedsClientOnlySecret, "cwd".to_string()),
        ]
    );
}

#[test]
fn a_variable_in_the_command_refuses() {
    assert_eq!(
        refused(&json!({"command": "${HOME}/bin/srv"})),
        one(AdoptRefusal::NeedsClientOnlySecret, "command")
    );
}

/// A find built by any producer gets its stdio command and working
/// directory checked by the rule itself.
#[test]
fn a_stdio_find_is_checked_whatever_scanned_it() {
    for (command, cwd, field) in [
        ("${HOME}/srv", None, "command"),
        ("srv", Some("tools"), "cwd"),
        ("srv", Some("${workspaceFolder}"), "cwd"),
    ] {
        let server = DiscoveredServer::new(
            "srv".to_string(),
            String::new(),
            DiscoverySource::Environment,
            TransportConfig::Stdio {
                command: command.to_string(),
                cwd: cwd.map(str::to_string),
                protocol_version: None,
            },
            crate::discovery::ServerMetadata::default(),
        );
        assert_eq!(
            refusals(&server),
            one(AdoptRefusal::NeedsClientOnlySecret, field),
            "{command} {cwd:?}"
        );
    }
}

#[test]
fn a_variable_in_a_url_refuses() {
    let entry = json!({"url": "https://${HOST}/mcp"});
    assert_eq!(
        refused(&entry),
        one(AdoptRefusal::NeedsClientOnlySecret, "url")
    );
}

#[test]
fn a_template_default_refuses_as_a_literal() {
    let entry = json!({"command": "srv", "env": {"API_KEY": "${API_KEY:-sk-secret}"}});
    assert_eq!(
        refused(&entry),
        one(AdoptRefusal::LiteralDefault, "env.API_KEY")
    );
    let empty_default = json!({"command": "srv", "env": {"API_KEY": "${API_KEY:-}"}});
    assert_eq!(refused(&empty_default), vec![]);
}

#[test]
fn a_mixed_template_is_carried_as_written() {
    let entry = json!({
        "url": "https://mcp.example.test/mcp",
        "headers": {"Authorization": "Bearer ${API_KEY}"},
    });
    let server = find(&entry);
    assert_eq!(refusals(&server), vec![]);
    assert_eq!(
        server
            .headers
            .expose()
            .get("Authorization")
            .map(String::as_str),
        Some("Bearer ${API_KEY}")
    );
}

#[test]
fn literal_text_beside_a_template_refuses() {
    for (map, key, value) in [
        ("headers", "Authorization", "Bearer sk-x${S:-}"),
        ("env", "API_KEY", "sk-${A}"),
    ] {
        let mut entry = if map == "env" {
            json!({"command": "srv"})
        } else {
            json!({"url": "https://mcp.example.test/mcp"})
        };
        entry[map][key] = json!(value);
        assert_eq!(
            refused(&entry),
            one(AdoptRefusal::LiteralInTemplate, &format!("{map}.{key}")),
            "{value}"
        );
    }
}

/// A harmless value refuses too, and the radar says what to change.
#[test]
fn a_harmless_mixed_value_refuses_with_the_remedy() {
    let server = find(&json!({"command": "srv", "env": {"PATH": "${HOME}/bin"}}));
    assert_eq!(
        refusals(&server),
        one(AdoptRefusal::LiteralInTemplate, "env.PATH")
    );
    let report = keyed_report(&[server], &HashSet::new(), Some(Path::new("gateway.yaml")));
    let risk = report.assets[0]
        .risks
        .iter()
        .find(|risk| risk.code == "literal_in_template")
        .expect("the radar names the reason");
    assert!(
        risk.detail
            .contains("Move the whole value into a variable or secret, then rescan"),
        "{}",
        risk.detail
    );
}

#[test]
fn a_client_env_variable_is_the_gateway_template() {
    let server = find(&json!({"command": "srv", "env": {"TOKEN": "${env:API_TOKEN}"}}));
    assert_eq!(refusals(&server), vec![]);
    assert_eq!(
        server.env.expose().get("TOKEN").map(String::as_str),
        Some("${API_TOKEN}")
    );
}

#[test]
fn a_template_read_as_a_reference_refuses() {
    // A load reads `file:...` as a file reference before expanding it.
    let entry = json!({"command": "srv", "env": {"TOKEN": "file:${HOME}/token"}});
    assert_eq!(
        refused(&entry),
        one(AdoptRefusal::NeedsClientOnlySecret, "env.TOKEN")
    );
}

#[test]
fn a_reference_shaped_literal_is_adoptable_as_bytes() {
    // No `${`: it is the client's literal, stored as a secret, never read
    // as a gateway reference.
    let entry = json!({
        "url": "https://mcp.example.test/mcp",
        "headers": {"X-Token": "file:/private/token"},
    });
    assert_eq!(refused(&entry), vec![]);
}

#[test]
fn a_client_setting_the_gateway_does_not_carry_refuses() {
    // A sandbox, an env file and client-held OAuth all change what the
    // server runs with; left behind, the adopted server would differ.
    let entry = json!({
        "type": "stdio",
        "command": "srv",
        "sandboxEnabled": true,
        "envFile": "${workspaceFolder}/.env",
    });
    assert_eq!(
        refused(&entry),
        vec![
            (AdoptRefusal::NeedsClientOnlySecret, "envFile".to_string()),
            (
                AdoptRefusal::NeedsClientOnlySecret,
                "sandboxEnabled".to_string()
            ),
        ]
    );
    let entry = json!({"url": "https://mcp.example.test/mcp", "oauth": {"clientId": "c"}});
    assert_eq!(
        refused(&entry),
        one(AdoptRefusal::NeedsClientOnlySecret, "oauth")
    );
}

#[test]
fn a_field_of_the_wrong_shape_refuses_rather_than_vanishing() {
    assert_eq!(
        refused(&json!({"command": "srv", "cwd": 7})),
        one(AdoptRefusal::NeedsClientOnlySecret, "cwd")
    );
    assert_eq!(
        refused(&json!({"command": "srv", "env": "K=v"})),
        one(AdoptRefusal::NeedsClientOnlySecret, "env")
    );
    assert_eq!(
        refused(&json!({"command": "srv", "headers": {"K": "v"}})),
        one(AdoptRefusal::NeedsClientOnlySecret, "headers")
    );
}

#[test]
fn a_switched_off_entry_refuses() {
    // Adopted, it would run: the client keeps it off.
    for (key, value) in [
        ("disabled", json!(true)),
        ("enabled", json!(false)),
        ("disabled", json!("no")),
    ] {
        let mut entry = json!({"command": "srv"});
        entry[key] = value;
        assert_eq!(
            refused(&entry),
            one(AdoptRefusal::NeedsClientOnlySecret, key),
            "{entry}"
        );
    }
}

#[test]
fn a_client_timeout_refuses() {
    // The gateway's own default would replace it.
    assert_eq!(
        refused(&json!({"command": "srv", "timeout": 600})),
        one(AdoptRefusal::NeedsClientOnlySecret, "timeout")
    );
}

#[test]
fn a_relative_working_directory_refuses() {
    assert_eq!(
        refused(&json!({"command": "srv", "cwd": "tools/srv"})),
        one(AdoptRefusal::NeedsClientOnlySecret, "cwd")
    );
}

#[test]
fn a_variable_in_a_name_refuses() {
    assert_eq!(
        refused(&json!({"command": "srv", "env": {"${PREFIX}_KEY": "v"}})),
        one(AdoptRefusal::NeedsClientOnlySecret, "env.${PREFIX}_KEY")
    );
}

#[test]
fn a_null_optional_field_is_left_out() {
    assert_eq!(
        refused(&json!({"command": "srv", "args": null, "env": null, "cwd": null})),
        vec![]
    );
}

/// An environment find skips the client config scanner; the rule checks
/// its URL itself.
#[test]
fn an_unusable_url_refuses_whatever_scanned_it() {
    for url in ["unix:///tmp/mcp.sock", "https://${HOST}/mcp", "not a url"] {
        let server = DiscoveredServer::new(
            "env-srv".to_string(),
            String::new(),
            DiscoverySource::Environment,
            TransportConfig::Http {
                http_url: url.to_string(),
                streamable_http: None,
                protocol_version: None,
            },
            crate::discovery::ServerMetadata::default(),
        );
        assert_eq!(
            refusals(&server),
            one(AdoptRefusal::NeedsClientOnlySecret, "url"),
            "{url}"
        );
    }
}

#[test]
fn a_socket_endpoint_refuses() {
    for url in ["unix:///tmp/mcp.sock", "pipe:///mcp"] {
        assert_eq!(
            refused(&json!({"url": url})),
            one(AdoptRefusal::NeedsClientOnlySecret, "url"),
            "{url}"
        );
    }
}

#[test]
fn descriptive_client_keys_do_not_refuse() {
    let entry = json!({
        "type": "stdio",
        "command": "srv",
        "description": "d",
        "disabled": false,
        "enabled": true,
        "autoApprove": ["read"],
    });
    assert_eq!(refused(&entry), vec![]);
}

#[test]
fn a_credential_in_a_url_refuses_naming_url() {
    for url in [
        "https://user:pass@mcp.example.test/mcp",
        "https://user@mcp.example.test/mcp",
        "https://mcp.example.test/mcp?api_key=k",
        "https://mcp.example.test/mcp?access_token=t",
        "https://mcp.example.test/mcp?X-Amz-Signature=s",
        "wss://mcp.example.test/ws?Session=s",
        "https://mcp.example.test/mcp?jwt=j",
        "https://mcp.example.test/mcp#token=t",
    ] {
        assert_eq!(
            refused(&json!({"url": url})),
            one(AdoptRefusal::CredentialInUrl, "url"),
            "{url}"
        );
    }
}

#[test]
fn cleartext_credentials_off_this_machine_refuse() {
    // The gateway refuses this backend once enabled, so adopting it would
    // write one that cannot run.
    let off_host =
        json!({"url": "http://mcp.lan.test/mcp", "headers": {"Authorization": "Bearer t"}});
    assert_eq!(
        refused(&off_host),
        one(AdoptRefusal::CleartextCredential, "url")
    );
    let loopback =
        json!({"url": "http://127.0.0.1:9000/mcp", "headers": {"Authorization": "Bearer t"}});
    assert_eq!(refused(&loopback), vec![]);
    let no_credential = json!({"url": "http://mcp.lan.test/mcp"});
    assert_eq!(refused(&no_credential), vec![]);
}

/// Any query refuses, named or not, ordinary or not: no name list can tell
/// a secret from a page number, and the value would reach gateway.yaml.
#[test]
fn any_query_refuses_without_echoing_it() {
    for url in [
        "https://mcp.example.test/mcp?passphrase=hunter2",
        "https://mcp.example.test/mcp?page=2",
        "https://mcp.example.test/mcp?",
        "http://127.0.0.1:9000/mcp?page=2",
    ] {
        let server = find(&json!({"url": url}));
        assert_eq!(
            refusals(&server),
            one(AdoptRefusal::CredentialInUrl, "url"),
            "{url}"
        );
        let report = keyed_report(&[server], &HashSet::new(), Some(Path::new("gateway.yaml")));
        let risk = report.assets[0]
            .risks
            .iter()
            .find(|risk| risk.code == "credential_in_url")
            .expect("the radar names the reason");
        assert!(
            !risk.detail.contains("hunter2") && !risk.detail.contains("page="),
            "{}",
            risk.detail
        );
    }
}

#[test]
fn a_url_without_a_query_is_adoptable() {
    assert_eq!(
        refused(&json!({"url": "https://mcp.example.test/mcp"})),
        vec![]
    );
}

/// The radar offers adoption exactly where the rule allows it.
#[test]
fn the_radar_offers_adoption_only_where_the_rule_allows() {
    let action = |entry: &Value| {
        let report = keyed_report(
            &[find(entry)],
            &HashSet::new(),
            Some(Path::new("gateway.yaml")),
        );
        report.assets[0].remediation.action.clone()
    };
    assert_eq!(
        action(&json!({"command": "npx", "args": ["-y", "srv"]})),
        ShadowRemediationAction::AdoptIntoGateway
    );
    for refused in [
        json!({"command": "srv", "args": ["${HOME}"]}),
        json!({"command": "srv", "env": {"K": "${K:-v}"}}),
        json!({"command": "srv", "env": {"K": "${input:k}"}}),
    ] {
        assert_eq!(
            action(&refused),
            ShadowRemediationAction::RequestOwner,
            "{refused}"
        );
    }
}

/// Discovery reads client config files and local processes only: no file
/// under `src/discovery` names a network socket, and no network-discovery
/// crate is a dependency (ADR-021).
#[test]
fn discovery_scans_no_network() {
    const SOCKETS: &[&str] = &["TcpStream", "TcpListener", "UdpSocket", "TcpSocket"];
    const CRATES: &[&str] = &["mdns", "zeroconf", "libmdns", "dns-sd", "pnet"];
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    let mut dirs = vec![root.join("src/discovery")];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(&dir).expect("read src/discovery") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                dirs.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                files.push(path);
            }
        }
    }
    assert!(files.len() > 10, "the walk found {} files", files.len());
    let this_file = Path::new(file!()).file_name().expect("file name");
    for path in files.iter().filter(|p| p.file_name() != Some(this_file)) {
        let source = std::fs::read_to_string(path).expect("read");
        for socket in SOCKETS {
            assert!(
                !source.contains(socket),
                "{} names {socket}",
                path.display()
            );
        }
    }
    let manifest = std::fs::read_to_string(root.join("Cargo.toml")).expect("read Cargo.toml");
    for line in manifest.lines().map(str::trim_start) {
        for name in CRATES {
            assert!(
                !line.starts_with(&format!("{name} ")) && !line.starts_with(&format!("{name}=")),
                "Cargo.toml depends on {name}"
            );
        }
    }
}

/// A report keyed by the test record key.
fn keyed_report(
    discovered: &[DiscoveredServer],
    registered: &HashSet<String>,
    gateway_config: Option<&Path>,
) -> ShadowScanReport {
    ShadowScanReport::from_discovered_keyed(
        discovered,
        registered,
        gateway_config,
        &crate::gateway::record_principal::test_record_key(),
    )
}

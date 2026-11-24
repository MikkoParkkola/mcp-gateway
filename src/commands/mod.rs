// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! CLI command handlers for `mcp-gateway`.
//!
//! Each public function corresponds to a top-level `Command` variant and
//! returns an `ExitCode` so `main` can remain a thin dispatcher.

use crate::cli::stdout::println;

mod accounts;
#[cfg(feature = "webui")]
mod add_remove;
#[cfg(feature = "webui")]
mod api;
// The router's rows drive the real CLI against a served router (test-only).
#[cfg(all(test, feature = "webui"))]
pub(crate) use api::run_api_for_tests;
mod api_key_rewrite;
mod audit;
#[cfg(feature = "webui")]
mod audit_lookup;
mod backend_url_keys;
mod cap;
mod capability_dirs;
/// The shared exit table and error shape: the remote commands' transport half (web UI only) and the three local
/// exits every command leaves through.
mod cli_exit;
pub(crate) use cli_exit::{CliExit, fail, usage, verdict};
pub(crate) mod color;
#[cfg(feature = "config-export")]
mod config_export;
pub mod config_write;
#[cfg(feature = "webui")]
mod dashboard_link;
#[cfg(feature = "discovery")]
pub(crate) mod discover;
mod doctor;
mod hash_key;
mod identity;
mod init_backends;
mod kubernetes;
// Only the config exporter consumes these client-path helpers.
#[cfg_attr(not(feature = "config-export"), allow(dead_code))]
pub mod paths;
mod protocol_import;
mod ranking;
mod regular_file;
mod retired_config_keys;
mod setup;
mod skills;
mod stats;
mod tool;
mod trust;
mod upgrade;

pub use accounts::run_accounts_command;
#[cfg(feature = "webui")]
pub use add_remove::{
    AddValues, run_add_command, run_get_command, run_list_available_command, run_list_command,
    run_remove_command,
};
#[cfg(feature = "webui")]
pub use api::run_api_command;
pub use audit::run_audit_command;
#[cfg(feature = "webui")]
pub use audit_lookup::run_audit_lookup_command;
pub use cap::run_cap_command;
#[cfg(feature = "config-export")]
pub use config_export::run_config_export;
#[cfg(feature = "webui")]
pub use dashboard_link::{run_dashboard_link_args, run_events_command};
pub use doctor::{StdioProbe, run_doctor_command, run_doctor_shadow_command};
pub use hash_key::run_hash_key_command;
pub use identity::run_identity_command;
pub use kubernetes::run_kubernetes_command;
pub use protocol_import::run_protocol_import_command;
pub use ranking::run_ranking_command;
pub use setup::run_setup_command;
pub use skills::{
    run_skills_generate, run_skills_import, run_skills_list, run_skills_remove, run_skills_search,
    run_skills_show,
};
pub use stats::{default_stats_url, run_stats_command};
pub use tool::run_tool_command;
pub use trust::run_trust_command;
pub use upgrade::{check_upgrade, data_dir as upgrade_data_dir, run_upgrade_with_config};

use std::process::ExitCode;

use mcp_gateway::{
    cli::{InitProfile, TlsCommand},
    mtls::{CaParams, CertGenerator, LeafCertParams},
};

/// The command that loads the gateway config at `path` and says why it will
/// not load: doctor's own `--config`, which `main` hands to doctor (a global
/// `--config` before the subcommand is not passed on). Every "this config does
/// not load" message points here; `validate` lints capability files and never
/// loads the gateway config (MIK-8375).
pub(crate) fn check_config_command(path: &std::path::Path) -> String {
    // One shell word, so a path with a space or a quote still copies whole.
    let text = path.to_string_lossy();
    let arg =
        shlex::try_quote(&text).map_or_else(|_| text.to_string(), std::borrow::Cow::into_owned);
    format!("mcp-gateway doctor --config {arg}")
}

/// Now for a CLI command, or the error it exits non-zero with: chrono's own
/// clock read panics on a clock before 1970 (MIK-8202 P4a).
pub(crate) fn clock_now() -> Result<chrono::DateTime<chrono::Utc>, String> {
    crate::clock::utc_now().map_err(|error| format!("the {error}"))
}

// ── init ─────────────────────────────────────────────────────────────────────

/// Generate a starter gateway configuration file.
///
const LOCAL_SAMPLE_CAPABILITIES: &[(&str, &str)] = &[
    (
        "capabilities/knowledge/weather_current.yaml",
        include_str!("../../capabilities/knowledge/weather_current.yaml"),
    ),
    (
        "capabilities/knowledge/public_holidays.yaml",
        include_str!("../../capabilities/knowledge/public_holidays.yaml"),
    ),
];

/// Generate a starter gateway configuration file.
///
/// Writes a commented YAML configuration to `output`. The local profile also
/// writes zero-key sample capability files next to the config so a clean install
/// can route a tool call without manual YAML authoring.
pub fn run_init_command(
    output: &std::path::Path,
    with_examples: bool,
    profile: InitProfile,
) -> ExitCode {
    if output.exists() {
        return fail(
            CliExit::LocalFailure,
            &format!("{} already exists.", output.display()),
            "Remove it first or choose a different path with --output.",
        );
    }
    let writable = || {
        format!(
            "Check that the folder of {} exists and that you can write to it.",
            output.display()
        )
    };

    let sample_files = init_sample_capability_files(output, with_examples, profile);
    if let Err(e) = preflight_init_targets(output, &sample_files) {
        return fail(CliExit::LocalFailure, &e.to_string(), &writable());
    }

    let (starter, skipped) = if with_examples && profile == InitProfile::Local {
        init_backends::starter_backends(doctor::which_command)
    } else {
        (String::new(), Vec::new())
    };
    for line in &skipped {
        eprintln!("{line}");
    }
    let config_content = build_init_config(with_examples, profile, &starter);

    match mcp_gateway::cli_support::write_init_files(output, &config_content, &sample_files) {
        Ok(reference) => {
            print_init_success(output, profile, !sample_files.is_empty(), &reference);
            ExitCode::SUCCESS
        }
        Err(e) => fail(CliExit::LocalFailure, &e, &writable()),
    }
}

fn build_init_config(with_examples: bool, profile: InitProfile, starter: &str) -> String {
    let write_local_samples = with_examples && profile == InitProfile::Local;
    let examples_section = if write_local_samples {
        concat!(
            "\n",
            "# Capabilities - direct REST API integration (no MCP server needed)\n",
            "# The local profile writes zero-key sample tools into ./capabilities/.\n",
            "capabilities:\n",
            "  directories:\n",
            "    - capabilities\n",
            "\n",
            "# Add MCP backends with `mcp-gateway add <name> -- <command>` or run:\n",
            "#   mcp-gateway setup wizard --configure-client\n",
        )
    } else {
        concat!(
            "\n",
            "# Capabilities - direct REST API integration\n",
            "capabilities:\n",
            "  directories:\n",
            "    - capabilities\n",
            "\n",
            "# Add your MCP backends here:\n",
            "# backends:\n",
            "#   my-server:\n",
            "#     command: \"npx -y @my/mcp-server\"\n",
            "#     description: \"My MCP server\"\n",
        )
    };

    format!(
        concat!(
            "# MCP Gateway Configuration\n",
            "# ========================\n",
            "# Generated by: mcp-gateway init\n",
            "# Profile: {profile}\n",
            "#\n",
            "# Documentation: https://github.com/MikkoParkkola/mcp-gateway#readme\n",
            "\n",
            "# Server settings\n",
            "server:\n",
            "  host: \"127.0.0.1\"\n",
            "  port: 39400\n",
            "\n",
            "# Admin credential, generated for this install.\n",
            "#\n",
            "# Tools stay open on the endpoints listed under public_paths, so the\n",
            "# MCP client you already configured keeps working with no change.\n",
            "# Managing the gateway and reading the dashboard need this token,\n",
            "# because an unauthenticated gateway cannot tell its operator from\n",
            "# anything else that reaches the port.\n",
            "#\n",
            "# On Unix this file is written readable only by you. Do not commit it.\n",
            "auth:\n",
            "  enabled: true\n",
            "  bearer_token: \"\"\n",
            "  single_user: true\n",
            "  public_paths:\n",
            "    - \"/health\"\n",
            "    - \"/mcp\"\n",
            "\n",
            "# Auth is on, so every tool call is recorded in a tamper-evident audit\n",
            "# log (required; see docs/UPGRADING-4.0.md). Default path:\n",
            "# ~/.mcp-gateway/transparency/transparency.jsonl\n",
            "security:\n",
            "  transparency_log:\n",
            "    enabled: true\n",
            "\n",
            "# Meta-MCP mode - exposes a compact gateway tool surface\n",
            "# Common deployment: 11 tools (9 minimum, 17 with every optional tool configured)\n",
            "# Keeps prompt overhead low by discovering backend tools on demand\n",
            "meta_mcp:\n",
            "  enabled: true\n",
            "{examples_section}",
            "{starter}",
        ),
        profile = profile,
        examples_section = examples_section,
        starter = if starter.is_empty() {
            String::new()
        } else {
            format!("\n{starter}")
        },
    )
}

fn init_sample_capability_files(
    output: &std::path::Path,
    with_examples: bool,
    profile: InitProfile,
) -> Vec<(std::path::PathBuf, &'static str)> {
    if !with_examples || profile != InitProfile::Local {
        return Vec::new();
    }

    let base = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));

    LOCAL_SAMPLE_CAPABILITIES
        .iter()
        .map(|(relative, content)| (base.join(relative), *content))
        .collect()
}

fn preflight_init_targets(
    output: &std::path::Path,
    sample_files: &[(std::path::PathBuf, &'static str)],
) -> std::io::Result<()> {
    if let Some(parent) = output.parent().filter(|p| !p.as_os_str().is_empty())
        && parent.exists()
        && !parent.is_dir()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!("{} exists and is not a directory", parent.display()),
        ));
    }

    for (path, _) in sample_files {
        if path.exists() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!(
                    "{} already exists; remove it or rerun with --with-examples=false",
                    path.display()
                ),
            ));
        }
    }

    Ok(())
}

fn print_init_success(
    output: &std::path::Path,
    profile: InitProfile,
    wrote_samples: bool,
    reference: &str,
) {
    println!("Created {}", output.display());
    println!("Profile: {profile}");
    if wrote_samples {
        println!("Created zero-key sample capabilities under ./capabilities/");
    }
    println!();
    // The credential is generated and written silently otherwise, and it is the
    // one thing in this file the operator has to know exists: management and the
    // dashboard need it, tool calls do not. Saying so here reaches the person
    // who never opens the docs.
    println!("An admin credential was generated in the secret store.");
    println!("Doctor shows its reference on the admin-token line. Tool calls do not need it;");
    println!("managing the gateway and opening the dashboard do. `serve` prints");
    println!("a single-use dashboard link on startup.");
    if reference.starts_with("keychain:") {
        println!("Stored in: the OS keychain");
    } else if let Some(dir) = reference
        .strip_prefix("file:")
        .and_then(|path| std::path::Path::new(path).parent())
    {
        println!("Stored in: owner-only files under {}", dir.display());
    }
    if let Ok(value) = std::env::var("MCP_GATEWAY_SECRETS__STORE")
        && !value.is_empty()
    {
        println!(
            "MCP_GATEWAY_SECRETS__STORE={value} applied to this run only; gateway.yaml keeps its own setting"
        );
    }
    println!();
    println!("Next steps:");
    println!("  1. Run diagnostics:");
    println!("     mcp-gateway doctor -c {}", output.display());
    println!("  2. Start the gateway:");
    println!("     mcp-gateway -c {}", output.display());
    println!("  3. Add to your MCP client:");
    println!("     mcp-gateway setup wizard --configure-client");
    println!("  4. Or add manually:");
    println!("     {{");
    println!("       \"mcpServers\": {{");
    println!("         \"gateway\": {{");
    println!("           \"url\": \"http://127.0.0.1:39400/mcp\"");
    println!("         }}");
    println!("       }}");
    println!("     }}");
}

// ── tls ──────────────────────────────────────────────────────────────────────

/// Run `mcp-gateway tls` subcommands.
#[allow(clippy::too_many_lines)]
pub fn run_tls_command(cmd: TlsCommand) -> ExitCode {
    match cmd {
        TlsCommand::InitCa {
            cn,
            validity_days,
            out,
        } => tls_init_ca(&cn, validity_days, &out),
        TlsCommand::IssueServer {
            ca_cert,
            ca_key,
            cn,
            san_dns,
            validity_days,
            out,
        } => tls_issue_server(&ca_cert, &ca_key, &cn, &san_dns, validity_days, &out),
        TlsCommand::IssueClient {
            ca_cert,
            ca_key,
            cn,
            ou,
            spiffe_uri,
            validity_days,
            out,
        } => tls_issue_client(
            &ca_cert,
            &ca_key,
            &cn,
            ou.as_deref(),
            spiffe_uri,
            validity_days,
            &out,
        ),
    }
}

/// Refuses a tls command whose output would replace something: `out` already
/// holds `<stem>.crt` or `<stem>.key`. Each path is looked at itself, never
/// through it, so any entry there (a file, a directory, a link even when it
/// dangles) refuses, and so does a lookup that fails for any reason other
/// than "not found". Called first, before any key is generated or read, so a
/// refusal writes nothing. The check runs once, when the command starts:
/// anything that creates these files while it runs, another tls command or
/// any other process, can still race; the rerun case is closed.
fn refuse_existing_tls_output(out: &std::path::Path, stem: &str) -> Result<(), ExitCode> {
    for extension in ["crt", "key"] {
        let path = out.join(format!("{stem}.{extension}"));
        match std::fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => {
                return Err(fail(
                    CliExit::LocalFailure,
                    &format!("{} already exists.", path.display()),
                    "Remove it first or choose a different --out.",
                ));
            }
            Err(e) => {
                return Err(fail(
                    CliExit::LocalFailure,
                    &format!(
                        "cannot tell whether {} exists ({e}); nothing was written.",
                        path.display()
                    ),
                    "Check the directory's access permissions, or choose a different --out.",
                ));
            }
        }
    }
    Ok(())
}

fn tls_init_ca(cn: &str, validity_days: u32, out: &std::path::Path) -> ExitCode {
    if let Err(code) = refuse_existing_tls_output(out, "ca") {
        return code;
    }
    println!("Generating Root CA: {cn}");
    let params = CaParams { cn, validity_days };
    match CertGenerator::init_ca(&params) {
        Ok(cert) => {
            if let Err(e) = CertGenerator::write_to_dir(&cert, out, "ca") {
                return fail(
                    CliExit::LocalFailure,
                    &format!("Failed to write CA files: {e}"),
                    &out_writable(out),
                );
            }
            println!("  CA cert: {}", out.join("ca.crt").display());
            println!("  CA key:  {}", out.join("ca.key").display());
            println!();
            println!("Keep the CA key offline or in a vault.");
            println!("Add to gateway.yaml:");
            println!("  mtls:");
            println!("    ca_cert: \"{}\"", out.join("ca.crt").display());
            ExitCode::SUCCESS
        }
        Err(e) => fail(
            CliExit::LocalFailure,
            &format!("CA generation failed: {e}"),
            "Check the --cn and --validity-days values, then rerun 'mcp-gateway tls init-ca'.",
        ),
    }
}

fn tls_issue_server(
    ca_cert: &std::path::Path,
    ca_key: &std::path::Path,
    cn: &str,
    san_dns: &str,
    validity_days: u32,
    out: &std::path::Path,
) -> ExitCode {
    if let Err(code) = refuse_existing_tls_output(out, "server") {
        return code;
    }
    println!("Issuing server certificate for: {cn}");
    let (ca_cert_pem, ca_key_pem) = match read_ca_files("tls issue-server", ca_cert, ca_key) {
        Ok(pair) => pair,
        Err(code) => return code,
    };
    let sans: Vec<String> = san_dns
        .split(',')
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();
    let params = LeafCertParams {
        cn,
        ou: None,
        san_dns: sans,
        san_uris: vec![],
        validity_days,
    };
    match CertGenerator::issue_leaf(&params, &ca_cert_pem, &ca_key_pem) {
        Ok(cert) => {
            if let Err(e) = CertGenerator::write_to_dir(&cert, out, "server") {
                return fail(
                    CliExit::LocalFailure,
                    &format!("Failed to write server cert files: {e}"),
                    &out_writable(out),
                );
            }
            println!("  Cert: {}", out.join("server.crt").display());
            println!("  Key:  {}", out.join("server.key").display());
            println!();
            println!("Add to gateway.yaml:");
            println!("  mtls:");
            println!("    enabled: true");
            println!("    server_cert: \"{}\"", out.join("server.crt").display());
            println!("    server_key:  \"{}\"", out.join("server.key").display());
            ExitCode::SUCCESS
        }
        Err(e) => fail(
            CliExit::LocalFailure,
            &format!("Server cert generation failed: {e}"),
            "Check the CA files and the --cn and --san-dns values, then rerun 'mcp-gateway tls issue-server'.",
        ),
    }
}

fn tls_issue_client(
    ca_cert: &std::path::Path,
    ca_key: &std::path::Path,
    cn: &str,
    ou: Option<&str>,
    spiffe_uri: Option<String>,
    validity_days: u32,
    out: &std::path::Path,
) -> ExitCode {
    // One stem for both the check and the write, so they cannot name
    // different files.
    let stem = cn.replace(['/', ' '], "-");
    if let Err(code) = refuse_existing_tls_output(out, &stem) {
        return code;
    }
    println!("Issuing client certificate for: {cn}");
    let (ca_cert_pem, ca_key_pem) = match read_ca_files("tls issue-client", ca_cert, ca_key) {
        Ok(pair) => pair,
        Err(code) => return code,
    };
    let san_uris = spiffe_uri.map(|u| vec![u]).unwrap_or_default();
    let params = LeafCertParams {
        cn,
        ou,
        san_dns: vec![],
        san_uris,
        validity_days,
    };
    match CertGenerator::issue_leaf(&params, &ca_cert_pem, &ca_key_pem) {
        Ok(cert) => {
            if let Err(e) = CertGenerator::write_to_dir(&cert, out, &stem) {
                return fail(
                    CliExit::LocalFailure,
                    &format!("Failed to write client cert files: {e}"),
                    &out_writable(out),
                );
            }
            println!("  Cert: {}", out.join(format!("{stem}.crt")).display());
            println!("  Key:  {}", out.join(format!("{stem}.key")).display());
            println!();
            println!("Configure the agent:");
            println!(
                "  export MCP_GATEWAY_CLIENT_CERT={}",
                out.join(format!("{stem}.crt")).display()
            );
            println!(
                "  export MCP_GATEWAY_CLIENT_KEY={}",
                out.join(format!("{stem}.key")).display()
            );
            ExitCode::SUCCESS
        }
        Err(e) => fail(
            CliExit::LocalFailure,
            &format!("Client cert generation failed: {e}"),
            "Check the CA files and the --cn and --spiffe-uri values, then rerun 'mcp-gateway tls issue-client'.",
        ),
    }
}

/// The remedy when a file under `out` could not be written.
fn out_writable(out: &std::path::Path) -> String {
    format!(
        "Check that {} exists and that you can write to it.",
        out.display()
    )
}

/// Read CA cert and key PEM files for `leaf` (`tls issue-server` or `tls issue-client`), returning early with the
/// error already printed.
fn read_ca_files(
    leaf: &str,
    ca_cert: &std::path::Path,
    ca_key: &std::path::Path,
) -> Result<(String, String), ExitCode> {
    let readable = |path: &std::path::Path| {
        format!(
            "Check that {} exists and that you can read it.",
            path.display()
        )
    };
    let cert = std::fs::read_to_string(ca_cert).map_err(|e| {
        fail(
            CliExit::LocalFailure,
            &format!("Cannot read CA cert '{}': {e}", ca_cert.display()),
            &readable(ca_cert),
        )
    })?;
    // Through the library's mode-checked key loader (F18 R6): the CA key signs
    // every client identity the gateway trusts, so one other users can read is
    // refused before anything is issued. The DER it returns is re-encoded as
    // the PEM `issue_leaf` takes; both accept PKCS#8 only, as before.
    let key_path = ca_key
        .to_str()
        .ok_or_else(|| usage(leaf, "CA key path is not valid UTF-8"))?;
    let key = mcp_gateway::mtls::cert_manager::load_private_key(key_path)
        .map_err(|e| e.to_string())
        .and_then(|der| {
            rcgen::KeyPair::try_from(&der)
                .map(|pair| pair.serialize_pem())
                .map_err(|e| format!("Cannot use CA key '{}': {e}", ca_key.display()))
        })
        .map_err(|e| fail(CliExit::LocalFailure, &e, &readable(ca_key)))?;
    Ok((cert, key))
}
#[cfg(tp2)]
#[cfg(all(test, feature = "webui"))]
#[path = "api_parity_tests.rs"]
mod api_parity_tests;
#[cfg(tp2)]
#[cfg(all(test, feature = "webui"))]
#[path = "api_tests.rs"]
mod api_tests;
#[cfg(tp2)]
#[cfg(all(test, feature = "webui"))]
mod dashboard_link_tls_tests;
#[cfg(tp2)]
#[cfg(all(test, feature = "webui"))]
#[path = "remote_exit_tests.rs"]
mod remote_exit_tests;
#[cfg(tp2)]
#[cfg(test)]
mod tls_ca_key_tests;
// Windows owner-only fixtures for the binary's `Inherit` callers.
#[cfg(all(test, windows))]
mod winacl_test_support;

#[cfg(tp2)]
#[cfg(test)]
mod admin_credential_tests {
    use super::{InitProfile, build_init_config};

    /// The starter capabilities are embedded at build time, so a CRLF checkout
    /// would ship CRLF bytes in that target's binary. `capabilities/.gitattributes` keeps
    /// them LF; this goes red on the Windows job if that rule is lost.
    #[test]
    fn the_embedded_starter_capabilities_are_lf_only() {
        for (path, body) in super::LOCAL_SAMPLE_CAPABILITIES {
            assert!(!body.contains('\r'), "{path} was embedded with a CR");
        }
    }

    #[test]
    // POSIX mode bits: asserts 0600 owner-only; Windows enforces owner-only through DACLs (win_acl).
    #[cfg(unix)]
    fn the_generated_config_is_not_readable_by_other_users() {
        // The starter config now carries a generated admin credential. Writing
        // it with `std::fs::write` left it at the umask, so the very file the
        // 0600 work was done for was the one that missed it.
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("gateway.yaml");
        let code = super::run_init_command(&path, false, InitProfile::Local);
        assert_eq!(code, std::process::ExitCode::SUCCESS, "init must succeed");

        let mode = std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "credential file wrote mode {mode:o}");
    }

    #[test]
    fn ordinary_tool_calls_still_work_without_the_credential() {
        // Enabling authentication gates EVERY path, not just admin ones. A
        // starter config that turns it on without exempting the MCP endpoint
        // breaks the client the operator already configured — a worse
        // regression than the missing dashboard it set out to fix.
        let config = build_init_config(true, InitProfile::Local, "");
        assert!(
            config.contains("/mcp"),
            "the MCP endpoint must stay reachable without a credential: {config}"
        );
        let parsed: crate::yaml::Value =
            crate::yaml::from_str(&config).expect("the starter config must parse");
        let paths = parsed["auth"]["public_paths"]
            .as_sequence()
            .expect("public_paths must be a list");
        let paths: Vec<&str> = paths.iter().filter_map(|v| v.as_str()).collect();
        assert!(
            paths.contains(&"/mcp"),
            "tools open, admin closed: {paths:?}"
        );
        assert!(paths.contains(&"/health"), "probes keep working: {paths:?}");
    }

    #[test]
    fn a_new_install_has_an_admin_credential() {
        // Removing admin from the anonymous identity left a fresh install with
        // no admin path at all: no dashboard, no management tools, and a YAML
        // edit as the only remedy. A generated credential restores it without
        // asking the operator to do anything.
        let config = build_init_config(true, InitProfile::Local, "");
        assert!(config.contains("enabled: true"), "auth must be on");
        assert!(
            config.contains("bearer_token: \"\""),
            "the template must leave credential generation to the writer: {config}"
        );
        assert!(
            config.contains("single_user: true"),
            "a laptop install is one principal; say so rather than making the \
             operator discover the flag"
        );
    }

    /// MIK-8064: `init` writes no `meta_mcp.cache_tools`, which nothing reads.
    #[test]
    fn init_writes_no_cache_tools() {
        let config = build_init_config(true, InitProfile::Local, "");
        assert!(!config.contains("cache_tools"), "{config}");
    }

    /// D1-T12. The starter config turns auth on, and D1-a refuses auth
    /// without the audit log, so the template must enable the log (D1-e) for
    /// a fresh install to load at all.
    #[test]
    fn init_config_loads_under_d1() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("gateway.yaml");
        let code = super::run_init_command(&path, false, InitProfile::Local);
        assert_eq!(code, std::process::ExitCode::SUCCESS, "init must succeed");

        let config = mcp_gateway::config::Config::load(Some(&path))
            .expect("a fresh init config must load and validate under D1-a");
        assert!(
            config
                .security
                .transparency_log
                .is_enabled(config.auth.enabled),
            "auth is on in the starter config, so the audit log must be too"
        );
    }
}

/// The serve paths' first load of the config, given the one path config resolution found. The
/// startup gate runs first: it takes the config lock (or proves none is needed), repairs what a
/// crashed write left and refuses what it cannot settle. The config is then loaded from the path
/// the gate checked, and the session rides in the result, still holding the lock, to the
/// construction that finishes it. With no path, the built-in defaults load and nothing is
/// searched for. Read-only commands load without the gate.
pub(crate) async fn load_for_serve(
    path: Option<&std::path::Path>,
) -> mcp_gateway::Result<mcp_gateway::config::Evaluated> {
    // Boxed: the gated load holds the startup session and the loaded config across its await,
    // which would otherwise sit inline in both serve paths' futures.
    Box::pin(gated_load(path)).await
}

async fn gated_load(
    path: Option<&std::path::Path>,
) -> mcp_gateway::Result<mcp_gateway::config::Evaluated> {
    let Some(path) = path else {
        return mcp_gateway::config::Config::load_evaluated_defaults();
    };
    let session = crate::config_reload::startup_settle::prepare_start(path)
        .await
        .map_err(|class| mcp_gateway::Error::Config(class.to_string()))?;
    #[cfg(all(test, unix))]
    crate::config_reload::serve_seams::reached(
        session.target(),
        crate::config_reload::serve_seams::Point::AfterPrepare,
    );
    let mut evaluated = mcp_gateway::config::Config::load_evaluated(Some(session.target()))?;
    evaluated.startup_session = crate::config::StartupSlot::holding(session);
    Ok(evaluated)
}

#[cfg(test)]
pub(crate) mod serve_fixture;
#[cfg(tp2)]
#[cfg(test)]
mod serve_load_tests;
#[cfg(tp2)]
#[cfg(test)]
mod serve_session_tests;

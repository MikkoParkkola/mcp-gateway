// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `Cli` argument parsing: the subcommand and flag grammar.

use super::*;

fn parse_args(args: &[&str]) -> Result<Cli, clap::Error> {
    use clap::Parser as _;
    let full: Vec<&str> = std::iter::once("mcp-gateway")
        .chain(args.iter().copied())
        .collect();
    Cli::try_parse_from(full)
}

/// The `plugin` command is retired in 4.0: its marketplace host never
/// resolved, and nothing read what `plugin install` wrote.
#[test]
fn cli_plugin_command_is_gone() {
    for args in [
        &["plugin", "search", "stripe"][..],
        &["plugin", "install", "stripe-payments"][..],
        &["plugin", "uninstall", "stripe-payments"][..],
        &["plugin", "list"][..],
    ] {
        assert!(parse_args(args).is_err(), "{args:?} still parses");
    }
}

#[test]
fn cli_identity_grants_list_parses_file_and_json_format() {
    let cli = parse_args(&[
        "identity",
        "grants",
        "list",
        "--file",
        "identity-grants.yaml",
        "--active-only",
        "--format",
        "json",
    ])
    .unwrap();
    match cli.command {
        Some(Command::Identity(mcp_gateway::cli::IdentityCommand::Grants(
            mcp_gateway::cli::IdentityGrantsCommand::List {
                file,
                active_only,
                format,
            },
        ))) => {
            assert_eq!(file, std::path::PathBuf::from("identity-grants.yaml"));
            assert!(active_only);
            assert_eq!(format, mcp_gateway::cli::output::OutputFormat::Json);
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn cli_identity_grants_grant_parses_required_local_admin_fields() {
    let cli = parse_args(&[
        "identity",
        "grants",
        "grant",
        "--file",
        "identity-grants.yaml",
        "--grant-id",
        "grant-alice-calendar",
        "--subject",
        "local:alice",
        "--agent",
        "agent-a",
        "--capability",
        "personal_calendar",
        "--tool",
        "read_day",
        "--scope",
        "read",
        "--ttl-seconds",
        "3600",
        "--reason",
        "read calendar",
    ])
    .unwrap();
    match cli.command {
        Some(Command::Identity(mcp_gateway::cli::IdentityCommand::Grants(
            mcp_gateway::cli::IdentityGrantsCommand::Grant {
                file,
                grant_id,
                subject,
                agent,
                capability,
                tool,
                scope,
                ttl_seconds,
                reason,
                ..
            },
        ))) => {
            assert_eq!(file, std::path::PathBuf::from("identity-grants.yaml"));
            assert_eq!(grant_id, "grant-alice-calendar");
            assert_eq!(subject, "local:alice");
            assert_eq!(agent.as_deref(), Some("agent-a"));
            assert_eq!(capability, "personal_calendar");
            assert_eq!(tool.as_deref(), Some("read_day"));
            assert_eq!(scope, mcp_gateway::cli::IdentityGrantScopeArg::Read);
            assert_eq!(ttl_seconds, Some(3600));
            assert_eq!(reason, "read calendar");
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn cli_trust_generate_parses_capabilities_and_json_format() {
    let cli = parse_args(&[
        "trust",
        "generate",
        "--capabilities",
        "fixtures/caps",
        "--format",
        "json",
    ])
    .unwrap();
    match cli.command {
        Some(Command::Trust(mcp_gateway::cli::TrustCommand::Generate {
            capabilities,
            format,
            output,
        })) => {
            assert_eq!(capabilities, std::path::PathBuf::from("fixtures/caps"));
            assert_eq!(format, mcp_gateway::cli::output::OutputFormat::Json);
            assert!(output.is_none());
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn cli_trust_validate_parses_file_and_strict_flag() {
    let cli = parse_args(&["trust", "validate", "--file", "trustcard.json", "--strict"]).unwrap();
    match cli.command {
        Some(Command::Trust(mcp_gateway::cli::TrustCommand::Validate { file, strict, .. })) => {
            assert_eq!(
                file.as_deref(),
                Some(std::path::Path::new("trustcard.json"))
            );
            assert!(strict);
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn cli_trust_lab_evaluate_parses_thresholds() {
    let cli = parse_args(&[
        "trust",
        "lab",
        "evaluate",
        "weather",
        "--capabilities",
        "fixtures/caps",
        "--enforce",
        "--baseline",
        "baseline.json",
        "--write-baseline",
        "next-baseline.json",
        "--baseline-registry",
        "fixtures/baselines",
        "--update-baseline-registry",
        "--active-fixtures",
        "fixtures/active-fixtures.json",
        "--runtime-provider-plan",
        "docker",
        "--runtime-image",
        "ghcr.io/example/weather-fixture:latest",
        "--baseline-id",
        "weather-baseline",
        "--minimum-score",
        "80",
        "--certification-score",
        "95",
        "--format",
        "json",
    ])
    .unwrap();
    match cli.command {
        Some(Command::Trust(mcp_gateway::cli::TrustCommand::Lab(
            mcp_gateway::cli::TrustLabCommand::Evaluate {
                name,
                capabilities,
                enforce,
                baseline,
                write_baseline,
                baseline_registry,
                update_baseline_registry,
                active_fixtures,
                execute_active_fixtures,
                runtime_provider_plan,
                runtime_image,
                baseline_id,
                minimum_score,
                certification_score,
                format,
            },
        ))) => {
            assert_eq!(name.as_deref(), Some("weather"));
            assert_eq!(capabilities, std::path::PathBuf::from("fixtures/caps"));
            assert!(enforce);
            assert_eq!(
                baseline.as_deref(),
                Some(std::path::Path::new("baseline.json"))
            );
            assert_eq!(
                write_baseline.as_deref(),
                Some(std::path::Path::new("next-baseline.json"))
            );
            assert_eq!(
                baseline_registry.as_deref(),
                Some(std::path::Path::new("fixtures/baselines"))
            );
            assert!(update_baseline_registry);
            assert_eq!(
                active_fixtures.as_deref(),
                Some(std::path::Path::new("fixtures/active-fixtures.json"))
            );
            assert!(!execute_active_fixtures);
            assert_eq!(
                runtime_provider_plan,
                Some(mcp_gateway::cli::RuntimeProviderArg::Docker)
            );
            assert_eq!(
                runtime_image.as_deref(),
                Some("ghcr.io/example/weather-fixture:latest")
            );
            assert_eq!(baseline_id, "weather-baseline");
            assert_eq!(minimum_score, 80);
            assert_eq!(certification_score, 95);
            assert_eq!(format, mcp_gateway::cli::output::OutputFormat::Json);
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn cli_trust_lab_evaluate_parses_execute_active_fixtures() {
    let cli = parse_args(&[
        "trust",
        "lab",
        "evaluate",
        "weather",
        "--active-fixtures",
        "fixtures/active-fixtures.json",
        "--execute-active-fixtures",
    ])
    .unwrap();
    match cli.command {
        Some(Command::Trust(mcp_gateway::cli::TrustCommand::Lab(
            mcp_gateway::cli::TrustLabCommand::Evaluate {
                active_fixtures,
                execute_active_fixtures,
                ..
            },
        ))) => {
            assert_eq!(
                active_fixtures.as_deref(),
                Some(std::path::Path::new("fixtures/active-fixtures.json"))
            );
            assert!(execute_active_fixtures);
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn cli_import_preview_parses_openapi_kind_and_json_format() {
    let cli = parse_args(&[
        "import",
        "preview",
        "--kind",
        "openapi",
        "fixtures/openapi.yaml",
        "--source-name",
        "users-api",
        "--format",
        "json",
        "--context-integrity-profile",
        "reviewed_import",
    ])
    .unwrap();
    match cli.command {
        Some(Command::Import(mcp_gateway::cli::ProtocolImportCommand::Preview {
            kind,
            file,
            source_name,
            format,
            context_integrity_profile,
        })) => {
            assert_eq!(kind, mcp_gateway::cli::ProtocolImportKind::OpenApi);
            assert_eq!(file, std::path::PathBuf::from("fixtures/openapi.yaml"));
            assert_eq!(source_name.as_deref(), Some("users-api"));
            assert_eq!(format, mcp_gateway::cli::output::OutputFormat::Json);
            assert_eq!(context_integrity_profile, "reviewed_import");
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn cli_import_preview_accepts_oci_alias() {
    let cli = parse_args(&["import", "preview", "--kind", "oci", "package.yaml"]).unwrap();
    match cli.command {
        Some(Command::Import(mcp_gateway::cli::ProtocolImportCommand::Preview {
            kind,
            file,
            format,
            ..
        })) => {
            assert_eq!(kind, mcp_gateway::cli::ProtocolImportKind::OciMcpPackage);
            assert_eq!(file, std::path::PathBuf::from("package.yaml"));
            assert_eq!(format, mcp_gateway::cli::output::OutputFormat::Table);
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn cli_kubernetes_plan_parses_resources_namespace_and_json_format() {
    let cli = parse_args(&[
        "kubernetes",
        "plan",
        "deploy/kubernetes/enterprise-alpha/base/example-gateway.yaml",
        "--namespace",
        "gateway-prod",
        "--format",
        "json",
    ])
    .unwrap();
    match cli.command {
        Some(Command::Kubernetes(mcp_gateway::cli::KubernetesCommand::Plan {
            resources,
            namespace,
            format,
        })) => {
            assert_eq!(
                resources,
                std::path::PathBuf::from(
                    "deploy/kubernetes/enterprise-alpha/base/example-gateway.yaml"
                )
            );
            assert_eq!(namespace, "gateway-prod");
            assert_eq!(format, mcp_gateway::cli::output::OutputFormat::Json);
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn cli_kubernetes_controller_parses_cycles_interval_and_plain_format() {
    let cli = parse_args(&[
        "kubernetes",
        "controller",
        "deploy/kubernetes/enterprise-alpha/base/example-gateway.yaml",
        "--namespace",
        "gateway-prod",
        "--interval-seconds",
        "5",
        "--cycles",
        "2",
        "--format",
        "plain",
    ])
    .unwrap();
    match cli.command {
        Some(Command::Kubernetes(mcp_gateway::cli::KubernetesCommand::Controller {
            resources,
            namespace,
            interval_seconds,
            cycles,
            watch,
            format,
        })) => {
            assert_eq!(
                resources,
                std::path::PathBuf::from(
                    "deploy/kubernetes/enterprise-alpha/base/example-gateway.yaml"
                )
            );
            assert_eq!(namespace, "gateway-prod");
            assert_eq!(interval_seconds, 5);
            assert_eq!(cycles, 2);
            assert!(!watch);
            assert_eq!(format, mcp_gateway::cli::output::OutputFormat::Plain);
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn cli_kubernetes_apply_plan_parses_approval_and_json_format() {
    let cli = parse_args(&[
        "kubernetes",
        "apply-plan",
        "deploy/kubernetes/enterprise-alpha/base/example-gateway.yaml",
        "--namespace",
        "gateway-prod",
        "--approve-apply",
        "--format",
        "json",
    ])
    .unwrap();
    match cli.command {
        Some(Command::Kubernetes(mcp_gateway::cli::KubernetesCommand::ApplyPlan {
            resources,
            namespace,
            approve_apply,
            execute,
            format,
        })) => {
            assert_eq!(
                resources,
                std::path::PathBuf::from(
                    "deploy/kubernetes/enterprise-alpha/base/example-gateway.yaml"
                )
            );
            assert_eq!(namespace, "gateway-prod");
            assert!(approve_apply);
            assert!(!execute);
            assert_eq!(format, mcp_gateway::cli::output::OutputFormat::Json);
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn cli_kubernetes_apply_plan_parses_execute_gate() {
    let cli = parse_args(&[
        "kubernetes",
        "apply-plan",
        "deploy/kubernetes/enterprise-alpha/base/example-gateway.yaml",
        "--execute",
        "--format",
        "plain",
    ])
    .unwrap();
    match cli.command {
        Some(Command::Kubernetes(mcp_gateway::cli::KubernetesCommand::ApplyPlan {
            execute,
            approve_apply,
            format,
            ..
        })) => {
            assert!(execute);
            assert!(!approve_apply);
            assert_eq!(format, mcp_gateway::cli::output::OutputFormat::Plain);
        }
        other => panic!("unexpected: {other:?}"),
    }
}

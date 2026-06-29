//! Kubernetes enterprise command handlers.

use std::{path::Path, process::ExitCode};

use mcp_gateway::{
    cli::{KubernetesCommand, output::OutputFormat},
    kubernetes::{KubernetesPlanStatus, KubernetesReconcilePlan, plan_reconciliation},
};

/// Run Kubernetes enterprise commands.
pub fn run_kubernetes_command(command: KubernetesCommand) -> ExitCode {
    match command {
        KubernetesCommand::Plan {
            resources,
            namespace,
            format,
        } => match read_plan(&resources, &namespace) {
            Ok(plan) => {
                print_plan(&plan, format);
                if plan.status == KubernetesPlanStatus::Blocked {
                    ExitCode::FAILURE
                } else {
                    ExitCode::SUCCESS
                }
            }
            Err(error) => {
                eprintln!("Error: {error}");
                ExitCode::FAILURE
            }
        },
    }
}

fn read_plan(resources: &Path, namespace: &str) -> Result<KubernetesReconcilePlan, String> {
    let content = std::fs::read_to_string(resources)
        .map_err(|error| format!("failed to read {}: {error}", resources.display()))?;
    plan_reconciliation(namespace, &resources.display().to_string(), &content)
        .map_err(|error| error.to_string())
}

fn print_plan(plan: &KubernetesReconcilePlan, format: OutputFormat) {
    match format {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(plan).unwrap_or_else(|_| "{}".to_string())
            );
        }
        OutputFormat::Plain => {
            println!("schema={}", plan.schema_version);
            println!("namespace={}", plan.namespace);
            println!("status={:?}", plan.status);
            println!("resources={}", plan.resource_count);
            println!("actions={}", plan.actions.len());
            println!(
                "server_side_dry_run={}",
                plan.server_side_dry_run.command.join(" ")
            );
        }
        OutputFormat::Table => {
            println!(
                "STATUS: {:?}  NAMESPACE: {}  RESOURCES: {}",
                plan.status, plan.namespace, plan.resource_count
            );
            println!("{:<24}  {:<18}  {:<26}  REASON", "ACTION", "KIND", "NAME");
            println!("{}", "-".repeat(96));
            for action in &plan.actions {
                println!(
                    "{:<24}  {:<18}  {:<26}  {}",
                    format!("{:?}", action.action),
                    action.resource_kind,
                    truncate(&action.resource_name, 26),
                    action.reason_code
                );
            }
        }
    }
}

fn truncate(value: &str, width: usize) -> String {
    if value.len() <= width {
        value.to_string()
    } else if width <= 1 {
        ".".to_string()
    } else {
        format!("{}.", &value[..width - 1])
    }
}

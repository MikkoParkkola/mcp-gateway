//! Kubernetes enterprise command handlers.

use std::{path::Path, process::ExitCode, thread, time::Duration};

use mcp_gateway::{
    cli::{KubernetesCommand, output::OutputFormat},
    kubernetes::{
        KubernetesClusterApplyOptions, KubernetesClusterApplyPlan, KubernetesClusterStepKind,
        KubernetesControllerMode, KubernetesControllerOptions, KubernetesControllerReport,
        KubernetesPlanStatus, KubernetesReconcilePlan, plan_cluster_apply, plan_controller_report,
        plan_reconciliation,
    },
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
        KubernetesCommand::Controller {
            resources,
            namespace,
            interval_seconds,
            cycles,
            watch,
            format,
        } => run_controller_command(
            &resources,
            &namespace,
            interval_seconds,
            cycles,
            watch,
            format,
        ),
        KubernetesCommand::ApplyPlan {
            resources,
            namespace,
            approve_apply,
            format,
        } => match read_cluster_apply_plan(&resources, &namespace, approve_apply) {
            Ok(plan) => {
                print_cluster_apply_plan(&plan, format);
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

fn read_cluster_apply_plan(
    resources: &Path,
    namespace: &str,
    approve_apply: bool,
) -> Result<KubernetesClusterApplyPlan, String> {
    let content = std::fs::read_to_string(resources)
        .map_err(|error| format!("failed to read {}: {error}", resources.display()))?;
    let source = resources.display().to_string();
    let options = if approve_apply {
        KubernetesClusterApplyOptions::approved(namespace, source)
    } else {
        KubernetesClusterApplyOptions::dry_run(namespace, source)
    };
    plan_cluster_apply(options, &content).map_err(|error| error.to_string())
}

fn read_controller_report(
    resources: &Path,
    namespace: &str,
    interval_seconds: u64,
    cycles: usize,
    mode: KubernetesControllerMode,
) -> Result<KubernetesControllerReport, String> {
    let content = std::fs::read_to_string(resources)
        .map_err(|error| format!("failed to read {}: {error}", resources.display()))?;
    let options = match mode {
        KubernetesControllerMode::Once => KubernetesControllerOptions::once(
            namespace,
            resources.display().to_string(),
            interval_seconds,
        ),
        KubernetesControllerMode::Bounded => KubernetesControllerOptions::bounded(
            namespace,
            resources.display().to_string(),
            interval_seconds,
            cycles,
        ),
        KubernetesControllerMode::Continuous => KubernetesControllerOptions::continuous(
            namespace,
            resources.display().to_string(),
            interval_seconds,
        ),
    };
    plan_controller_report(options, &content).map_err(|error| error.to_string())
}

fn run_controller_command(
    resources: &Path,
    namespace: &str,
    interval_seconds: u64,
    cycles: usize,
    watch: bool,
    format: OutputFormat,
) -> ExitCode {
    if watch {
        if interval_seconds == 0 {
            eprintln!("Error: --watch requires --interval-seconds greater than 0");
            return ExitCode::FAILURE;
        }

        loop {
            match read_controller_report(
                resources,
                namespace,
                interval_seconds,
                1,
                KubernetesControllerMode::Continuous,
            ) {
                Ok(report) => {
                    let blocked = report.status == KubernetesPlanStatus::Blocked;
                    print_controller_report(&report, format);
                    if blocked {
                        return ExitCode::FAILURE;
                    }
                }
                Err(error) => {
                    eprintln!("Error: {error}");
                    return ExitCode::FAILURE;
                }
            }
            thread::sleep(Duration::from_secs(interval_seconds));
        }
    }

    let mode = if cycles == 1 {
        KubernetesControllerMode::Once
    } else {
        KubernetesControllerMode::Bounded
    };
    match read_controller_report(resources, namespace, interval_seconds, cycles, mode) {
        Ok(report) => {
            let blocked = report.status == KubernetesPlanStatus::Blocked;
            print_controller_report(&report, format);
            if blocked {
                ExitCode::FAILURE
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(error) => {
            eprintln!("Error: {error}");
            ExitCode::FAILURE
        }
    }
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
            println!("evidence_exports={}", plan.evidence_exports.len());
            println!(
                "server_side_dry_run={}",
                plan.server_side_dry_run.command.join(" ")
            );
        }
        OutputFormat::Table => {
            println!(
                "STATUS: {:?}  NAMESPACE: {}  RESOURCES: {}  EVIDENCE_EXPORTS: {}",
                plan.status,
                plan.namespace,
                plan.resource_count,
                plan.evidence_exports.len()
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

fn print_controller_report(report: &KubernetesControllerReport, format: OutputFormat) {
    match format {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".to_string())
            );
        }
        OutputFormat::Plain => {
            println!("schema={}", report.schema_version);
            println!("namespace={}", report.namespace);
            println!("mode={:?}", report.mode);
            println!("status={:?}", report.status);
            println!("completed_cycles={}", report.completed_cycles);
            println!("resources={}", report.last_plan.resource_count);
            println!("actions={}", report.last_plan.actions.len());
            println!(
                "evidence_exports={}",
                report.last_plan.evidence_exports.len()
            );
            println!("shutdown_reason={:?}", report.shutdown_reason);
        }
        OutputFormat::Table => {
            println!(
                "CONTROLLER: {:?}  STATUS: {:?}  NAMESPACE: {}  CYCLES: {}/{}",
                report.mode,
                report.status,
                report.namespace,
                report.completed_cycles,
                report.requested_cycles
            );
            println!(
                "{:<8}  {:<8}  {:<10}  {:<10}  REASON_CODES",
                "CYCLE", "STATUS", "ACTIONS", "EVIDENCE"
            );
            println!("{}", "-".repeat(96));
            for cycle in &report.cycles {
                println!(
                    "{:<8}  {:<8}  {:<10}  {:<10}  {}",
                    cycle.cycle,
                    format!("{:?}", cycle.status),
                    cycle.action_count,
                    cycle.evidence_export_count,
                    truncate(&cycle.reason_codes.join(","), 42)
                );
            }
        }
    }
}

fn print_cluster_apply_plan(plan: &KubernetesClusterApplyPlan, format: OutputFormat) {
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
            println!("intent={:?}", plan.intent);
            println!("status={:?}", plan.status);
            println!("mutation_allowed={}", plan.mutation_allowed);
            println!("steps={}", plan.steps.len());
            println!(
                "enabled_mutating_steps={}",
                plan.steps
                    .iter()
                    .filter(|step| step.enabled && step.modifies_cluster)
                    .count()
            );
            println!("blocked_reasons={}", plan.blocked_reasons.len());
        }
        OutputFormat::Table => {
            println!(
                "APPLY_PLAN: {:?}  STATUS: {:?}  NAMESPACE: {}  MUTATION_ALLOWED: {}",
                plan.intent, plan.status, plan.namespace, plan.mutation_allowed
            );
            println!(
                "{:<18}  {:<7}  {:<6}  {:<8}  COMMAND",
                "STEP", "ENABLED", "MUTATE", "CONFIRM"
            );
            println!("{}", "-".repeat(110));
            for step in &plan.steps {
                println!(
                    "{:<18}  {:<7}  {:<6}  {:<8}  {}",
                    cluster_step_label(step.step),
                    step.enabled,
                    step.modifies_cluster,
                    step.requires_human_confirmation,
                    truncate(&step.command.join(" "), 58)
                );
            }
        }
    }
}

fn cluster_step_label(step: KubernetesClusterStepKind) -> &'static str {
    match step {
        KubernetesClusterStepKind::Preflight => "preflight",
        KubernetesClusterStepKind::ServerSideDryRun => "server_dry_run",
        KubernetesClusterStepKind::Apply => "apply",
        KubernetesClusterStepKind::Verify => "verify",
        KubernetesClusterStepKind::EvidenceExport => "evidence_export",
        KubernetesClusterStepKind::Rollback => "rollback",
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

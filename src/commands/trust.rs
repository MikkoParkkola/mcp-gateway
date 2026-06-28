//! `TrustCard` and CBOM command handlers.

use std::{
    path::{Path, PathBuf},
    process::ExitCode,
};

use mcp_gateway::{
    capability::CapabilityLoader,
    cli::{TrustCommand, TrustLabCommand, output::OutputFormat},
    trust::{
        TrustAssistantPrompt, TrustCard, TrustCardAssistant, TrustCardValidator,
        TrustEvaluationStatus, TrustFindingSeverity,
        lab::{
            CatalogTrustLab, TrustLabBaseline, TrustLabEvaluation, TrustLabPolicy,
            TrustLabPolicyVerdict, TrustLabProfile,
        },
    },
};
use serde::Serialize;

/// Run a `trust` subcommand.
pub async fn run_trust_command(cmd: TrustCommand) -> ExitCode {
    match cmd {
        TrustCommand::Generate {
            capabilities,
            format,
            output,
        } => match generate_cards_from_capabilities(&capabilities).await {
            Ok(cards) => {
                if let Some(output) = output {
                    if let Err(e) = write_cards_json(&cards, &output).await {
                        eprintln!("Error: {e}");
                        return ExitCode::FAILURE;
                    }
                    eprintln!("Wrote {}", output.display());
                }
                print_cards(&cards, format);
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("Error: {e}");
                ExitCode::FAILURE
            }
        },
        TrustCommand::Inspect {
            name,
            capabilities,
            format,
        } => match generate_cards_from_capabilities(&capabilities).await {
            Ok(cards) => {
                if let Some(card) = cards.iter().find(|card| card.server.name == name) {
                    print_card(card, format);
                    ExitCode::SUCCESS
                } else {
                    eprintln!(
                        "Error: no capability named '{name}' found under {}",
                        capabilities.display()
                    );
                    ExitCode::FAILURE
                }
            }
            Err(e) => {
                eprintln!("Error: {e}");
                ExitCode::FAILURE
            }
        },
        TrustCommand::Validate {
            file,
            capabilities,
            strict,
            format,
        } => {
            let cards = if let Some(file) = file {
                match read_card_file(&file).await {
                    Ok(card) => vec![card.with_validation()],
                    Err(e) => {
                        eprintln!("Error: {e}");
                        return ExitCode::FAILURE;
                    }
                }
            } else {
                match generate_cards_from_capabilities(&capabilities).await {
                    Ok(cards) => cards,
                    Err(e) => {
                        eprintln!("Error: {e}");
                        return ExitCode::FAILURE;
                    }
                }
            };

            print_validation_report(&cards, format);
            validation_exit_code(&cards, strict)
        }
        TrustCommand::Lab(command) => run_trust_lab_command(command).await,
    }
}

async fn run_trust_lab_command(command: TrustLabCommand) -> ExitCode {
    match command {
        TrustLabCommand::Evaluate {
            name,
            capabilities,
            enforce,
            baseline,
            write_baseline,
            baseline_id,
            minimum_score,
            certification_score,
            format,
        } => {
            let policy = TrustLabPolicy {
                profile: TrustLabProfile::LocalOneShot,
                minimum_score,
                certification_score,
                fail_on_blocking_findings: true,
                advisory_only: !enforce,
            };
            match run_lab_evaluation(
                &capabilities,
                name.as_deref(),
                policy,
                baseline.as_deref(),
                write_baseline.as_deref(),
                &baseline_id,
            )
            .await
            {
                Ok(report) => {
                    if let Some(path) = report.written_baseline.as_ref() {
                        eprintln!("Wrote TrustLab baseline {}", path.display());
                    }
                    print_lab_evaluations(&report.evaluations, format);
                    lab_exit_code(&report.evaluations, enforce)
                }
                Err(e) => {
                    eprintln!("Error: {e}");
                    ExitCode::FAILURE
                }
            }
        }
    }
}

async fn generate_cards_from_capabilities(capabilities: &Path) -> Result<Vec<TrustCard>, String> {
    let path = capabilities.to_str().ok_or_else(|| {
        format!(
            "capability path is not valid UTF-8: {}",
            capabilities.display()
        )
    })?;
    let mut cards: Vec<_> = CapabilityLoader::load_directory(path)
        .await
        .map_err(|e| {
            format!(
                "failed to load capabilities from {}: {e}",
                capabilities.display()
            )
        })?
        .iter()
        .map(|capability| TrustCard::from_capability(capability).with_validation())
        .collect();

    cards.sort_by(|left, right| left.server.name.cmp(&right.server.name));
    Ok(cards)
}

async fn read_card_file(path: &Path) -> Result<TrustCard, String> {
    let content = tokio::fs::read_to_string(path)
        .await
        .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    serde_json::from_str::<TrustCard>(&content)
        .or_else(|_| serde_yaml::from_str::<TrustCard>(&content))
        .map_err(|e| format!("failed to parse TrustCard {}: {e}", path.display()))
}

async fn write_cards_json(cards: &[TrustCard], output: &Path) -> Result<(), String> {
    let body = serde_json::to_string_pretty(cards)
        .map_err(|e| format!("failed to serialize TrustCards: {e}"))?;
    tokio::fs::write(output, format!("{body}\n"))
        .await
        .map_err(|e| format!("failed to write {}: {e}", output.display()))
}

fn print_cards(cards: &[TrustCard], format: OutputFormat) {
    match format {
        OutputFormat::Json => print_json(cards),
        OutputFormat::Plain => {
            for card in cards {
                println!("{}", card.server.name);
            }
        }
        OutputFormat::Table => print_card_table(cards),
    }
}

fn print_card(card: &TrustCard, format: OutputFormat) {
    match format {
        OutputFormat::Json => print_json(card),
        OutputFormat::Plain | OutputFormat::Table => {
            println!("Name: {}", card.server.name);
            println!("Status: {:?}", card.evaluation_status);
            println!("Risk: {:?}", card.server.risk_class);
            println!("Transport: {:?}", card.server.transport);
            println!("Auth: {:?}", card.server.auth_mode);
            println!("Components: {}", card.cbom.components.len());
            print_findings(&card.findings);
            print_decision_prompts(&TrustCardAssistant::plan(card).human_decisions);
        }
    }
}

fn print_validation_report(cards: &[TrustCard], format: OutputFormat) {
    match format {
        OutputFormat::Json => {
            let rows: Vec<_> = cards.iter().map(ValidationRow::from_card).collect();
            print_json(&rows);
        }
        OutputFormat::Plain => {
            for card in cards {
                let plan = TrustCardAssistant::plan(card);
                println!(
                    "{} {:?} decisions={}",
                    card.server.name,
                    card.evaluation_status,
                    plan.human_decisions.len()
                );
            }
        }
        OutputFormat::Table => {
            print_card_table(cards);
            for card in cards {
                if !card.findings.is_empty() {
                    println!();
                    println!("Findings for {}:", card.server.name);
                    print_findings(&card.findings);
                }
                let plan = TrustCardAssistant::plan(card);
                if !plan.human_decisions.is_empty() {
                    println!();
                    println!("Human decisions for {}:", card.server.name);
                    print_decision_prompts(&plan.human_decisions);
                }
            }
        }
    }
}

fn validation_exit_code(cards: &[TrustCard], strict: bool) -> ExitCode {
    let has_failure = cards
        .iter()
        .any(|card| card.evaluation_status == TrustEvaluationStatus::Failed);
    let has_warning = cards
        .iter()
        .any(|card| card.evaluation_status == TrustEvaluationStatus::Warning);

    if has_failure || (strict && has_warning) {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

#[cfg(test)]
async fn evaluate_lab_from_capabilities(
    capabilities: &Path,
    name: Option<&str>,
    policy: TrustLabPolicy,
    baseline: Option<&TrustLabBaseline>,
) -> Result<Vec<TrustLabEvaluation>, String> {
    let cards = select_cards(capabilities, name).await?;
    Ok(evaluate_lab_cards(&cards, policy, baseline))
}

struct LabEvaluationRun {
    evaluations: Vec<TrustLabEvaluation>,
    written_baseline: Option<PathBuf>,
}

async fn run_lab_evaluation(
    capabilities: &Path,
    name: Option<&str>,
    policy: TrustLabPolicy,
    baseline_path: Option<&Path>,
    write_baseline_path: Option<&Path>,
    baseline_id: &str,
) -> Result<LabEvaluationRun, String> {
    let cards = select_cards(capabilities, name).await?;
    let baseline = match baseline_path {
        Some(path) => Some(read_lab_baseline(path).await?),
        None => None,
    };
    let evaluations = evaluate_lab_cards(&cards, policy, baseline.as_ref());
    let written_baseline = match write_baseline_path {
        Some(path) => {
            let baseline = lab_baseline_from_cards(baseline_id, &cards);
            write_lab_baseline(&baseline, path).await?;
            Some(path.to_path_buf())
        }
        None => None,
    };

    Ok(LabEvaluationRun {
        evaluations,
        written_baseline,
    })
}

async fn select_cards(capabilities: &Path, name: Option<&str>) -> Result<Vec<TrustCard>, String> {
    let cards = generate_cards_from_capabilities(capabilities).await?;
    if let Some(name) = name {
        let card = cards
            .iter()
            .find(|card| card.server.name == name)
            .ok_or_else(|| {
                format!(
                    "no capability named '{name}' found under {}",
                    capabilities.display()
                )
            })?;
        Ok(vec![card.clone()])
    } else {
        Ok(cards)
    }
}

fn evaluate_lab_cards(
    cards: &[TrustCard],
    policy: TrustLabPolicy,
    baseline: Option<&TrustLabBaseline>,
) -> Vec<TrustLabEvaluation> {
    let lab = CatalogTrustLab::new(policy);
    cards
        .iter()
        .map(|card| lab.evaluate_card_with_baseline_at(card, baseline, chrono::Utc::now()))
        .collect()
}

async fn read_lab_baseline(path: &Path) -> Result<TrustLabBaseline, String> {
    let content = tokio::fs::read_to_string(path)
        .await
        .map_err(|e| format!("failed to read TrustLab baseline {}: {e}", path.display()))?;
    serde_json::from_str::<TrustLabBaseline>(&content)
        .or_else(|_| serde_yaml::from_str::<TrustLabBaseline>(&content))
        .map_err(|e| format!("failed to parse TrustLab baseline {}: {e}", path.display()))
}

async fn write_lab_baseline(baseline: &TrustLabBaseline, output: &Path) -> Result<(), String> {
    let body = serde_json::to_string_pretty(baseline)
        .map_err(|e| format!("failed to serialize TrustLab baseline: {e}"))?;
    tokio::fs::write(output, format!("{body}\n"))
        .await
        .map_err(|e| {
            format!(
                "failed to write TrustLab baseline {}: {e}",
                output.display()
            )
        })
}

fn lab_baseline_from_cards(baseline_id: &str, cards: &[TrustCard]) -> TrustLabBaseline {
    let mut baseline = TrustLabBaseline {
        baseline_id: baseline_id.to_string(),
        tool_schema_digests: std::collections::BTreeMap::default(),
    };
    for card in cards {
        let card_baseline = TrustLabBaseline::from_card(baseline_id, card);
        baseline
            .tool_schema_digests
            .extend(card_baseline.tool_schema_digests);
    }
    baseline
}

fn print_lab_evaluations(evaluations: &[TrustLabEvaluation], format: OutputFormat) {
    match format {
        OutputFormat::Json => print_json(evaluations),
        OutputFormat::Plain => {
            for evaluation in evaluations {
                println!(
                    "{} {} {:?}",
                    evaluation.input.server_name, evaluation.score, evaluation.policy_verdict
                );
            }
        }
        OutputFormat::Table => print_lab_table(evaluations),
    }
}

fn print_lab_table(evaluations: &[TrustLabEvaluation]) {
    if evaluations.is_empty() {
        println!("No TrustLab evaluations generated.");
        return;
    }

    println!(
        "{:<28}  {:<5}  {:<10}  {:<12}  FINDINGS",
        "NAME", "SCORE", "VERDICT", "CERT"
    );
    println!("{}", "-".repeat(76));
    for evaluation in evaluations {
        println!(
            "{:<28}  {:<5}  {:<10}  {:<12}  {}",
            truncate(&evaluation.input.server_name, 28),
            evaluation.score,
            format!("{:?}", evaluation.policy_verdict),
            format!("{:?}", evaluation.certification.status),
            evaluation.findings.len()
        );
    }
}

fn lab_exit_code(evaluations: &[TrustLabEvaluation], enforce: bool) -> ExitCode {
    if enforce
        && evaluations
            .iter()
            .any(|evaluation| evaluation.policy_verdict == TrustLabPolicyVerdict::Block)
    {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn print_card_table(cards: &[TrustCard]) {
    if cards.is_empty() {
        println!("No TrustCards generated.");
        return;
    }

    println!(
        "{:<28}  {:<12}  {:<8}  {:<10}  {:<8}  {:<8}  DECISIONS",
        "NAME", "STATUS", "RISK", "TRANSPORT", "AUTH", "FINDINGS"
    );
    println!("{}", "-".repeat(104));
    for card in cards {
        let plan = TrustCardAssistant::plan(card);
        println!(
            "{:<28}  {:<12}  {:<8}  {:<10}  {:<8}  {:<8}  {}",
            truncate(&card.server.name, 28),
            format!("{:?}", card.evaluation_status),
            format!("{:?}", card.server.risk_class),
            format!("{:?}", card.server.transport),
            format!("{:?}", card.server.auth_mode),
            card.findings.len(),
            plan.human_decisions.len()
        );
    }
}

fn print_findings(findings: &[mcp_gateway::trust::TrustFinding]) {
    if findings.is_empty() {
        println!("Findings: none");
        return;
    }

    println!("Findings:");
    for finding in findings {
        println!(
            "- {:?} {} {}: {}",
            finding.severity, finding.code, finding.field, finding.message
        );
    }
}

fn print_decision_prompts(prompts: &[TrustAssistantPrompt]) {
    if prompts.is_empty() {
        println!("Human decisions: none");
        return;
    }

    println!("Human decisions:");
    for prompt in prompts {
        println!(
            "- {:?} {}: {}",
            prompt.severity, prompt.prompt_id, prompt.question
        );
    }
}

fn print_json<T: Serialize + ?Sized>(value: &T) {
    match serde_json::to_string_pretty(value) {
        Ok(json) => println!("{json}"),
        Err(e) => eprintln!("Error: failed to serialize JSON: {e}"),
    }
}

fn truncate(value: &str, max_len: usize) -> String {
    if value.len() <= max_len {
        value.to_string()
    } else {
        format!("{}...", &value[..max_len.saturating_sub(3)])
    }
}

#[derive(Serialize)]
struct ValidationRow {
    name: String,
    status: TrustEvaluationStatus,
    risk_class: mcp_gateway::trust::TrustRiskClass,
    failure_count: usize,
    warning_count: usize,
    human_decision_count: usize,
    finding_codes: Vec<String>,
    human_decisions: Vec<TrustAssistantPrompt>,
}

impl ValidationRow {
    fn from_card(card: &TrustCard) -> Self {
        let report = TrustCardValidator::validate(card);
        let plan = TrustCardAssistant::plan(card);
        Self {
            name: card.server.name.clone(),
            status: report.status,
            risk_class: card.server.risk_class,
            failure_count: report
                .findings
                .iter()
                .filter(|finding| finding.severity == TrustFindingSeverity::Fail)
                .count(),
            warning_count: report
                .findings
                .iter()
                .filter(|finding| finding.severity == TrustFindingSeverity::Warn)
                .count(),
            human_decision_count: plan.human_decisions.len(),
            finding_codes: report
                .findings
                .into_iter()
                .map(|finding| finding.code)
                .collect(),
            human_decisions: plan.human_decisions,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcp_gateway::trust::TrustAuthMode;
    use tempfile::TempDir;

    fn write_capability(dir: &Path, name: &str) {
        let yaml = format!(
            r"
name: {name}
description: Read weather forecasts
providers:
  primary:
    service: rest
    config:
      base_url: https://example.invalid
auth:
  required: true
  type: api_key
schema:
  input:
    type: object
    properties:
      city:
        type: string
"
        );
        std::fs::write(dir.join(format!("{name}.yaml")), yaml).unwrap();
    }

    #[tokio::test]
    async fn generate_cards_from_capabilities_sorts_and_validates() {
        let temp = TempDir::new().unwrap();
        write_capability(temp.path(), "weather_z");
        write_capability(temp.path(), "weather_a");

        let cards = generate_cards_from_capabilities(temp.path()).await.unwrap();

        assert_eq!(cards[0].server.name, "weather_a");
        assert_eq!(cards[1].server.name, "weather_z");
        assert_eq!(cards[0].server.auth_mode, TrustAuthMode::Key);
        assert_eq!(cards[0].evaluation_status, TrustEvaluationStatus::Warning);
    }

    #[tokio::test]
    async fn validation_row_includes_grouped_human_decisions() {
        let temp = TempDir::new().unwrap();
        write_capability(temp.path(), "weather");
        let cards = generate_cards_from_capabilities(temp.path()).await.unwrap();

        let row = ValidationRow::from_card(&cards[0]);

        assert_eq!(row.name, "weather");
        assert!(row.human_decision_count >= 2);
        assert!(
            row.human_decisions
                .iter()
                .any(|prompt| prompt.prompt_id == "source-ownership")
        );
        assert!(
            row.human_decisions
                .iter()
                .any(|prompt| prompt.prompt_id == "license-review")
        );
    }

    #[tokio::test]
    async fn read_card_file_accepts_json_and_revalidates_on_command_path() {
        let temp = TempDir::new().unwrap();
        write_capability(temp.path(), "weather");
        let card = generate_cards_from_capabilities(temp.path())
            .await
            .unwrap()
            .remove(0);
        let card_path = temp.path().join("trustcard.json");
        std::fs::write(&card_path, serde_json::to_string_pretty(&card).unwrap()).unwrap();

        let loaded = read_card_file(&card_path).await.unwrap().with_validation();

        assert_eq!(loaded.server.name, "weather");
        assert_eq!(loaded.evaluation_status, TrustEvaluationStatus::Warning);
    }

    #[tokio::test]
    async fn trust_validate_returns_failure_only_for_failures_or_strict_warnings() {
        let temp = TempDir::new().unwrap();
        write_capability(temp.path(), "weather");
        let cards = generate_cards_from_capabilities(temp.path()).await.unwrap();

        assert_eq!(validation_exit_code(&cards, false), ExitCode::SUCCESS);
        assert_eq!(validation_exit_code(&cards, true), ExitCode::FAILURE);

        let mut failed = cards[0].clone();
        failed.server.name.clear();
        let failed = failed.with_validation();

        assert_eq!(validation_exit_code(&[failed], false), ExitCode::FAILURE);
    }

    #[tokio::test]
    async fn lab_evaluation_reports_warning_verdict_by_default() {
        let temp = TempDir::new().unwrap();
        write_capability(temp.path(), "weather");
        let policy = TrustLabPolicy::default();

        let evaluations =
            evaluate_lab_from_capabilities(temp.path(), Some("weather"), policy, None)
                .await
                .unwrap();

        assert_eq!(evaluations.len(), 1);
        assert_eq!(evaluations[0].input.server_name, "weather");
        assert_eq!(evaluations[0].policy_verdict, TrustLabPolicyVerdict::Warn);
        assert_eq!(lab_exit_code(&evaluations, false), ExitCode::SUCCESS);
    }

    #[tokio::test]
    async fn lab_evaluation_enforce_mode_fails_blocking_thresholds() {
        let temp = TempDir::new().unwrap();
        write_capability(temp.path(), "weather");
        let policy = TrustLabPolicy {
            advisory_only: false,
            minimum_score: 101,
            ..TrustLabPolicy::default()
        };

        let evaluations =
            evaluate_lab_from_capabilities(temp.path(), Some("weather"), policy, None)
                .await
                .unwrap();

        assert_eq!(evaluations[0].policy_verdict, TrustLabPolicyVerdict::Block);
        assert_eq!(lab_exit_code(&evaluations, true), ExitCode::FAILURE);
    }

    #[tokio::test]
    async fn lab_baseline_write_and_read_round_trips() {
        let temp = TempDir::new().unwrap();
        write_capability(temp.path(), "weather");
        let baseline_path = temp.path().join("trustlab-baseline.json");

        let report = run_lab_evaluation(
            temp.path(),
            Some("weather"),
            TrustLabPolicy::default(),
            None,
            Some(&baseline_path),
            "weather-baseline",
        )
        .await
        .unwrap();

        assert_eq!(
            report.written_baseline.as_deref(),
            Some(baseline_path.as_path())
        );
        let baseline = read_lab_baseline(&baseline_path).await.unwrap();
        assert_eq!(baseline.baseline_id, "weather-baseline");
        assert_eq!(baseline.tool_schema_digests.len(), 1);
    }

    #[tokio::test]
    async fn lab_baseline_detects_schema_drift_in_enforce_mode() {
        let temp = TempDir::new().unwrap();
        write_capability(temp.path(), "weather");
        let cards = generate_cards_from_capabilities(temp.path()).await.unwrap();
        let baseline = lab_baseline_from_cards("baseline-1", &cards);

        let changed = r"
name: weather
description: Read weather forecasts
providers:
  primary:
    service: rest
    config:
      base_url: https://example.invalid
auth:
  required: true
  type: api_key
schema:
  input:
    type: object
    properties:
      postal_code:
        type: string
";
        std::fs::write(temp.path().join("weather.yaml"), changed).unwrap();
        let policy = TrustLabPolicy {
            advisory_only: false,
            ..TrustLabPolicy::default()
        };

        let evaluations =
            evaluate_lab_from_capabilities(temp.path(), Some("weather"), policy, Some(&baseline))
                .await
                .unwrap();

        assert_eq!(evaluations[0].policy_verdict, TrustLabPolicyVerdict::Block);
        assert!(
            evaluations[0]
                .findings
                .iter()
                .any(|finding| finding.code == "TRUSTLAB_SCHEMA_DRIFT")
        );
    }
}

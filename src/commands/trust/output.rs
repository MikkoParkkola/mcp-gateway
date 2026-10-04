// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Human and JSON rendering for the `trust` commands.

use mcp_gateway::{
    cli::output::OutputFormat,
    trust::{
        TrustAssistantPrompt, TrustCard, TrustCardAssistant, TrustCardValidator,
        TrustEvaluationStatus, TrustFindingSeverity, lab::TrustLabEvaluation,
    },
};
use serde::Serialize;

pub(super) fn print_cards(cards: &[TrustCard], format: OutputFormat) {
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

pub(super) fn print_card(card: &TrustCard, format: OutputFormat) {
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

pub(super) fn print_validation_report(cards: &[TrustCard], format: OutputFormat) {
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

pub(super) fn print_lab_evaluations(evaluations: &[TrustLabEvaluation], format: OutputFormat) {
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

pub(super) fn print_lab_table(evaluations: &[TrustLabEvaluation]) {
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

pub(super) fn print_card_table(cards: &[TrustCard]) {
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

pub(super) fn print_findings(findings: &[mcp_gateway::trust::TrustFinding]) {
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

pub(super) fn print_decision_prompts(prompts: &[TrustAssistantPrompt]) {
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

pub(super) fn print_json<T: Serialize + ?Sized>(value: &T) {
    match serde_json::to_string_pretty(value) {
        Ok(json) => println!("{json}"),
        Err(e) => eprintln!("Error: failed to serialize JSON: {e}"),
    }
}

pub(super) fn truncate(value: &str, max_len: usize) -> String {
    if value.len() <= max_len {
        value.to_string()
    } else {
        format!("{}...", &value[..max_len.saturating_sub(3)])
    }
}

#[derive(Serialize)]
pub(super) struct ValidationRow {
    pub(super) name: String,
    pub(super) status: TrustEvaluationStatus,
    pub(super) risk_class: mcp_gateway::trust::TrustRiskClass,
    pub(super) failure_count: usize,
    pub(super) warning_count: usize,
    pub(super) human_decision_count: usize,
    pub(super) finding_codes: Vec<String>,
    pub(super) human_decisions: Vec<TrustAssistantPrompt>,
}

impl ValidationRow {
    pub(super) fn from_card(card: &TrustCard) -> Self {
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

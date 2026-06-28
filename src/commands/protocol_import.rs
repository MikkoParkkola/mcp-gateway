//! Safe protocol import preview command handlers.

use std::{path::Path, process::ExitCode};

use mcp_gateway::{
    cli::{ProtocolImportCommand, ProtocolImportKind, output::OutputFormat},
    protocol_imports::{
        GraphqlImportSpec, ImportPlan, ImportRiskLevel, ImportSourceKind, OciMcpPackageImport,
        ProtocolImportPlanner,
    },
};
use serde::{Serialize, de::DeserializeOwned};

/// Run a safe protocol import subcommand.
pub async fn run_protocol_import_command(cmd: ProtocolImportCommand) -> ExitCode {
    match cmd {
        ProtocolImportCommand::Preview {
            kind,
            file,
            source_name,
            format,
            context_integrity_profile,
        } => {
            match preview_plan_from_file(kind, &file, source_name, context_integrity_profile).await
            {
                Ok(plan) => {
                    print_import_plan(&plan, format);
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("Error: {e}");
                    ExitCode::FAILURE
                }
            }
        }
    }
}

async fn preview_plan_from_file(
    kind: ProtocolImportKind,
    file: &Path,
    source_name: Option<String>,
    context_integrity_profile: String,
) -> Result<ImportPlan, String> {
    let content = tokio::fs::read_to_string(file)
        .await
        .map_err(|e| format!("failed to read {}: {e}", file.display()))?;
    let source_name = source_name.unwrap_or_else(|| default_source_name(file));
    let planner =
        ProtocolImportPlanner::new().with_context_integrity_profile(context_integrity_profile);

    match kind {
        ProtocolImportKind::OpenApi => planner
            .plan_openapi(&source_name, &content)
            .map_err(|e| format!("failed to plan OpenAPI import for {}: {e}", file.display())),
        ProtocolImportKind::Graphql => {
            let spec = parse_document::<GraphqlImportSpec>("GraphQL import spec", file, &content)?;
            planner
                .plan_graphql(&source_name, &spec)
                .map_err(|e| format!("failed to plan GraphQL import for {}: {e}", file.display()))
        }
        ProtocolImportKind::Postman => planner
            .plan_postman(&content)
            .map_err(|e| format!("failed to plan Postman import for {}: {e}", file.display())),
        ProtocolImportKind::OciMcpPackage => {
            let package =
                parse_document::<OciMcpPackageImport>("OCI MCP package metadata", file, &content)?;
            planner.plan_oci_package(&package).map_err(|e| {
                format!(
                    "failed to plan OCI MCP package import for {}: {e}",
                    file.display()
                )
            })
        }
    }
}

fn parse_document<T: DeserializeOwned>(
    label: &str,
    file: &Path,
    content: &str,
) -> Result<T, String> {
    serde_json::from_str(content).or_else(|json_err| {
        serde_yaml::from_str(content).map_err(|yaml_err| {
            format!(
                "failed to parse {label} {} as JSON or YAML: {json_err}; {yaml_err}",
                file.display()
            )
        })
    })
}

fn default_source_name(file: &Path) -> String {
    file.file_stem()
        .and_then(|stem| stem.to_str())
        .filter(|stem| !stem.is_empty())
        .unwrap_or("import-source")
        .to_string()
}

fn print_import_plan(plan: &ImportPlan, format: OutputFormat) {
    match format {
        OutputFormat::Json => print_json(plan),
        OutputFormat::Plain => print_plain(plan),
        OutputFormat::Table => print_table(plan),
    }
}

fn print_plain(plan: &ImportPlan) {
    println!("source={}", plan.source.name);
    println!("kind={}", source_kind_label(plan.source.kind));
    println!("drafts={}", plan.drafts.len());
    println!("review_gates={}", plan.review_gates.len());
    println!("reversible={}", plan.reversible);
    println!("plan_digest_sha256={}", plan.plan_digest_sha256);
    for draft in &plan.drafts {
        println!(
            "draft={} enabled={} risks={} gates={}",
            draft.name,
            draft.enabled,
            draft.risks.len(),
            draft.review_gates.len()
        );
    }
}

fn print_table(plan: &ImportPlan) {
    println!(
        "SOURCE: {} ({})  DRAFTS: {}  GATES: {}  REVERSIBLE: {}",
        plan.source.name,
        source_kind_label(plan.source.kind),
        plan.drafts.len(),
        plan.review_gates.len(),
        plan.reversible
    );
    println!("PLAN DIGEST: {}", plan.plan_digest_sha256);

    if plan.drafts.is_empty() {
        println!("No import drafts generated.");
        return;
    }

    println!();
    println!(
        "{:<28}  {:<8}  {:<10}  {:<7}  {:<5}  GATES",
        "DRAFT", "ENABLED", "PROTOCOL", "RISK", "RISKS"
    );
    println!("{}", "-".repeat(78));
    for draft in &plan.drafts {
        println!(
            "{:<28}  {:<8}  {:<10}  {:<7}  {:<5}  {}",
            truncate(&draft.name, 28),
            draft.enabled,
            truncate(&draft.route.protocol, 10),
            highest_risk_label(draft.risks.iter().map(|risk| risk.level)),
            draft.risks.len(),
            draft.review_gates.len()
        );
    }
}

fn highest_risk_label(levels: impl Iterator<Item = ImportRiskLevel>) -> String {
    levels.max().map_or_else(
        || "none".to_string(),
        |level| format!("{level:?}").to_ascii_lowercase(),
    )
}

fn source_kind_label(kind: ImportSourceKind) -> &'static str {
    match kind {
        ImportSourceKind::OpenApi => "openapi",
        ImportSourceKind::Graphql => "graphql",
        ImportSourceKind::Postman => "postman",
        ImportSourceKind::OciMcpPackage => "oci-mcp-package",
    }
}

fn print_json<T: Serialize + ?Sized>(value: &T) {
    match serde_json::to_string_pretty(value) {
        Ok(json) => println!("{json}"),
        Err(e) => eprintln!("Error: failed to serialize JSON: {e}"),
    }
}

fn truncate(value: &str, max_len: usize) -> String {
    if value.chars().count() <= max_len {
        value.to_string()
    } else {
        let prefix = value
            .chars()
            .take(max_len.saturating_sub(3))
            .collect::<String>();
        format!("{prefix}...")
    }
}

#[cfg(test)]
mod tests {
    use mcp_gateway::protocol_imports::{ImportRiskKind, ImportSourceKind};

    use super::*;

    const OPENAPI_SPEC: &str = r#"
openapi: 3.0.0
info:
  title: Pets
  version: "1.0"
servers:
  - url: https://api.example.test
paths:
  /pets:
    get:
      operationId: listPets
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema:
                type: object
    post:
      operationId: createPet
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                name:
                  type: string
      responses:
        "201":
          description: created
"#;

    #[tokio::test]
    async fn preview_openapi_file_returns_disabled_reversible_plan() {
        let dir = tempfile::tempdir().expect("tempdir");
        let spec = dir.path().join("pets.yaml");
        tokio::fs::write(&spec, OPENAPI_SPEC)
            .await
            .expect("write spec");

        let plan = preview_plan_from_file(
            ProtocolImportKind::OpenApi,
            &spec,
            Some("petstore".to_string()),
            "imported_tool_baseline".to_string(),
        )
        .await
        .expect("preview plan");

        assert_eq!(plan.source.name, "petstore");
        assert_eq!(plan.source.kind, ImportSourceKind::OpenApi);
        assert!(plan.reversible);
        assert!(!plan.safe_defaults.drafts_enabled);
        assert!(!plan.drafts.is_empty());
        assert!(plan.drafts.iter().all(|draft| !draft.enabled));
        assert!(
            plan.drafts
                .iter()
                .any(|draft| draft.review_gates.iter().any(|gate| gate.non_inferable))
        );
    }

    #[tokio::test]
    async fn preview_oci_package_metadata_preserves_supply_chain_gates() {
        let dir = tempfile::tempdir().expect("tempdir");
        let spec = dir.path().join("package.yaml");
        tokio::fs::write(
            &spec,
            r"
name: demo-tools
image_ref: ghcr.io/example/demo-tools:latest
tools:
  - name: export_data
    description: Export account data
    input_schema:
      type: object
      properties:
        account_id:
          type: string
",
        )
        .await
        .expect("write package");

        let plan = preview_plan_from_file(
            ProtocolImportKind::OciMcpPackage,
            &spec,
            None,
            "imported_tool_baseline".to_string(),
        )
        .await
        .expect("preview plan");

        assert_eq!(plan.source.kind, ImportSourceKind::OciMcpPackage);
        assert!(plan.drafts.iter().all(|draft| !draft.enabled));
        assert!(plan.drafts.iter().any(|draft| {
            draft
                .risks
                .iter()
                .any(|risk| risk.kind == ImportRiskKind::SupplyChainProvenance)
        }));
    }
}

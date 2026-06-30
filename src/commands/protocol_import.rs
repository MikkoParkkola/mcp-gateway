//! Safe protocol import preview and draft-apply command handlers.

use std::{path::Path, process::ExitCode};

use mcp_gateway::{
    cli::{ProtocolImportCommand, ProtocolImportKind, output::OutputFormat},
    protocol_imports::{
        CapabilityDraft, GraphqlImportSpec, ImportPlan, ImportRiskLevel, ImportSourceKind,
        OciMcpPackageImport, ProtocolImportPlanner,
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
        ProtocolImportCommand::Apply {
            kind,
            file,
            output,
            source_name,
            format,
            context_integrity_profile,
            force,
        } => {
            match apply_plan_from_file(
                kind,
                &file,
                &output,
                source_name,
                context_integrity_profile,
                force,
            )
            .await
            {
                Ok(report) => {
                    print_apply_report(&report, format);
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

#[derive(Debug, Serialize)]
struct ImportApplyReport {
    schema_version: &'static str,
    source_name: String,
    source_kind: &'static str,
    source_digest_sha256: String,
    plan_digest_sha256: String,
    output_dir: String,
    manifest_path: String,
    activation_state: &'static str,
    review_gate_count: usize,
    written: Vec<AppliedDraft>,
    skipped: Vec<SkippedDraft>,
    rollback: ImportApplyRollback,
    next_steps: Vec<String>,
}

#[derive(Debug, Serialize)]
struct AppliedDraft {
    draft_id: String,
    name: String,
    path: String,
    draft_digest_sha256: String,
    enabled: bool,
    risk_count: usize,
    review_gate_count: usize,
}

#[derive(Debug, Serialize)]
struct SkippedDraft {
    draft_id: String,
    name: String,
    reason: String,
}

#[derive(Debug, Serialize)]
struct ImportApplyRollback {
    command: String,
    files: Vec<String>,
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

async fn apply_plan_from_file(
    kind: ProtocolImportKind,
    file: &Path,
    output: &Path,
    source_name: Option<String>,
    context_integrity_profile: String,
    force: bool,
) -> Result<ImportApplyReport, String> {
    let plan = preview_plan_from_file(kind, file, source_name, context_integrity_profile).await?;
    apply_plan_to_directory(&plan, output, force).await
}

async fn apply_plan_to_directory(
    plan: &ImportPlan,
    output: &Path,
    force: bool,
) -> Result<ImportApplyReport, String> {
    let manifest_path = output.join(manifest_file_name(plan));
    let mut writable = Vec::new();
    let mut skipped = Vec::new();
    let mut claimed_paths = std::collections::HashSet::new();

    for draft in &plan.drafts {
        let Some(generated_yaml) = draft.generated_yaml.as_deref() else {
            skipped.push(SkippedDraft {
                draft_id: draft.id.clone(),
                name: draft.name.clone(),
                reason: format!(
                    "{} drafts do not yet have a reversible capability YAML projection",
                    source_kind_label(draft.source_kind)
                ),
            });
            continue;
        };

        let path = output.join(format!("{}.yaml", draft.name));
        // In-batch collision: two source operations whose names slugify to the
        // same file (e.g. "Delete User" in two Postman folders) would otherwise
        // silently overwrite each other. Skip the later one with an explicit
        // reason instead of clobbering the earlier write.
        if !claimed_paths.insert(path.clone()) {
            skipped.push(SkippedDraft {
                draft_id: draft.id.clone(),
                name: draft.name.clone(),
                reason: format!(
                    "output path {} already claimed by an earlier draft in this import (slug collision); rename the source operation to disambiguate",
                    path.display()
                ),
            });
            continue;
        }
        writable.push((draft, generated_yaml, path));
    }

    if writable.is_empty() {
        return Err(
            "import plan has no reversible capability YAML drafts to apply yet; use preview output for review evidence"
                .to_string(),
        );
    }

    if !force {
        if manifest_path.exists() {
            return Err(format!(
                "refusing to overwrite existing manifest {}; pass --force to replace it",
                manifest_path.display()
            ));
        }
        if let Some((_, _, path)) = writable.iter().find(|(_, _, path)| path.exists()) {
            return Err(format!(
                "refusing to overwrite existing draft {}; pass --force to replace it",
                path.display()
            ));
        }
    }

    tokio::fs::create_dir_all(output).await.map_err(|e| {
        format!(
            "failed to create output directory {}: {e}",
            output.display()
        )
    })?;

    let mut written = Vec::new();
    for (draft, generated_yaml, path) in writable {
        let body = render_applied_draft_yaml(plan, draft, generated_yaml);
        write_atomic(&path, &body, force).await?;
        written.push(AppliedDraft {
            draft_id: draft.id.clone(),
            name: draft.name.clone(),
            path: path.display().to_string(),
            draft_digest_sha256: draft.trust_card.draft_digest_sha256.clone(),
            enabled: draft.enabled,
            risk_count: draft.risks.len(),
            review_gate_count: draft.review_gates.len(),
        });
    }

    let report = build_apply_report(plan, output, &manifest_path, written, skipped);
    let manifest_body = serde_json::to_string_pretty(&report)
        .map_err(|e| format!("failed to serialize apply manifest: {e}"))?;
    write_atomic(&manifest_path, &format!("{manifest_body}\n"), force).await?;

    Ok(report)
}

fn build_apply_report(
    plan: &ImportPlan,
    output: &Path,
    manifest_path: &Path,
    written: Vec<AppliedDraft>,
    skipped: Vec<SkippedDraft>,
) -> ImportApplyReport {
    let rollback_files = written
        .iter()
        .map(|draft| draft.path.clone())
        .chain(std::iter::once(manifest_path.display().to_string()))
        .collect::<Vec<_>>();

    ImportApplyReport {
        schema_version: "protocol_import.apply_report.v1",
        source_name: plan.source.name.clone(),
        source_kind: source_kind_label(plan.source.kind),
        source_digest_sha256: plan.source_digest_sha256.clone(),
        plan_digest_sha256: plan.plan_digest_sha256.clone(),
        output_dir: output.display().to_string(),
        manifest_path: manifest_path.display().to_string(),
        activation_state: "inactive_draft_directory",
        review_gate_count: plan.review_gates.len(),
        written,
        skipped,
        rollback: ImportApplyRollback {
            command: rollback_command(&rollback_files),
            files: rollback_files,
        },
        next_steps: vec![
            "Review each draft YAML and the risk gates in this manifest.".to_string(),
            "Run mcp-gateway cap validate <draft-file> after any manual edits.".to_string(),
            "Move reviewed files into a configured capability directory only after human approval."
                .to_string(),
            "Reload capabilities only after review; import apply never changes active routing."
                .to_string(),
        ],
    }
}

fn render_applied_draft_yaml(
    plan: &ImportPlan,
    draft: &CapabilityDraft,
    generated_yaml: &str,
) -> String {
    format!(
        "# mcp-gateway protocol import draft\n\
         # inactive until this file is reviewed and moved into a configured capability directory\n\
         # source: {} ({})\n\
         # plan_digest_sha256: {}\n\
         # draft_digest_sha256: {}\n\
         # review_gates: {}\n\
         # risks: {}\n\n{}",
        plan.source.name,
        source_kind_label(plan.source.kind),
        plan.plan_digest_sha256,
        draft.trust_card.draft_digest_sha256,
        draft.review_gates.len(),
        draft.risks.len(),
        generated_yaml
    )
}

async fn write_atomic(path: &Path, content: &str, force: bool) -> Result<(), String> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    tokio::fs::create_dir_all(parent)
        .await
        .map_err(|e| format!("failed to create {}: {e}", parent.display()))?;

    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("invalid output path {}", path.display()))?;
    let tmp = parent.join(format!(".{file_name}.tmp"));

    tokio::fs::write(&tmp, content)
        .await
        .map_err(|e| format!("failed to write temp file {}: {e}", tmp.display()))?;
    if force && path.exists() {
        tokio::fs::remove_file(path)
            .await
            .map_err(|e| format!("failed to replace {}: {e}", path.display()))?;
    }
    tokio::fs::rename(&tmp, path).await.map_err(|e| {
        format!(
            "failed to move {} to {}: {e}",
            tmp.display(),
            path.display()
        )
    })
}

fn manifest_file_name(plan: &ImportPlan) -> String {
    let digest = plan.plan_digest_sha256.chars().take(12).collect::<String>();
    format!("import-plan-{digest}.manifest.json")
}

fn rollback_command(files: &[String]) -> String {
    format!(
        "rm -- {}",
        files
            .iter()
            .map(|path| shell_quote(path))
            .collect::<Vec<_>>()
            .join(" ")
    )
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn parse_document<T: DeserializeOwned>(
    label: &str,
    file: &Path,
    content: &str,
) -> Result<T, String> {
    serde_json::from_str(content).or_else(|json_err| {
        guard_untrusted_yaml(content)
            .map_err(|guard_err| format!("rejected {label} {}: {guard_err}", file.display()))?;
        serde_yaml::from_str(content).map_err(|yaml_err| {
            format!(
                "failed to parse {label} {} as JSON or YAML: {json_err}; {yaml_err}",
                file.display()
            )
        })
    })
}

/// Maximum byte size of an untrusted spec document.
const MAX_SPEC_BYTES: usize = 16 * 1024 * 1024;
/// Maximum number of YAML alias references tolerated. Legitimate API specs use
/// `$ref` (a spec-level mechanism), not YAML aliases, so this is ~0 in practice;
/// a low cap kills the exponential "billion laughs" alias-amplification bomb.
const MAX_YAML_ALIASES: usize = 64;

/// Reject hostile untrusted YAML before it reaches `serde_yaml`, which expands
/// anchor/alias references during deserialization (a "billion laughs" memory /
/// stack `DoS`). JSON parsing is already bounded by `serde_json`'s recursion limit,
/// so this guard only runs on the YAML fallback path.
fn guard_untrusted_yaml(content: &str) -> Result<(), String> {
    if content.len() > MAX_SPEC_BYTES {
        return Err(format!(
            "document is {} bytes, exceeds the {MAX_SPEC_BYTES}-byte spec limit",
            content.len()
        ));
    }
    let alias_count = count_yaml_aliases(content);
    if alias_count > MAX_YAML_ALIASES {
        return Err(format!(
            "document uses {alias_count} YAML aliases (limit {MAX_YAML_ALIASES}); \
             alias amplification is rejected — use $ref for spec-level reuse"
        ));
    }
    Ok(())
}

/// Count YAML alias references (`*name` in node position) in raw text. A node
/// alias appears at the start of a value, i.e. after a structural character
/// (`:`, `-`, `[`, `{`, `,`) or at line start, followed by an anchor-name char.
/// This deliberately over-counts conservatively rather than parse YAML.
fn count_yaml_aliases(content: &str) -> usize {
    let bytes = content.as_bytes();
    let mut count = 0;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'*' && i + 1 < bytes.len() {
            let next = bytes[i + 1];
            let prev = bytes[..i]
                .iter()
                .rev()
                .find(|b| !b.is_ascii_whitespace())
                .copied();
            let at_node_position = matches!(prev, None | Some(b':' | b'-' | b'[' | b'{' | b','));
            if at_node_position && (next.is_ascii_alphanumeric() || next == b'_') {
                count += 1;
            }
        }
        i += 1;
    }
    count
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

fn print_apply_report(report: &ImportApplyReport, format: OutputFormat) {
    match format {
        OutputFormat::Json => print_json(report),
        OutputFormat::Plain => print_apply_plain(report),
        OutputFormat::Table => print_apply_table(report),
    }
}

fn print_apply_plain(report: &ImportApplyReport) {
    println!("source={}", report.source_name);
    println!("kind={}", report.source_kind);
    println!("written={}", report.written.len());
    println!("skipped={}", report.skipped.len());
    println!("activation_state={}", report.activation_state);
    println!("output_dir={}", report.output_dir);
    println!("manifest={}", report.manifest_path);
    println!("rollback={}", report.rollback.command);
}

fn print_apply_table(report: &ImportApplyReport) {
    println!(
        "APPLIED: {} ({})  WRITTEN: {}  SKIPPED: {}  ACTIVE: no",
        report.source_name,
        report.source_kind,
        report.written.len(),
        report.skipped.len()
    );
    println!("MANIFEST: {}", report.manifest_path);
    println!("ROLLBACK: {}", report.rollback.command);

    if !report.written.is_empty() {
        println!();
        println!("{:<28}  {:<8}  {:<5}  FILE", "DRAFT", "ENABLED", "GATES");
        println!("{}", "-".repeat(82));
        for draft in &report.written {
            println!(
                "{:<28}  {:<8}  {:<5}  {}",
                truncate(&draft.name, 28),
                draft.enabled,
                draft.review_gate_count,
                draft.path
            );
        }
    }

    if !report.skipped.is_empty() {
        println!();
        println!("Skipped drafts:");
        for draft in &report.skipped {
            println!("  {}: {}", draft.name, draft.reason);
        }
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

    #[test]
    fn guard_rejects_yaml_alias_bomb() {
        // A billion-laughs-style alias amplification must be rejected before
        // serde_yaml expands it.
        use std::fmt::Write as _;
        let mut bomb = String::from("a: &a [x, x, x, x, x, x, x, x, x]\n");
        for (i, prev) in ('b'..='z').zip('a'..='y') {
            let _ = writeln!(
                bomb,
                "{i}: &{i} [*{prev}, *{prev}, *{prev}, *{prev}, *{prev}, *{prev}, *{prev}, *{prev}, *{prev}]"
            );
        }
        let err = guard_untrusted_yaml(&bomb).expect_err("alias bomb must be rejected");
        assert!(err.contains("alias"), "got: {err}");
    }

    #[test]
    fn guard_allows_normal_yaml_without_aliases() {
        let ok = "openapi: 3.0.0\ninfo:\n  title: x\npaths: {}\n";
        assert!(guard_untrusted_yaml(ok).is_ok());
    }

    #[test]
    fn guard_rejects_oversized_document() {
        let big = "x".repeat(MAX_SPEC_BYTES + 1);
        let err = guard_untrusted_yaml(&big).expect_err("oversized doc must be rejected");
        assert!(err.contains("exceeds"), "got: {err}");
    }

    #[test]
    fn count_yaml_aliases_ignores_scalar_stars() {
        // `*` inside scalar text (not in node position) must not be counted.
        assert_eq!(count_yaml_aliases("note: see 2 * 3 for math\n"), 0);
        assert_eq!(count_yaml_aliases("ref: *anchor\n"), 1);
        assert_eq!(count_yaml_aliases("list:\n  - *a\n  - *b\n"), 2);
    }

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

    #[tokio::test]
    async fn apply_openapi_file_writes_inactive_drafts_and_manifest() {
        let dir = tempfile::tempdir().expect("tempdir");
        let spec = dir.path().join("pets.yaml");
        let output = dir.path().join("capability-drafts");
        tokio::fs::write(&spec, OPENAPI_SPEC)
            .await
            .expect("write spec");

        let report = apply_plan_from_file(
            ProtocolImportKind::OpenApi,
            &spec,
            &output,
            Some("petstore".to_string()),
            "imported_tool_baseline".to_string(),
            false,
        )
        .await
        .expect("apply plan");

        assert_eq!(report.activation_state, "inactive_draft_directory");
        assert!(!report.written.is_empty());
        assert!(report.skipped.is_empty());
        assert!(
            report
                .written
                .iter()
                .all(|draft| !draft.enabled && draft.path.contains("capability-drafts"))
        );

        let first_draft = &report.written[0];
        let draft_yaml = tokio::fs::read_to_string(&first_draft.path)
            .await
            .expect("draft yaml");
        assert!(draft_yaml.contains("# mcp-gateway protocol import draft"));
        assert!(draft_yaml.contains("# inactive until this file is reviewed"));
        assert!(draft_yaml.contains("fulcrum: \"1.0\""));

        let manifest = tokio::fs::read_to_string(&report.manifest_path)
            .await
            .expect("manifest");
        let value: serde_json::Value = serde_json::from_str(&manifest).expect("manifest json");
        assert_eq!(value["schema_version"], "protocol_import.apply_report.v1");
        assert_eq!(value["activation_state"], "inactive_draft_directory");
        assert_eq!(
            value["written"].as_array().unwrap().len(),
            report.written.len()
        );
        assert!(
            value["rollback"]["command"]
                .as_str()
                .unwrap()
                .contains(&first_draft.path)
        );
    }

    #[tokio::test]
    async fn apply_graphql_file_writes_inactive_draft_and_manifest() {
        let dir = tempfile::tempdir().expect("tempdir");
        let spec = dir.path().join("graphql.yaml");
        let output = dir.path().join("graphql-drafts");
        tokio::fs::write(
            &spec,
            r#"
endpoint: https://api.example.test/graphql
operations:
  - name: Viewer
    operation_type: query
    query: "query Viewer($first: Int) { viewer { login repositories(first: $first) { nodes { name } } } }"
    variables_schema:
      type: object
      properties:
        first:
          type: integer
"#,
        )
        .await
        .expect("write graphql spec");

        let report = apply_plan_from_file(
            ProtocolImportKind::Graphql,
            &spec,
            &output,
            Some("github-graphql".to_string()),
            "imported_tool_baseline".to_string(),
            false,
        )
        .await
        .expect("apply plan");

        assert_eq!(report.activation_state, "inactive_draft_directory");
        assert_eq!(report.written.len(), 1);
        assert!(report.skipped.is_empty());
        assert!(!report.written[0].enabled);

        let draft_yaml = tokio::fs::read_to_string(&report.written[0].path)
            .await
            .expect("graphql draft yaml");
        let value: serde_json::Value = serde_yaml::from_str(&draft_yaml).expect("graphql yaml");
        assert_eq!(value["providers"]["primary"]["service"], "graphql");
        assert_eq!(
            value["providers"]["primary"]["config"]["endpoint"],
            "https://api.example.test/graphql"
        );
        assert_eq!(value["metadata"]["read_only"], true);

        let manifest = tokio::fs::read_to_string(&report.manifest_path)
            .await
            .expect("manifest");
        let value: serde_json::Value = serde_json::from_str(&manifest).expect("manifest json");
        assert_eq!(value["written"].as_array().unwrap().len(), 1);
        assert!(
            value["rollback"]["command"]
                .as_str()
                .unwrap()
                .contains("rm --")
        );
    }

    #[tokio::test]
    async fn apply_postman_file_writes_inactive_draft_and_manifest() {
        let dir = tempfile::tempdir().expect("tempdir");
        let spec = dir.path().join("collection.json");
        let output = dir.path().join("postman-drafts");
        tokio::fs::write(
            &spec,
            r#"{
  "info": { "name": "Admin API", "_postman_id": "collection-1" },
  "item": [
    {
      "name": "Delete All Users",
      "request": {
        "method": "DELETE",
        "url": {
          "raw": "https://api.example.test/users",
          "query": [{ "key": "confirm" }]
        }
      }
    }
  ]
}"#,
        )
        .await
        .expect("write postman collection");

        let report = apply_plan_from_file(
            ProtocolImportKind::Postman,
            &spec,
            &output,
            None,
            "imported_tool_baseline".to_string(),
            false,
        )
        .await
        .expect("apply plan");

        assert_eq!(report.activation_state, "inactive_draft_directory");
        assert_eq!(report.written.len(), 1);
        assert!(report.skipped.is_empty());
        assert!(!report.written[0].enabled);

        let draft_yaml = tokio::fs::read_to_string(&report.written[0].path)
            .await
            .expect("postman draft yaml");
        let value: serde_json::Value = serde_yaml::from_str(&draft_yaml).expect("postman yaml");
        assert_eq!(value["providers"]["primary"]["service"], "rest");
        assert_eq!(value["providers"]["primary"]["config"]["method"], "DELETE");
        assert_eq!(
            value["providers"]["primary"]["config"]["param_map"]["confirm"],
            "confirm"
        );
        assert_eq!(value["metadata"]["read_only"], false);
    }

    #[tokio::test]
    async fn apply_oci_package_without_reversible_yaml_fails_closed() {
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
",
        )
        .await
        .expect("write package");

        let err = apply_plan_from_file(
            ProtocolImportKind::OciMcpPackage,
            &spec,
            &dir.path().join("drafts"),
            None,
            "imported_tool_baseline".to_string(),
            false,
        )
        .await
        .expect_err("unsupported apply should fail closed");

        assert!(err.contains("no reversible capability YAML drafts"));
        assert!(!dir.path().join("drafts").exists());
    }
}

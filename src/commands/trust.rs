use std::path::Path;
use std::process::ExitCode;

use mcp_gateway::config::Config;
use mcp_gateway::trust::generator::{generate_cbom, generate_trust_card};
use mcp_gateway::trust::validator::{validate_cbom, validate_trust_card};

pub fn run_trust_inspect(backend: &str, config_path: &Path, json: bool) -> ExitCode {
    let config = match Config::load(Some(config_path)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: Failed to load config: {e}");
            return ExitCode::FAILURE;
        }
    };

    let backend_config = match config.backends.get(backend) {
        Some(b) => b,
        None => {
            eprintln!("Error: Backend '{backend}' not found in config");
            return ExitCode::FAILURE;
        }
    };

    let card = generate_trust_card(backend, backend_config, &config);

    if json {
        match serde_json::to_string_pretty(&card) {
            Ok(s) => {
                println!("{s}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("Error: Failed to serialize TrustCard: {e}");
                ExitCode::FAILURE
            }
        }
    } else {
        print_trust_card(&card);
        ExitCode::SUCCESS
    }
}

pub fn run_trust_generate(backend: &str, config_path: &Path, json: bool) -> ExitCode {
    let config = match Config::load(Some(config_path)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: Failed to load config: {e}");
            return ExitCode::FAILURE;
        }
    };

    let backend_config = match config.backends.get(backend) {
        Some(b) => b,
        None => {
            eprintln!("Error: Backend '{backend}' not found in config");
            return ExitCode::FAILURE;
        }
    };

    let card = generate_trust_card(backend, backend_config, &config);
    let cbom = generate_cbom(backend, backend_config, &config, &[], &[], &[]);

    if json {
        let output = serde_json::json!({
            "trust_card": card,
            "cbom": cbom,
        });
        match serde_json::to_string_pretty(&output) {
            Ok(s) => {
                println!("{s}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("Error: Failed to serialize output: {e}");
                ExitCode::FAILURE
            }
        }
    } else {
        println!("=== TrustCard ===");
        print_trust_card(&card);
        println!();
        println!("=== CBOM ===");
        println!("  Subject: {}", cbom.subject.name);
        println!("  Tools: {}", cbom.tools.len());
        println!("  Prompts: {}", cbom.prompts.len());
        println!("  Resources: {}", cbom.resources.len());
        println!("  Dependencies: {}", cbom.dependencies.len());
        ExitCode::SUCCESS
    }
}

pub fn run_trust_validate(backend: &str, config_path: &Path, json: bool) -> ExitCode {
    let config = match Config::load(Some(config_path)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: Failed to load config: {e}");
            return ExitCode::FAILURE;
        }
    };

    let backend_config = match config.backends.get(backend) {
        Some(b) => b,
        None => {
            eprintln!("Error: Backend '{backend}' not found in config");
            return ExitCode::FAILURE;
        }
    };

    let card = generate_trust_card(backend, backend_config, &config);
    let cbom = generate_cbom(backend, backend_config, &config, &[], &[], &[]);

    let card_findings = validate_trust_card(&card);
    let cbom_findings = validate_cbom(&cbom);

    let mut all_findings = card_findings;
    all_findings.extend(cbom_findings);
    all_findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.code.cmp(&b.code))
    });

    if json {
        match serde_json::to_string_pretty(&all_findings) {
            Ok(s) => {
                println!("{s}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("Error: Failed to serialize findings: {e}");
                ExitCode::FAILURE
            }
        }
    } else {
        if all_findings.is_empty() {
            println!("No findings — TrustCard and CBOM are valid.");
        } else {
            for f in &all_findings {
                println!("  [{:?}] {}: {}", f.severity, f.code, f.message);
            }
        }
        ExitCode::SUCCESS
    }
}

fn print_trust_card(card: &mcp_gateway::trust::TrustCard) {
    println!("  Schema Version: {}", card.schema_version);
    println!("  Subject:");
    println!("    Name: {}", card.subject.name);
    println!("    Kind: {}", card.subject.kind);
    if let Some(ref v) = card.subject.version {
        println!("    Version: {v}");
    }
    if let Some(ref d) = card.subject.description {
        println!("    Description: {d}");
    }
    println!("  Source:");
    println!("    Origin: {}", card.source.origin);
    if let Some(ref r) = card.source.registry {
        println!("    Registry: {r}");
    }
    println!("    Manual Override: {}", card.source.manual_override);
    println!("  Owner:");
    if let Some(ref n) = card.owner.name {
        println!("    Name: {n}");
    }
    if let Some(ref h) = card.owner.homepage {
        println!("    Homepage: {h}");
    }
    println!("  License:");
    if let Some(ref s) = card.license.spdx {
        println!("    SPDX: {s}");
    }
    println!("  Transport:");
    println!("    Protocol: {}", card.transport.protocol);
    if let Some(ref u) = card.transport.url {
        println!("    URL: {u}");
    }
    if let Some(ref c) = card.transport.command {
        println!("    Command: {c}");
    }
    if !card.transport.env_var_names.is_empty() {
        println!("    Env Vars: {}", card.transport.env_var_names.join(", "));
    }
    println!("  Runtime:");
    if let Some(ref l) = card.runtime.language {
        println!("    Language: {l}");
    }
    if let Some(ref r) = card.runtime.runtime {
        println!("    Runtime: {r}");
    }
    println!("  Permissions: {}", card.permissions.len());
    println!("  Data Classes: {}", card.data_classes.len());
    println!("  Credential Needs: {}", card.credential_needs.len());
    for cn in &card.credential_needs {
        let req = if cn.required { "required" } else { "optional" };
        println!("    - {} ({req})", cn.name);
    }
    println!("  Network Reach:");
    if !card.network_reach.domains.is_empty() {
        println!("    Domains: {}", card.network_reach.domains.join(", "));
    }
    println!("  Signature: {}", card.signature.is_some());
    println!("  Provenance: {}", card.provenance.is_some());
    println!("  Risk Verdict:");
    println!("    Level: {}", card.risk_verdict.level);
    println!("    Policy Allows: {}", card.risk_verdict.policy_allows);
    println!("    Findings: {}", card.risk_verdict.findings.len());
}

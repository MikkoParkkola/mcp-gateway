// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `mcp-gateway oauth migrate-legacy`: carry one ordinary backend's 3.x OAuth
//! credential to its 4.0 per-issuer key, offline (MIK-6744.STORE.1).

use std::path::Path;
use std::process::ExitCode;

use mcp_gateway::cli::OauthCommand;
use mcp_gateway::config::Config;
use mcp_gateway::oauth::legacy_migrate::{
    LegacyOAuthMigrateError, LegacyOAuthMigration, migrate_legacy_oauth_offline,
};

/// Run `mcp-gateway oauth` subcommands.
pub fn run_oauth_command(cmd: &OauthCommand, config_path: Option<&Path>) -> ExitCode {
    let OauthCommand::MigrateLegacy {
        backend,
        issuer,
        legacy_backend_name,
        legacy_resource_url,
        dry_run,
    } = cmd;
    let Some(path) = config_path else {
        eprintln!(
            "Error: oauth migrate-legacy needs an explicit configuration. Pass --config PATH \
             naming the gateway config that declares the backend."
        );
        return ExitCode::FAILURE;
    };
    let evaluated = match Config::load_evaluated(Some(path)) {
        Ok(evaluated) => evaluated,
        Err(error) => {
            eprintln!(
                "Error: cannot load configuration {}: {error}",
                path.display()
            );
            return ExitCode::FAILURE;
        }
    };
    let request = LegacyOAuthMigration {
        backend,
        issuer,
        legacy_backend_name: legacy_backend_name.as_deref(),
        legacy_resource_url: legacy_resource_url.as_deref(),
        dry_run: *dry_run,
    };
    match migrate_legacy_oauth_offline(&evaluated.config, &request) {
        Ok(done) => {
            for warning in &done.warnings {
                eprintln!("Warning: {warning}");
            }
            if done.dry_run {
                println!(
                    "Dry run: would carry backend `{backend}`'s 3.x credential to issuer {issuer}."
                );
            } else if done.already_present {
                println!(
                    "Nothing to do: backend `{backend}` already holds a 4.0 credential for {issuer}."
                );
            } else {
                println!(
                    "Carried backend `{backend}`'s 3.x credential to issuer {issuer}{}.",
                    if done.wrote_client {
                        ", with its client id"
                    } else {
                        ""
                    }
                );
                println!(
                    "It is used only if this backend's discovery returns exactly {issuer}. \
                     A match does not prove that server issued the grant: its refresh token now \
                     goes there."
                );
            }
            println!("Your 3.x credential files were not modified, renamed or deleted.");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("Error: {error}");
            if matches!(error, LegacyOAuthMigrateError::AccountBound(_)) {
                eprintln!(
                    "Use `mcp-gateway accounts migrate-credentials` for a backend bound to a \
                     personal account."
                );
            }
            ExitCode::FAILURE
        }
    }
}

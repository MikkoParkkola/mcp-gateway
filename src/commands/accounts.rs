// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Offline handlers for `mcp-gateway accounts`.
//!
//! This is the only CLI path that may create a personal-account store. It is
//! deliberately thin: it selects a configuration, loads it through the existing
//! loader so `env_files` are honoured exactly as they are at startup, and hands
//! the result to `initialize_store_offline`. No crypto, no path rule and no
//! emptiness rule is decided here, and nothing in this module opens a socket,
//! starts the custody worker or touches an account record.

use std::path::Path;
use std::process::ExitCode;

use mcp_gateway::{
    InitializedStore, MigratedCredential, OfflineInitError, OfflineMigrationError,
    cli::AccountsCommand, config::Config, initialize_store_offline,
    migrate_legacy_credential_offline,
};

/// Run `mcp-gateway accounts` subcommands.
///
/// `config_path` is the globally selected `--config`, passed in from `main`
/// because `Cli` parses it before the subcommand is dispatched.
pub fn run_accounts_command(cmd: &AccountsCommand, config_path: Option<&Path>) -> ExitCode {
    match cmd {
        AccountsCommand::InitStore => run_init_store(config_path),
        AccountsCommand::MigrateCredentials {
            descriptor_id,
            legacy_issuer,
            legacy_backend_name,
        } => run_migrate_credentials(
            config_path,
            descriptor_id,
            legacy_issuer,
            legacy_backend_name.as_deref(),
        ),
    }
}

/// Migrate one 3.x credential into the configured store.
///
/// Same configuration discipline as `init-store`: the file is named rather than
/// discovered, and it is loaded through `load_evaluated` so the env overlay the
/// key references resolve against is the one the config's own `env_files`
/// produced.
fn run_migrate_credentials(
    config_path: Option<&Path>,
    descriptor_id: &str,
    legacy_issuer: &str,
    legacy_backend_name: Option<&str>,
) -> ExitCode {
    let Some(path) = config_path else {
        eprintln!(
            "Error: accounts migrate-credentials needs an explicit configuration. \
             Pass --config PATH naming the gateway config whose `accounts` block \
             declares the store and the descriptor to migrate into."
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

    match migrate_legacy_credential_offline(
        &evaluated.config,
        &evaluated.overlay,
        descriptor_id,
        legacy_issuer,
        legacy_backend_name,
    ) {
        Ok(report) => {
            print_migrated(&report);
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("Error: {error}");
            eprintln!("{}", migration_hint(&error));
            ExitCode::FAILURE
        }
    }
}

/// Guidance per refusal, so a failure says what to do next rather than only
/// what went wrong.
fn migration_hint(error: &OfflineMigrationError) -> &'static str {
    match error {
        OfflineMigrationError::NotConfigured => {
            "Add an `accounts` block naming store_dir, authority_dir and the key \
             references, then run `accounts init-store` before migrating into it."
        }
        OfflineMigrationError::NoSuchDescriptor(_) => {
            "Name a descriptor declared under `accounts.descriptors` with mode \
             personal_managed. The id is the map key, not the backend registry name."
        }
        OfflineMigrationError::Configuration(_) => {
            "Fix the `accounts` block. A personal_managed descriptor must declare \
             both an explicit resource and an explicit issuer."
        }
        OfflineMigrationError::StoreUnavailable(_) => {
            "The store must already exist and be openable: run `accounts init-store` \
             first, and make sure no gateway is holding its locks."
        }
        OfflineMigrationError::Refused(_) => {
            "Nothing was written and your 3.x file is untouched. The message above \
             names what to change; a renamed backend needs --legacy-backend-name."
        }
    }
}

/// Paths and names only: no token, no scope and no account identity is printed.
fn print_migrated(report: &MigratedCredential) {
    if report.written {
        println!("Migrated one 3.x credential into the account store.");
    } else {
        println!("Nothing to do: this account already holds a grant.");
    }
    println!("  descriptor_id: {}", report.descriptor_id);
    println!("  source file:   {}", report.source);
    println!();
    println!(
        "Your 3.x credential file was not modified, renamed or deleted. Keep it \
         until the migrated backend has been used successfully."
    );
}

/// Initialize an empty store for the selected configuration.
fn run_init_store(config_path: Option<&Path>) -> ExitCode {
    // No implicit discovery. Creating custody state is irreversible for the
    // roots it claims, so the operator names the file instead of learning
    // afterwards which config happened to be found first.
    let Some(path) = config_path else {
        eprintln!(
            "Error: accounts init-store needs an explicit configuration. \
             Pass --config PATH naming the gateway config whose `accounts` block \
             declares the store to create."
        );
        return ExitCode::FAILURE;
    };

    // `load_evaluated`, not `load`: it returns the overlay the config's own
    // `env_files` produced, which is the environment the key references must be
    // resolved against, and it refuses a malformed env file rather than
    // initializing a store against half of one. The env file is never exported
    // into this process's environment.
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

    match initialize_store_offline(&evaluated.config, &evaluated.overlay) {
        Ok(report) => {
            print_report(&report);
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("Error: {error}");
            eprintln!("{}", hint(&error));
            ExitCode::FAILURE
        }
    }
}

/// Operator guidance per refusal, so a failure says what to do next.
fn hint(error: &OfflineInitError) -> &'static str {
    match error {
        OfflineInitError::NotConfigured => {
            "Add an `accounts` block naming store_dir, authority_dir and the key \
             references before initializing a store."
        }
        OfflineInitError::Configuration(_) => {
            "Fix the `accounts` block, or make the declared key reference resolve \
             in one of the config's own `env_files`. Keys are 32 raw bytes in \
             standard base64."
        }
        OfflineInitError::Refused(_) => {
            "Existing state is never replaced and nothing is migrated. Both \
             configured roots must be empty, owner-only directories, and no other \
             process may hold the store locks."
        }
    }
}

/// Report paths and non-secret names only: no key material, no key bytes and no
/// account identity ever reaches this output.
fn print_report(report: &InitializedStore) {
    println!("Initialized an empty personal-account store.");
    println!("  instance_id:   {}", report.instance_id);
    println!("  store_dir:     {}", report.store_dir.display());
    println!("  authority_dir: {}", report.authority_dir.display());
    if report.secret_refs_read.is_empty() {
        println!("  keys read:     none");
    } else {
        // Variable NAMES, which is what makes "which key did it read"
        // answerable without printing what it read.
        println!("  keys read:     {}", report.secret_refs_read.join(", "));
    }
    println!();
    println!("The store holds zero records. No gateway was started and nothing was imported.");
}

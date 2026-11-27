// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Implementation of `mcp-gateway add` and `mcp-gateway remove`.
//!
//! `add` creates a new backend entry in gateway.yaml, optionally bootstrapped
//! from the built-in server registry.  `remove` deletes an existing entry.
//!
//! All core logic is delegated to [`mcp_gateway::gateway::ui::backend_ops`],
//! which provides `Result<T>` functions usable from both CLI and HTTP handlers.

use crate::cli::stdout::println;

use std::path::Path;
use std::process::ExitCode;

use super::config_write::CommentLoss;

use super::{CliExit, check_config_command, fail, usage, write_remedy};

use mcp_gateway::{
    cli_support::store_backend_literals,
    config::TransportConfig,
    config_persistence::load_existing_or_default,
    gateway::ui::backend_ops::{
        add_backend, get_backend, list_backends, remove_backend, resolve_backend,
    },
    gateway::ui::backends::RegistryEntryJson,
    registry::server_registry,
};

// ── add ───────────────────────────────────────────────────────────────────────

/// The values `add` writes: `-e` names, an `--env-file`, and the fields to keep
/// as typed instead of storing (`--keep-as-text`: an env key, or
/// `header:NAME`).
#[derive(Debug, Clone, Copy, Default)]
pub struct AddValues<'a> {
    /// `-e` names, each read from this process's environment.
    pub env_vars: &'a [String],
    /// `--env-file`: a JSON object of names to values; `-` is stdin.
    pub env_file: Option<&'a Path>,
    /// Env keys, or `header:NAME`, to write as typed.
    pub keep_as_text: &'a [String],
}

/// The field a `--keep-as-text` value names: `header:NAME` is a header,
/// anything else an env key.
fn keep_field(given: &str) -> String {
    given.strip_prefix("header:").map_or_else(
        || format!("env.{given}"),
        |header| format!("headers.{header}"),
    )
}

/// Run `mcp-gateway add`.
///
/// # Arguments
///
/// * `name` – backend key (also used for registry lookup)
/// * `cmd` – explicit stdio command (overrides registry)
/// * `url` – explicit HTTP URL (overrides registry)
/// * `desc` – description (overrides registry)
/// * `values` – `KEY=VALUE` env strings, and the fields to keep as text
/// * `config` – path to the gateway config file
pub async fn run_add_command(
    name: &str,
    cmd: Option<&str>,
    url: Option<&str>,
    desc: Option<&str>,
    values: AddValues<'_>,
    config: &Path,
    mode: CommentLoss,
) -> ExitCode {
    // ── Build env map ──────────────────────────────────────────────────────
    let env_file = match values.env_file.map(read_env_file).transpose() {
        Ok(bytes) => bytes,
        Err(msg) => {
            let file = values.env_file.unwrap_or(Path::new("-"));
            return fail(
                CliExit::Usage,
                &msg,
                &format!(
                    "Check that {} exists and that you can read it.",
                    file.display()
                ),
            );
        }
    };
    let env = match env_inputs(values.env_vars, env_file.as_deref(), |name| {
        std::env::var(name).ok()
    }) {
        Ok(e) => e.into_iter().collect::<std::collections::HashMap<_, _>>(),
        // A usage error, before any side effect.
        Err(msg) => {
            return mutant!("N14", crate::commands::fail(crate::commands::CliExit::LocalFailure, "add", &msg), usage("add", &msg));
        }
    };

    // ── Resolve the whole backend ──────────────────────────────────────────
    let resolved = match resolve_backend(name, cmd, url, desc, env) {
        Ok(r) => r,
        Err(msg) => {
            // A credential in the command or URL is a usage error, like a
            // value given to -e (the library's CREDENTIAL_IN_ARGV phrase).
            if msg.contains("would write a credential into gateway.yaml as text") {
                return usage("add", &msg);
            }
            return fail(
                CliExit::LocalFailure,
                &msg,
                "Check the name, --command and --url given, then rerun 'mcp-gateway add'.",
            );
        }
    };
    let transport = resolved.backend.transport.clone();

    // ── Load config ────────────────────────────────────────────────────────
    //
    // Noted before the write, because `add` is a plausible FIRST command — it
    // is in the top-level help — and the config it creates from nothing carries
    // `auth.enabled: false` and no credential. Since the anonymous identity
    // stopped holding admin, that config has no admin path at all: no
    // dashboard, no management tools, and nothing on screen saying why. The
    // credential is not generated here on purpose; minting one as a side effect
    // of adding a backend is a surprise. Saying so is not.
    let creating_config = !config.exists();

    // ── Insert backend and write, under one config lock hold ───────────────
    // A literal the shared rule stores goes to the secret store inside the
    // same hold; the entries are settled by the write's result.
    let keep: Vec<String> = values.keep_as_text.iter().map(|k| keep_field(k)).collect();
    let mut notes = Vec::new();
    let mut store_step = None;
    let written = super::config_write::write(config, mode, |gateway_config| {
        notes = add_backend(gateway_config, name, resolved)
            .map_err(|msg| format!("{msg} (in {})", config.display()))?;
        store_step = Some(store_backend_literals(
            config,
            gateway_config,
            &[name],
            &keep,
        )?);
        Ok(())
    });
    let stored = match store_step {
        Some((adoption, stored)) => {
            adoption.settle(&written);
            stored
        }
        None => Vec::new(),
    };
    if let Err(e) = written {
        return fail(CliExit::LocalFailure, &e, &write_remedy(Some(config)));
    }

    // ── Report ─────────────────────────────────────────────────────────────
    let transport_label = match &transport {
        TransportConfig::Stdio { .. } => "stdio",
        TransportConfig::Http { .. } => "http",
        TransportConfig::WebSocket { .. } => "websocket",
        #[cfg(feature = "a2a")]
        TransportConfig::A2a { .. } => "a2a",
    };
    println!("Added '{name}' ({transport_label}).");
    for (field, reference) in &stored {
        println!("  {field} is in the secret store; gateway.yaml holds {reference}");
    }
    for note in &notes {
        println!("  {note}");
    }
    if creating_config {
        println!();
        println!(
            "Note: created a new {} with authentication off, so it has no",
            config.display()
        );
        println!("admin path — no dashboard and no management tools. To get one:");
        println!("  mcp-gateway init          # generates a credential and writes the config");
        println!("or set auth.enabled with a bearer_token, and list /health and /mcp under");
        println!("auth.public_paths so tool calls keep working.");
    }

    ExitCode::SUCCESS
}

// ── remove ────────────────────────────────────────────────────────────────────

/// Run `mcp-gateway remove`.
pub fn run_remove_command(name: &str, config: &Path, mode: CommentLoss) -> ExitCode {
    let written = super::config_write::write(config, mode, |gateway_config| {
        remove_backend(gateway_config, name)
            .map_err(|msg| format!("{msg} (in {})", config.display()))
    });
    if let Err(e) = written {
        return fail(CliExit::LocalFailure, &e, &write_remedy(Some(config)));
    }

    println!("Removed '{name}'.");
    ExitCode::SUCCESS
}

// ── list ─────────────────────────────────────────────────────────────────────

/// Run `mcp-gateway list`.
pub fn run_list_command(json: bool, config: &Path) -> ExitCode {
    let gateway_config = match load_existing_or_default(config) {
        Ok(config) => config,
        Err(e) => {
            return fail(
                CliExit::LocalFailure,
                &format!("Failed to load {}: {e}", config.display()),
                &format!("Run '{}' to see why.", check_config_command(config)),
            );
        }
    };

    if gateway_config.backends.is_empty() {
        if json {
            println!("[]");
        } else {
            println!("No backends configured in {}.", config.display());
        }
        return ExitCode::SUCCESS;
    }

    let backends = list_backends(&gateway_config);

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&backends).unwrap_or_default()
        );
    } else {
        println!("{} backend(s) in {}:\n", backends.len(), config.display());
        for info in &backends {
            let desc = if info.description.is_empty() {
                "(no description)"
            } else {
                &info.description
            };
            let enabled = if info.enabled { "" } else { " [disabled]" };
            println!("  {} ({}){enabled}", info.name, info.transport);
            println!("    {desc}");
        }
    }
    ExitCode::SUCCESS
}

/// Run `mcp-gateway list --available`: the built-in server library, with
/// what each needs and whether `add` writes it on or off.
pub fn run_list_available_command(json: bool) -> ExitCode {
    let entries: Vec<RegistryEntryJson> = server_registry::all()
        .iter()
        .map(RegistryEntryJson::from)
        .collect();
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&entries).unwrap_or_default()
        );
        return ExitCode::SUCCESS;
    }
    println!(
        "{} servers in the built-in library. Turn one on with `mcp-gateway add <name>`.\n",
        entries.len()
    );
    for e in &entries {
        let state = if e.default_enabled {
            "on in `mcp-gateway init`"
        } else if e.reach_reason.is_some() {
            "added disabled: can reach any address"
        } else {
            "off until added"
        };
        println!("  {} ({}, {}) - {state}", e.name, e.category, e.transport);
        println!("    {}", e.description);
        println!("    login: {}", e.login);
        if let Some(setup) = e.setup {
            println!("    needs: {setup}");
        }
    }
    ExitCode::SUCCESS
}

// ── get ──────────────────────────────────────────────────────────────────────

/// Run `mcp-gateway get`: the backend as text, or one document with `--json` (MIK-9764.JSONF.1). Both show env and
/// header names with the reference as written or `<set>`, never a value.
pub fn run_get_command(name: &str, config: &Path, render: crate::cli::output::Render) -> ExitCode {
    let gateway_config = match load_existing_or_default(config) {
        Ok(config) => config,
        Err(e) => {
            return fail(
                CliExit::LocalFailure,
                &format!("Failed to load {}: {e}", config.display()),
                &format!("Run '{}' to see why.", check_config_command(config)),
            );
        }
    };

    let info = match get_backend(&gateway_config, name) {
        Ok(i) => i,
        Err(msg) => {
            return fail(
                CliExit::LocalFailure,
                &format!("{msg} (in {})", config.display()),
                "Run 'mcp-gateway list' with the same --config to see its backends.",
            );
        }
    };
    if render == crate::cli::output::Render::Json {
        return print_get_document(name, &info, &gateway_config.backends[name]);
    }

    println!("Name:        {name}");
    println!("Transport:   {}", info.transport);
    println!(
        "Description: {}",
        if info.description.is_empty() {
            "(none)"
        } else {
            &info.description
        }
    );
    println!("Enabled:     {}", info.enabled);

    if let Some(command) = &info.command {
        println!(
            "Command:     {} ({} argument(s) redacted)",
            command.executable, command.argument_count
        );
    }
    if let Some(url) = &info.url {
        println!("URL:         {url}");
    }

    // Names and references, never values. This output is routinely pasted
    // into bug reports and CI logs, which is what made the previous `{k}={v}`
    // a credential disclosure rather than a cosmetic issue. A
    // secret reference is shown as written (ADR-028); a value never is.
    let backend = &gateway_config.backends[name];
    if !info.env.is_empty() {
        println!("Environment:");
        for key in &info.env {
            println!("  {key}={}", shown(&backend.env, key));
        }
    }

    if !info.headers.is_empty() {
        println!("Headers:");
        for key in &info.headers {
            println!("  {key}={}", shown(&backend.headers, key));
        }
    }

    ExitCode::SUCCESS
}

/// A backend env or header entry as `get` shows it: the reference as written, `<set>` or `<empty>`, never a value.
fn shown(map: &std::collections::HashMap<String, String>, key: &str) -> String {
    map.get(key).map_or_else(
        || "<set>".to_owned(),
        |v| mcp_gateway::config::secret_slot(v),
    )
}

/// `get --json`'s document (design 3a): names with what `shown` gives, never a value, as the text form.
fn print_get_document(
    name: &str,
    info: &mcp_gateway::gateway::ui::backend_ops::BackendInfo,
    backend: &mcp_gateway::config::BackendConfig,
) -> ExitCode {
    use std::collections::BTreeMap;
    #[derive(serde::Serialize)]
    struct Command<'a> {
        executable: &'a str,
        argument_count: usize,
    }
    #[derive(serde::Serialize)]
    struct View<'a> {
        name: &'a str,
        transport: &'a str,
        description: &'a str,
        enabled: bool,
        command: Option<Command<'a>>,
        url: Option<&'a str>,
        env: BTreeMap<&'a str, String>,
        headers: BTreeMap<&'a str, String>,
    }
    let view = View {
        name,
        transport: &info.transport,
        description: &info.description,
        enabled: info.enabled,
        command: info.command.as_ref().map(|c| Command {
            executable: &c.executable,
            argument_count: c.argument_count,
        }),
        url: info.url.as_deref(),
        env: info
            .env
            .iter()
            .map(|key| (key.as_str(), shown(&backend.env, key)))
            .collect(),
        headers: info
            .headers
            .iter()
            .map(|key| (key.as_str(), shown(&backend.headers, key)))
            .collect(),
    };
    crate::cli::output::print_document(crate::cli::output::document(&view))
}

/// `--env-file`'s entries in file order, repeats kept.
struct EnvFile(Vec<(String, serde_json::Value)>);

impl<'de> serde::Deserialize<'de> for EnvFile {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Entries;
        impl<'de> serde::de::Visitor<'de> for Entries {
            type Value = EnvFile;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a JSON object of names to values")
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                mut map: M,
            ) -> Result<EnvFile, M::Error> {
                let mut entries = Vec::new();
                while let Some(entry) = map.next_entry::<String, serde_json::Value>()? {
                    entries.push(entry);
                }
                Ok(EnvFile(entries))
            }
        }
        deserializer.deserialize_map(Entries)
    }
}

/// `--env-file`'s bytes, from the file or (`-`) stdin, read at most one
/// byte past the bound so an oversized input is refused, not truncated.
fn read_env_file(path: &Path) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let limit = u64::try_from(ENV_FILE_MAX_BYTES).unwrap_or(u64::MAX) + 1;
    let mut bytes = Vec::new();
    let read = if path == Path::new("-") {
        std::io::stdin().take(limit).read_to_end(&mut bytes)
    } else {
        std::fs::File::open(path).and_then(|f| f.take(limit).read_to_end(&mut bytes))
    };
    read.map_err(|e| format!("--env-file {}: {e}", path.display()))?;
    Ok(bytes)
}

/// The largest `--env-file` accepted, as `hash-key` bounds its input.
pub(crate) const ENV_FILE_MAX_BYTES: usize = 64 * 1024;

/// The env values `add` writes, from `-e NAME` (each looked up with
/// `lookup`, the CLI's own environment in production) and `--env-file`'s
/// bytes (a JSON object of names to string values). A name given twice, a
/// `-e` value with `=` (a value on the command line), a name the lookup
/// lacks, or a file that is not such an object within
/// [`ENV_FILE_MAX_BYTES`] is refused with a message naming the problem and
/// never a value.
pub(crate) fn env_inputs(
    names: &[String],
    env_file: Option<&[u8]>,
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<std::collections::BTreeMap<String, String>, String> {
    let mut values = std::collections::BTreeMap::new();
    let mut put = |name: String, value: String| {
        if values.insert(name.clone(), value).is_some() {
            return Err(format!("{name} is given twice; give each variable once"));
        }
        Ok(())
    };
    for given in names {
        if let Some((name, _value)) = given.split_once('=') {
            return Err(format!(
                "-e takes an environment variable name, not a name with a value: values on \
                 the command line are visible in process lists and shell history. Set {name} \
                 in the environment and pass -e {name}, or use --env-file FILE (- for stdin)"
            ));
        }
        let value =
            lookup(given).ok_or_else(|| format!("{given} is not set in the environment"))?;
        put(given.clone(), value)?;
    }
    if let Some(bytes) = env_file {
        if bytes.len() > ENV_FILE_MAX_BYTES {
            return Err(format!(
                "--env-file is larger than {ENV_FILE_MAX_BYTES} bytes"
            ));
        }
        // Every entry in order, a repeated name included (a JSON map would
        // keep only the last).
        let EnvFile(entries) = serde_json::from_slice(bytes).map_err(|e| {
            if e.is_data() {
                "--env-file must be a JSON object of names to values".to_string()
            } else {
                format!(
                    "--env-file is not JSON (line {}, column {})",
                    e.line(),
                    e.column()
                )
            }
        })?;
        for (name, value) in entries {
            let serde_json::Value::String(value) = value else {
                return Err(format!("--env-file: the value of {name} is not a string"));
            };
            put(name, value)?;
        }
    }
    Ok(values)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(tp2)]
#[cfg(test)]
#[path = "add_remove_tests.rs"]
mod tests;

#[cfg(tp2)]
#[cfg(test)]
#[path = "add_remove_layout_tests.rs"]
mod layout_tests;

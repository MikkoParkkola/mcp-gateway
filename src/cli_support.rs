// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Used by the mcp-gateway binary; not part of the library API; no semver
//! guarantee.

/// Whether `c` is a Unicode format character (general category Cf): bidi
/// overrides, zero-width marks and their kin, which reorder or hide the
/// text around them on a terminal.
#[must_use]
pub fn is_format_char(c: char) -> bool {
    matches!(
        c,
        '\u{00ad}'
            | '\u{0600}'..='\u{0605}'
            | '\u{061c}'
            | '\u{06dd}'
            | '\u{070f}'
            | '\u{0890}'..='\u{0891}'
            | '\u{08e2}'
            | '\u{180e}'
            | '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206f}'
            | '\u{feff}'
            | '\u{fff9}'..='\u{fffb}'
            | '\u{110bd}'
            | '\u{110cd}'
            | '\u{13430}'..='\u{1343f}'
            | '\u{1bca0}'..='\u{1bca3}'
            | '\u{1d173}'..='\u{1d17a}'
            | '\u{e0001}'
            | '\u{e0020}'..='\u{e007f}'
    )
}

/// One discovered server's fate in [`adopt_literals`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Written as a backend; its literal values went to the secret store.
    Adopted {
        /// The backend name.
        name: String,
    },
    /// Left out: each reason code with the field it names, never a value.
    Skipped {
        /// The server name as the client file has it.
        name: String,
        /// `(reason code, field)` pairs, sorted by field.
        reasons: Vec<(&'static str, String)>,
    },
}

/// What [`adopt_literals`] put into the config, and the secret entries it
/// created for it. Settle it with the write's result ([`Adoption::settle`]).
/// Dropped unsettled, it keeps the entries (they may already be named by a
/// saved file); an `Err` from [`adopt_literals`] has already removed them.
#[must_use = "settle the secret entries after the write"]
pub struct Adoption {
    /// One per offered server, in input order.
    pub outcomes: Vec<Outcome>,
    secrets: Option<crate::secret_store::PendingSecrets>,
}

impl Adoption {
    /// Settles the entries by the config write's result: saved keeps them; a
    /// refusal before any write (the writer's `Not saved:` errors) deletes
    /// them; any other failure keeps them, since the save may have landed.
    pub fn settle(mut self, saved: &Result<(), String>) {
        let Some(pending) = self.secrets.take() else {
            return;
        };
        match saved {
            Ok(()) => pending.keep(),
            Err(message) if message.starts_with("Not saved:") => {
                // What could not be removed stays indexed and shows as unused.
                let _kept = pending.discard();
            }
            Err(_) => pending.abandon(),
        }
    }
}

impl Drop for Adoption {
    fn drop(&mut self) {
        // Also on an unwind after the save (a panic printing a note): a
        // saved file may name these entries, so they are never deleted here.
        if let Some(pending) = self.secrets.take() {
            pending.abandon();
        }
    }
}

/// Puts each adoptable server in `servers` into `config` as a backend, with
/// every literal `env` and header value moved to the secret store and only
/// its reference written. Runs inside the config writer's edit, under its
/// lock; the vault lock is taken inside it, in the ratified order.
///
/// A server is skipped, with its reasons, when it is named like
/// `capabilities.name`, its name is not a valid backend name, or the shared
/// adopt rule refuses it. A template (`${NAME}`) and an empty value are
/// copied as written. All literals go to the store in one save, and no
/// store is opened when there are none.
///
/// # Errors
///
/// A message ready to print, after removing any entry this call created:
/// every offered server was skipped, the secret store refused, or an
/// adopted backend's references would not resolve.
pub fn adopt_literals(
    destination: &std::path::Path,
    config: &mut crate::config::Config,
    servers: &[crate::discovery::DiscoveredServer],
) -> Result<Adoption, String> {
    let dir = destination
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let choice = config.secrets.store;
    adopt_with(config, servers, || {
        let refused = |e: crate::secret_store::StoreError| store_refused(choice, &e);
        let chosen = crate::secret_store::choose_store(choice, dir).map_err(refused)?;
        let vault = crate::secret_store::Vault::for_config_dir(dir).map_err(refused)?;
        Ok((vault, chosen.store))
    })
}

type Opened = (
    crate::secret_store::Vault,
    std::sync::Arc<dyn crate::secret_store::SecretStore + Send + Sync>,
);

fn store_refused(
    choice: crate::config::SecretStoreChoice,
    error: &crate::secret_store::StoreError,
) -> String {
    format!(
        "secrets.store ({}) refused the discovered values; nothing was written: {error}",
        crate::secret_store::choice_str(choice)
    )
}

/// [`adopt_literals`] over a store that `open` provides, once, and only
/// when there is a literal to save.
pub(crate) fn adopt_with(
    config: &mut crate::config::Config,
    servers: &[crate::discovery::DiscoveredServer],
    open: impl FnOnce() -> Result<Opened, String>,
) -> Result<Adoption, String> {
    use crate::secret_store::{LOCK_WAIT, NewSecretOwned, SaveError, create_secrets};

    let mut outcomes = Vec::with_capacity(servers.len());
    let mut adopted: Vec<(String, crate::config::BackendConfig)> = Vec::new();
    let mut literals: Vec<NewSecretOwned> = Vec::new();
    // Where each literal's reference goes: (adopted index, header?, key).
    let mut slots: Vec<(usize, bool, String)> = Vec::new();
    for server in servers {
        let name = server.name.clone();
        let mut reasons: Vec<(&'static str, String)> = Vec::new();
        if name == config.capabilities.name {
            reasons.push(("capabilities_name", "name".to_owned()));
        } else if crate::config::backend_add::validate_backend_name(&name).is_err() {
            reasons.push(("invalid_name", "name".to_owned()));
        }
        reasons.extend(
            crate::discovery::adopt::refusals(server)
                .into_iter()
                .map(|(refusal, field)| (refusal.code(), field)),
        );
        if !reasons.is_empty() {
            outcomes.push(Outcome::Skipped { name, reasons });
            continue;
        }
        let backend = server.to_backend_config();
        for (header, map) in [(false, &backend.env), (true, &backend.headers)] {
            for (key, value) in map {
                if value.is_empty() || value.contains("${") {
                    continue;
                }
                let kind = if header { "headers" } else { "env" };
                slots.push((adopted.len(), header, key.clone()));
                literals.push(NewSecretOwned {
                    field: format!("backends.{name}.{kind}.{key}"),
                    value: crate::wiped_bytes::WipedBytes::new(value.clone().into_bytes()),
                });
            }
        }
        adopted.push((name.clone(), backend));
        outcomes.push(Outcome::Adopted { name });
    }
    if adopted.is_empty() && !servers.is_empty() {
        return Err(format!(
            "no discovered server could be adopted; nothing was written: {}",
            describe_skipped(&outcomes)
        ));
    }

    // Outside an `Adoption` until the end: an `Err` before then drops it
    // undecided, which removes the entries, since no config names them.
    let pending = if literals.is_empty() {
        None
    } else {
        let (vault, store) = open()?;
        let pending = create_secrets(
            vault,
            store,
            &literals,
            std::time::Instant::now() + LOCK_WAIT,
        )
        .map_err(|error| match error {
            SaveError::Refused(e) | SaveError::Store(e) => store_refused(config.secrets.store, &e),
            SaveError::Commit(never) => match never {},
        })?;
        for ((index, header, key), reference) in slots.iter().zip(pending.refs()) {
            let backend = &mut adopted[*index].1;
            let map = if *header {
                &mut backend.headers
            } else {
                &mut backend.env
            };
            map.insert(key.clone(), reference.clone());
        }
        Some(pending)
    };
    // B3's backstop: a literal is now a fresh reference and a template is
    // not checked, so this should never refuse.
    let overlay = config.env_overlay();
    for (name, backend) in &adopted {
        backend
            .check_secret_references(name, &overlay)
            .map_err(|refused| {
                format!(
                    "discovered server {name:?} has secret references that do not resolve: {}",
                    refused.join("; ")
                )
            })?;
    }
    for (name, backend) in adopted {
        config.backends.insert(name, backend);
    }
    Ok(Adoption {
        outcomes,
        secrets: pending,
    })
}

/// `"name": code (field), ...; ...` for every skipped server: codes and
/// field names only, escaped so no control or bidi character reaches a
/// terminal.
#[must_use]
pub fn describe_skipped(outcomes: &[Outcome]) -> String {
    outcomes
        .iter()
        .filter_map(|outcome| match outcome {
            Outcome::Skipped { name, reasons } => Some(format!(
                "{name:?}: {}",
                reasons
                    .iter()
                    .map(|(code, field)| format!("{code} ({})", field.escape_debug()))
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
            Outcome::Adopted { .. } => None,
        })
        .collect::<Vec<_>>()
        .join("; ")
}

#[cfg(test)]
#[path = "cli_support_tests.rs"]
mod tests;

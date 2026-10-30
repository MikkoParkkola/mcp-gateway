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

/// `raw` as safe display text: without controls (Cc), formats (Cf: bidi
/// overrides, zero-width marks) or line and paragraph separators (Zl, Zp),
/// trimmed and capped at `cap` characters, with whether the cap cut it; `None`
/// when nothing is left. A peer picks these strings, so they must not be able
/// to reorder or hide what is shown. No Unicode normalization: format
/// characters are already gone, and display text needs no dependency for it.
pub(crate) fn display_text(raw: &str, cap: usize) -> Option<(String, bool)> {
    let kept: String = raw
        .chars()
        .filter(|&c| !(c.is_control() || is_format_char(c) || matches!(c, '\u{2028}' | '\u{2029}')))
        .collect();
    let kept = kept.trim();
    if kept.is_empty() {
        return None;
    }
    Some((kept.chars().take(cap).collect(), kept.chars().count() > cap))
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
        /// Whether a rule left it out or it was refused.
        skip: Skip,
    },
}

/// Why a server was left out. A run whose only skips are by rule is a
/// successful import of nothing; a refusal with nothing adopted fails it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Skip {
    /// Left out by a rule every import applies, not for a fault of the
    /// server: the entry named like `capabilities.name`, usually the
    /// gateway's own export.
    ByRule,
    /// The server cannot be adopted as it stands.
    Refused,
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
    /// Settles the entries by the config write's result: saved keeps them, an
    /// error deletes them. The writer's last fallible step is the atomic
    /// rename, so its `Err` means the old file is still in place and nothing
    /// names them.
    pub fn settle(mut self, saved: &Result<(), String>) {
        let Some(pending) = self.secrets.take() else {
            return;
        };
        if saved.is_ok() {
            pending.keep();
            return;
        }
        let kept = pending.discard();
        if !kept.is_empty() {
            // They stay indexed, so the unused listing shows them.
            tracing::warn!(
                not_removed = kept.len(),
                "secret entries of a discover write that was not saved could not be removed"
            );
        }
    }
}

impl Drop for Adoption {
    fn drop(&mut self) {
        // Unsettled means an unwind somewhere after the edit returned: before
        // the rename or after it (printing a note after the save, say). This
        // side cannot tell which, and a saved file may name these entries,
        // so they are kept; with no file naming them they list as unused.
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
/// `capabilities.name`, its name is not a valid backend name or repeats an
/// earlier one, the shared adopt rule refuses it, or a literal value is
/// larger than the store keeps. A template (`${NAME}`) and an empty value
/// are copied as written. All literals go to the store in one save, and no
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
    let (mut outcomes, mut candidates) = classify(config, servers);

    let opened = if candidates.iter().any(|c| !c.literals.is_empty()) {
        Some(open()?)
    } else {
        None
    };
    if let Some((_, store)) = &opened {
        // A value the store cannot keep skips its server, not the import.
        let limit = store.limit();
        candidates.retain(|candidate| {
            let mut over: Vec<(&'static str, String)> = candidate
                .literals
                .iter()
                .filter(|(_, _, value)| value.len() > limit)
                .map(|(header, key, _)| ("value_too_large", field_of(*header, key)))
                .collect();
            if over.is_empty() {
                return true;
            }
            over.sort_by(|a, b| a.1.cmp(&b.1));
            outcomes[candidate.outcome] = Outcome::Skipped {
                name: candidate.name.clone(),
                reasons: over,
                skip: Skip::Refused,
            };
            false
        });
    }
    let refused = outcomes.iter().any(|outcome| {
        matches!(
            outcome,
            Outcome::Skipped {
                skip: Skip::Refused,
                ..
            }
        )
    });
    // Nothing adopted fails the run only when a server was refused; a run
    // whose only finds were left out by rule writes nothing and succeeds.
    if candidates.is_empty() && refused {
        return Err(format!(
            "no discovered server could be adopted; nothing was written: {}",
            describe_skipped(&outcomes)
        ));
    }

    // Outside an `Adoption` until the end: an `Err` before then drops it
    // undecided, which removes the entries, since no config names them.
    let pending = match opened {
        Some((vault, store)) => {
            store_literals(config.secrets.store, vault, store, &mut candidates)?
        }
        None => None,
    };
    // B3's backstop: a literal is now a fresh reference and a template is
    // not checked, so this should never refuse.
    let overlay = config.env_overlay();
    for Candidate { name, backend, .. } in &candidates {
        backend
            .check_secret_references(name, &overlay)
            .map_err(|refused| {
                format!(
                    "discovered server {name:?} has secret references that do not resolve: {}",
                    refused.join("; ").escape_debug()
                )
            })?;
    }
    for Candidate { name, backend, .. } in candidates {
        config.backends.insert(name, backend);
    }
    Ok(Adoption {
        outcomes,
        secrets: pending,
    })
}

/// Each server's fate under the shared rule, before any store is opened:
/// the outcomes in input order, and the servers that passed with their
/// literal values.
fn classify(
    config: &crate::config::Config,
    servers: &[crate::discovery::DiscoveredServer],
) -> (Vec<Outcome>, Vec<Candidate>) {
    let mut outcomes = Vec::with_capacity(servers.len());
    // Adoptable so far: the outcome index, the name, the backend, and its
    // literal values as (header?, key, value).
    let mut candidates: Vec<Candidate> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for server in servers {
        let name = server.name.clone();
        let mut reasons: Vec<(&'static str, String)> = Vec::new();
        if name == config.capabilities.name {
            reasons.push(("capabilities_name", "name".to_owned()));
        } else if crate::config::backend_add::validate_backend_name(&name).is_err() {
            reasons.push(("invalid_name", "name".to_owned()));
        } else if seen.contains(&name) {
            // The first adoptable find of a name wins, as discovery's own
            // dedup does.
            reasons.push(("duplicate_name", "name".to_owned()));
        }
        reasons.extend(
            crate::discovery::adopt::refusals(server)
                .into_iter()
                .map(|(refusal, field)| (refusal.code(), field)),
        );
        if !reasons.is_empty() {
            reasons.sort_by(|a, b| a.1.cmp(&b.1));
            let skip = if reasons.iter().all(|(code, _)| *code == "capabilities_name") {
                Skip::ByRule
            } else {
                Skip::Refused
            };
            outcomes.push(Outcome::Skipped {
                name,
                reasons,
                skip,
            });
            continue;
        }
        seen.insert(name.clone());
        let backend = server.to_backend_config();
        let mut literals = Vec::new();
        for (header, map) in [(false, &backend.env), (true, &backend.headers)] {
            for (key, value) in map {
                if !value.is_empty() && !value.contains("${") {
                    literals.push((header, key.clone(), value.clone()));
                }
            }
        }
        candidates.push(Candidate {
            outcome: outcomes.len(),
            name: name.clone(),
            backend,
            literals,
        });
        outcomes.push(Outcome::Adopted { name });
    }
    (outcomes, candidates)
}

/// Saves every candidate's literals in one batch and puts each reference in
/// its place. `None` when there is no literal. The pending save is returned
/// undecided: an `Err` after this drops it, which removes the entries.
fn store_literals(
    choice: crate::config::SecretStoreChoice,
    vault: crate::secret_store::Vault,
    store: std::sync::Arc<dyn crate::secret_store::SecretStore + Send + Sync>,
    candidates: &mut [Candidate],
) -> Result<Option<crate::secret_store::PendingSecrets>, String> {
    use crate::secret_store::{LOCK_WAIT, NewSecretOwned, SaveError, create_secrets};

    let literals: Vec<NewSecretOwned> = candidates
        .iter()
        .flat_map(|c| {
            c.literals
                .iter()
                .map(|(header, key, value)| NewSecretOwned {
                    field: format!("backends.{}.{}", c.name, field_of(*header, key)),
                    value: crate::wiped_bytes::WipedBytes::new(value.clone().into_bytes()),
                })
        })
        .collect();
    if literals.is_empty() {
        return Ok(None);
    }
    let pending = create_secrets(
        vault,
        store,
        &literals,
        std::time::Instant::now() + LOCK_WAIT,
    )
    .map_err(|error| match error {
        SaveError::Refused(e) | SaveError::Store(e) => store_refused(choice, &e),
        SaveError::Commit(never) => match never {},
    })?;
    // References come back in input order: the same walk as above.
    // A short list would leave a literal as text: refuse instead.
    if pending.refs().len() != literals.len() {
        return Err("the secret store returned fewer references than values; \
             nothing was written"
            .to_owned());
    }
    let mut references = pending.refs().iter();
    for candidate in candidates.iter_mut() {
        for (header, key, _) in &candidate.literals {
            let map = if *header {
                &mut candidate.backend.headers
            } else {
                &mut candidate.backend.env
            };
            if let Some(reference) = references.next() {
                map.insert(key.clone(), reference.clone());
            }
        }
    }
    Ok(Some(pending))
}

/// A server that passed the rule, before its literals are stored.
struct Candidate {
    outcome: usize,
    name: String,
    backend: crate::config::BackendConfig,
    literals: Vec<(bool, String, String)>,
}

/// `env.KEY` or `headers.KEY`.
fn field_of(header: bool, key: &str) -> String {
    format!("{}.{key}", if header { "headers" } else { "env" })
}

/// `"name": code (field), ...; ...` for every skipped server: codes and
/// field names only, escaped so no control or bidi character reaches a
/// terminal.
#[must_use]
pub fn describe_skipped(outcomes: &[Outcome]) -> String {
    outcomes
        .iter()
        .filter_map(|outcome| match outcome {
            Outcome::Skipped { name, reasons, .. } => Some(format!(
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

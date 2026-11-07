// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The secret-slot mechanism every web UI write that stores a literal shares
//! (discovery adopt, the backend routes): a literal leaves the backend through
//! the writer's secret slots, so gateway.yaml holds only the store's reference.
//! Each caller keeps its own answers; this module only says why a store could
//! not be opened, never with the store's own text.

use std::sync::Arc;

use crate::config::SecretStoreChoice;
use crate::config_persistence::keyedit::{Segment, SlotId};
use crate::config_reload::{RELOAD_LOCK_WAIT, SecretStep};
use crate::secret_store::{Chosen, NewSecretOwned, SecretStore, StoreError, Vault, choose_store};
use crate::wiped_bytes::WipedBytes;

/// A secret store the writer can save into.
pub(super) type Store = Arc<dyn SecretStore + Send + Sync>;

/// Why no store took the values. Each caller answers with its own fixed text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Unopened {
    /// The configured choice cannot be met on this host (a 422).
    Unavailable,
    /// The store or the vault failed (a 500).
    Failed,
    /// The store choice or the vault did not answer within the writer's wait
    /// (a 503, retryable).
    TimedOut,
}

/// Parts of an env key that mark its value as a credential wherever they
/// appear. A stored value becomes a whole-value reference, which the redactor
/// holds at any length, so storing an ordinary setting (`DEBUG=1`) would scrub
/// every `1` from tool results: a part that also names ordinary settings
/// (`AUTH_TYPE`, `SESSION_TIMEOUT`, `COOKIE_SECURE`, `PRIVATE_MODE`,
/// `SORT_KEY`) is left out.
const CREDENTIAL_PARTS: [&str; 10] = [
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "PASSPHRASE",
    "CREDENTIAL",
    "CREDENTIALS",
    "APIKEY",
    "PAT",
    "DSN",
];

/// Parts that mark a credential only directly before `KEY` (`API_KEY`,
/// `PRIVATE_KEY`); `KEY` alone names ordinary settings too (`SORT_KEY`).
const KEY_QUALIFIERS: [&str; 6] = [
    "API",
    "ACCESS",
    "PRIVATE",
    "SECRET",
    "SIGNING",
    "ENCRYPTION",
];

/// The parts of env key `key`, split at `_` and `-` and where a lower-case
/// letter or digit meets an upper-case one (`authToken` is `auth`, `Token`).
fn key_parts(key: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    for word in key.split(['_', '-']) {
        let mut start = 0;
        let bytes = word.as_bytes();
        for i in 1..bytes.len() {
            if bytes[i].is_ascii_uppercase() && !bytes[i - 1].is_ascii_uppercase() {
                parts.push(&word[start..i]);
                start = i;
            }
        }
        parts.push(&word[start..]);
    }
    parts.retain(|p| !p.is_empty());
    parts
}

/// Whether env key `key` names a credential: one of its parts (see
/// [`key_parts`]), in any letter case, is a [`CREDENTIAL_PARTS`] entry, or a
/// [`KEY_QUALIFIERS`] entry directly followed by `KEY` (`DB_PASSWORD`,
/// `x_auth_token`, `githubPat`, `OPENAI_API_KEY`). Headers are not judged:
/// every header value is stored. The panel and discovery adopt both store by
/// this rule.
pub(super) fn names_a_credential(key: &str) -> bool {
    let parts = key_parts(key);
    let is = |part: &str, word: &str| part.eq_ignore_ascii_case(word);
    parts
        .iter()
        .any(|part| CREDENTIAL_PARTS.iter().any(|word| is(part, word)))
        || parts
            .windows(2)
            .any(|pair| is(pair[1], "KEY") && KEY_QUALIFIERS.iter().any(|word| is(pair[0], word)))
}

/// The secret slot of backend `name`'s `key`, under `headers` or `env`. Its
/// display form is the secret step's field for that value.
pub(super) fn backend_slot(name: &str, header: bool, key: &str) -> SlotId {
    let map = if header { "headers" } else { "env" };
    SlotId(
        ["backends", name, map, key]
            .map(|k| Segment::Key(k.to_owned()))
            .to_vec(),
    )
}

/// The store the configured choice resolves to.
pub(super) fn chosen(choice: Result<Chosen, StoreError>) -> Result<Store, Unopened> {
    match choice {
        Ok(chosen) => Ok(chosen.store),
        Err(StoreError::Unavailable(_)) => Err(Unopened::Unavailable),
        Err(_) => Err(Unopened::Failed),
    }
}

/// The store choice and the vault beside gateway.yaml, opened off the async
/// workers: `auto` probes the OS keychain, a blocking call that may stall on a
/// locked or slow keychain. Bounded by the writer's own wait; a keychain that
/// does not answer by then is `TimedOut`, and its thread finishes on its own.
pub(super) async fn open_store(
    configured: SecretStoreChoice,
    dir: std::path::PathBuf,
) -> Result<(Store, Result<Vault, StoreError>), Unopened> {
    let open = tokio::task::spawn_blocking(move || {
        (choose_store(configured, &dir), Vault::for_config_dir(&dir))
    });
    match tokio::time::timeout(RELOAD_LOCK_WAIT, open).await {
        Ok(Ok((choice, vault))) => Ok((chosen(choice)?, vault)),
        Ok(Err(_)) => Err(Unopened::Failed),
        Err(_) => Err(Unopened::TimedOut),
    }
}

/// The writer's secret step: each `(field, value)` (value wiped on drop) saved under
/// `backends.<name>.<field>`, in the order given. A vault that cannot be
/// opened (no home for its lock) is `Failed`.
pub(super) fn secret_step(
    name: &str,
    values: Vec<(String, WipedBytes)>,
    store: Store,
    vault: Result<Vault, StoreError>,
) -> Result<SecretStep, Unopened> {
    let Ok(vault) = vault else {
        return Err(Unopened::Failed);
    };
    let values = values
        .into_iter()
        .map(|(field, value)| NewSecretOwned {
            field: format!("backends.{name}.{field}"),
            value,
        })
        .collect();
    Ok(SecretStep {
        vault,
        store,
        values,
    })
}

/// The answer to refused values, shared by the backend add, update and the
/// add preview: each field and code, never a value.
pub(super) fn refused_values(reasons: &[(&'static str, String)]) -> axum::response::Response {
    use axum::response::IntoResponse;
    let refusals: Vec<_> = reasons
        .iter()
        .map(|(reason, field)| serde_json::json!({"reason": reason, "field": field}))
        .collect();
    (
        axum::http::StatusCode::UNPROCESSABLE_ENTITY,
        axum::Json(serde_json::json!({"error": "literal_in_value", "refusals": refusals})),
    )
        .into_response()
}

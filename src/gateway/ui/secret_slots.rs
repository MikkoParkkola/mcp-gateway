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

/// Words an env key may end with, beyond the firewall's own credential names,
/// that mark its value as a credential (`GITHUB_PAT`, `SENTRY_DSN`,
/// `GOOGLE_CREDENTIALS`, `STRIPE_SECRET`, `APIKEY`). Only the last word
/// counts: a stored value becomes a whole-value reference, which the redactor
/// holds at any length, so a setting such as `TOKEN_LIMIT=1` stored would scrub
/// every `1` from tool results.
const ENV_CREDENTIAL_ENDINGS: [&str; 6] = [
    "pat",
    "dsn",
    "credential",
    "credentials",
    "secret",
    "apikey",
];

/// Words that, directly before a final `key`, mark an env credential beyond
/// the firewall's own pairs (`SESSION_KEY`, `AUTH_KEY`, `ENCRYPTION_KEY`).
const ENV_KEY_QUALIFIERS: [&str; 5] = ["session", "cookie", "auth", "access", "encryption"];

/// Whether env key `key` names a credential, judged by its last words only:
/// the firewall's credential-name rule
/// ([`crate::security::credential_names::family_of`], which already leaves
/// out pagination names such as `next_page_token`), or a final word in
/// [`ENV_CREDENTIAL_ENDINGS`], or a final `key` after an
/// [`ENV_KEY_QUALIFIERS`] word. Words are the firewall's own split (`_`, `-`,
/// camel case). Headers are not judged: every header value is stored. The
/// panel and discovery adopt both store by this rule.
pub(super) fn names_a_credential(key: &str) -> bool {
    use crate::security::credential_names::{family_of, words};
    if family_of(key).is_some() {
        return true;
    }
    match words(key).as_slice() {
        // Rails' `SECRET_KEY_BASE`.
        [.., a, b, c] if a == "secret" && b == "key" && c == "base" => true,
        [.., last] if ENV_CREDENTIAL_ENDINGS.contains(&last.as_str()) => true,
        [.., before, last] => last == "key" && ENV_KEY_QUALIFIERS.contains(&before.as_str()),
        _ => false,
    }
}

/// Whether env value `value` under key `key` goes to the store: its key
/// [`names_a_credential`] and it is at least the redactor's short-value bound
/// long. A stored value is redacted wherever it appears, at any length, so a
/// shorter one (`1`, `true`, `none`, as in `HF_HUB_DISABLE_IMPLICIT_TOKEN=1`)
/// would blank ordinary text: it is written as typed, as in 3.x.
pub(super) fn stores_env_value(key: &str, value: &str) -> bool {
    value.len() >= crate::security::needles::SHORT_VALUE_BYTES && names_a_credential(key)
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

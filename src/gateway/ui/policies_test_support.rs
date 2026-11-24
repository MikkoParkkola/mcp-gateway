// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Building the Policies read model in tests through the production
//! `Sources::of`: a real `LiveConfig` started on one config and, for the
//! file-versus-enforced rows, reloaded to another with `set` (the reload's
//! own `Generation::following`).

use serde_json::{Value, json};

use super::policies::{Sources, read_model as model_of};
use crate::config::Config;
use crate::config_reload::LiveConfig;

/// The read model of a gateway started on `config`, with nothing reloaded.
pub(super) fn read_model(config: &Config) -> Value {
    reloaded(config, &[])
}

/// The read model of a gateway started on `startup` and then reloaded to
/// each of `reloads` in turn.
pub(super) fn reloaded(startup: &Config, reloads: &[&Config]) -> Value {
    let live = LiveConfig::new(startup.clone());
    for next in reloads {
        live.set((*next).clone());
    }
    model_of(&Sources::of(&live))
}

/// An expected setting object, every field given: the values a row pins.
pub(super) fn setting_obj(path: &str, file: &Value, enforced: &Value, read_only: bool) -> Value {
    let pending_restart = file != enforced;
    json!({
        "path": path,
        "file": file,
        "enforced": enforced,
        "pending_restart": pending_restart,
        "read_only": read_only,
    })
}

/// An expected switch object: a setting object that also says `on`.
pub(super) fn switch_obj(path: &str, file: bool, enforced: bool, read_only: bool) -> Value {
    let mut s = setting_obj(path, &json!(file), &json!(enforced), read_only);
    s["on"] = json!(enforced);
    s
}

/// The firewall config's path prefix.
#[cfg(feature = "firewall")]
pub(super) const FW: &str = "security.firewall";

/// Every `security.` id the save table lists, as literals in table order, so
/// no test computes `read_only` with the code under test; rc3 ties this list
/// to the table itself.
#[cfg(feature = "firewall")]
pub(super) const SAVEABLE: [&str; 7] = [
    "security.tool_policy.enabled",
    "security.tool_policy.default_action",
    "security.tool_policy.use_default_deny",
    "security.firewall.credential_redaction",
    "security.firewall.collusion.action",
    "security.sanitize_input",
    "security.ssrf_protection",
];

/// A setting as the read model reports it.
#[cfg(feature = "firewall")]
pub(super) fn setting(path: &str, file: Value, enforced: Value) -> Value {
    let pending = file != enforced;
    let mut s = serde_json::Map::new();
    s.insert("path".to_owned(), Value::from(path));
    s.insert("file".to_owned(), file);
    s.insert("enforced".to_owned(), enforced);
    s.insert("pending_restart".to_owned(), Value::Bool(pending));
    // Read-only unless the save table lists the path.
    s.insert(
        "read_only".to_owned(),
        Value::Bool(!SAVEABLE.contains(&path)),
    );
    Value::Object(s)
}

/// A boolean precondition, `on` when its enforced value is.
#[cfg(feature = "firewall")]
pub(super) fn switch(path: &str, file: bool, enforced: bool) -> Value {
    let mut s = setting(path, json!(file), json!(enforced));
    s["on"] = json!(enforced);
    s
}

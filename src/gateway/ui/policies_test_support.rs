// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Building the Policies read model in tests through the production
//! `Sources::of`: a real `LiveConfig` started on one config and, for the
//! file-versus-enforced rows, reloaded to another with `set` (the reload's
//! own `Generation::following`).

use serde_json::Value;
#[cfg(feature = "firewall")]
use serde_json::json;

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

/// The firewall config's path prefix.
#[cfg(feature = "firewall")]
pub(super) const FW: &str = "security.firewall";

/// A setting as the read model reports it.
#[cfg(feature = "firewall")]
pub(super) fn setting(path: &str, file: Value, enforced: Value) -> Value {
    let pending = file != enforced;
    let mut s = serde_json::Map::new();
    s.insert("path".to_owned(), Value::from(path));
    s.insert("file".to_owned(), file);
    s.insert("enforced".to_owned(), enforced);
    s.insert("pending_restart".to_owned(), Value::Bool(pending));
    Value::Object(s)
}

/// A boolean precondition, `on` when its enforced value is.
#[cfg(feature = "firewall")]
pub(super) fn switch(path: &str, file: bool, enforced: bool) -> Value {
    let mut s = setting(path, json!(file), json!(enforced));
    s["on"] = json!(enforced);
    s
}

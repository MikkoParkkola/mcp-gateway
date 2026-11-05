// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Building the Policies read model in tests through the production
//! `Sources::of`: a real `LiveConfig` started on one config and, for the
//! file-versus-enforced rows, reloaded to another with `set` (the reload's
//! own `Generation::following`).

use serde_json::Value;

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

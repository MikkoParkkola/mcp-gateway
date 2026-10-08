// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Which keys choose how a backend is reached, and the refusals that keep a
//! backend to exactly one of them once the file and environment layers merge.

use figment::Figment;
use figment::value::Dict;

use super::OverlayEnv;
use crate::{Error, Result};

/// An environment `url` for a backend is refused, never ignored. The file and
/// the environment merge key by key, so `MCP_GATEWAY_BACKENDS__<NAME>__URL`
/// could not replace a `http_url` the file sets; the variables that can are
/// named instead. The value is not echoed: a URL can carry a credential.
pub(super) fn refuse_backend_url(dict: &Dict) -> std::result::Result<(), String> {
    let Some(figment::value::Value::Dict(_, backends)) = dict.get("backends") else {
        return Ok(());
    };
    for (name, fields) in backends {
        if let figment::value::Value::Dict(_, fields) = fields
            && fields.contains_key("url")
        {
            let var = format!("{}BACKENDS__{}", OverlayEnv::PREFIX, name.to_uppercase());
            return Err(format!(
                "{var}__URL is not read: set {var}__HTTP_URL or {var}__WS_URL instead."
            ));
        }
    }
    Ok(())
}

/// The keys that each pick a backend's transport; `url` stands for one of them.
pub(super) const TRANSPORT_KEYS: &[&str] = &["command", "http_url", "ws_url", "a2a_url"];

/// A backend reached by more than one transport key is refused. The file and
/// environment layers merge key by key, and the transport enum takes the first
/// key present, so before 4.0 an environment `__WS_URL` over a file
/// `http_url` was dropped without a word. Keys only, never values.
pub(super) fn refuse_two_transports(figment: &Figment) -> Result<()> {
    let Ok(figment::value::Value::Dict(_, backends)) = figment.find_value("backends") else {
        return Ok(());
    };
    for (name, fields) in &backends {
        let figment::value::Value::Dict(_, fields) = fields else {
            continue;
        };
        let held: Vec<&str> = TRANSPORT_KEYS
            .iter()
            .copied()
            .filter(|k| fields.contains_key(*k))
            .collect();
        if held.len() > 1 {
            return Err(Error::Config(format!(
                "backend {name} has both {}; keep one.",
                held.join(" and ")
            )));
        }
    }
    Ok(())
}

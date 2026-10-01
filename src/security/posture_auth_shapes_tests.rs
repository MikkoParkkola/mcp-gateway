// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Design row 15: the one auth-shape table that both the startup warning test
//! (`security::posture` tests) and the `doctor` row test read, so the WARN and
//! the doctor finding are held to one expected column. Test-only; declared by
//! `#[path]` from both crates, and `Config` comes from the declaring module.

use super::Config;
use serde_json::json;

/// Auth shapes, and whether each is multi-user.
pub(crate) fn auth_shapes() -> Vec<(&'static str, Config, bool)> {
    // A digest-shaped key, so a gateway built from the shape validates.
    let key = |name: &str| {
        serde_json::from_value(
            json!({ "name": name, "key_sha256": format!("sha256:{}", "ab".repeat(32)) }),
        )
        .unwrap()
    };
    let mut shapes = Vec::new();
    // Would be multi-user if auth were on: only `enabled` makes it false.
    let mut disabled = Config::default();
    disabled.auth.api_keys = vec![key("a"), key("b")];
    shapes.push(("auth disabled, two keys", disabled, false));
    let mut one_key = Config::default();
    one_key.auth.enabled = true;
    one_key.auth.api_keys = vec![key("a")];
    shapes.push(("one key", one_key.clone(), true));
    let mut solo = one_key.clone();
    solo.auth.single_user = true;
    shapes.push(("one key, single_user", solo.clone(), false));
    let mut two_keys = solo.clone();
    two_keys.auth.api_keys.push(key("b"));
    shapes.push(("two keys, single_user", two_keys, true));
    let mut oidc = solo;
    oidc.key_server.oidc =
        vec![serde_json::from_value(json!({ "issuer": "https://idp.example" })).unwrap()];
    shapes.push(("one key, single_user, OIDC", oidc, true));
    let mut bearer = Config::default();
    bearer.auth.enabled = true;
    bearer.auth.bearer_token = Some("t".repeat(40));
    shapes.push(("bearer only", bearer, true));
    shapes
}

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Which startup-only environment keys a reload leaves a restart to apply.

use super::{EvaluatedReload, IMPLICIT_STARTUP_ENV_KEYS, LiveEnv};

/// Startup-only environment keys a restart would read differently.
///
/// Two kinds, and neither is visible in the config diff:
///
/// * a rotated `env:NAME` secret. The holder that consumed it — a
///   `ResolvedAuthConfig`, an agent's HS256 key — is built once at startup and
///   nothing rebuilds it, so the running process keeps the old value.
/// * a `HOME` that no longer resolves where it did at startup, when an env-file
///   entry was spelled with `~`. A restart resolves that entry against the new
///   home and opens a different file.
///
/// The `HOME` rule is deliberately conservative: any assignment of `HOME` by
/// either run's env files, or any change in the value they leave standing, is
/// reported. The notice is never absent when a restart would read different
/// files, and it does not clear: a config whose env files assign `HOME` beside
/// a `~` entry reports `HOME` on every reload, and restarting does not settle
/// it, because the next startup's env files assign it again. It says a restart
/// *could* read different files, never that one is outstanding.
///
/// It has to be, because the question the rule is really answering — would a
/// restart open different files than startup did — cannot be answered from
/// values. `~` in entry N is expanded against the `HOME` in force at THAT point
/// in the sequence (`Config::evaluate`), so an env file can move where a later
/// entry is read while a file after it restores the final value, leaving both
/// runs equal on every value comparison. Answering exactly would mean expanding
/// `~` a second time, which the design forbids. Both runs' assignments count:
/// deleting the move leaves nothing to notice on the reload side, and the
/// restored value can equal the process environment's, so only startup's own
/// assignment records that the expansion base was ever moved.
///
/// The accepted cost is a notice that fires when nothing moved — re-stating an
/// unchanged `HOME` beside a `~` entry (ENVFILE.19g). Reordering is not this
/// rule's to catch: an edit to the `env_files` list is reported as `env_files`.
///
/// Names only. The values are secrets and a reload report is not a place to
/// print one.
pub(in crate::config_reload) fn changed_startup_env_keys(
    env: &LiveEnv,
    evaluated: &EvaluatedReload,
) -> Vec<String> {
    let startup = env.startup();
    let keys: std::collections::BTreeSet<String> = evaluated
        .secret_refs
        .iter()
        .map(String::as_str)
        .chain(IMPLICIT_STARTUP_ENV_KEYS.iter().copied())
        .filter(|name| startup.resolve(name) != evaluated.overlay.resolve(name))
        .map(ToString::to_string)
        .collect();
    let mut keys: Vec<String> = keys.into_iter().collect();
    keys.extend(evaluated.overlay.rotated_secret_files(startup));
    // A `~` entry is expanded against the `HOME` in force AT THAT POINT in the
    // sequence (`Config::evaluate`), not the one left standing at the end, so
    // an env file can move where a LATER entry reads while the final value is
    // restored and compares equal (ENVFILE.19i). Comparing values alone cannot
    // see that, and neither can the reload overlay alone: deleting the move
    // leaves nothing there to notice, and the value it restored may be the
    // process environment's own (ENVFILE.19j). Either run's assignment counts,
    // so the notice never clears for such a config — see the fn doc.
    if env.env_paths().has_tilde_entry()
        && (startup.assigns("HOME")
            || evaluated.overlay.assigns("HOME")
            || startup.resolve("HOME") != evaluated.overlay.resolve("HOME"))
    {
        keys.push("HOME".to_string());
    }
    keys
}

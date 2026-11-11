// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Full validation before any entry: the new bytes go through the reload's
//! own load and refusals with each secret slot standing in as a reserved
//! `env:` name, so a save the reload would refuse creates no store entry.
//! No submitted secret goes through the loader; the one check that needs a
//! real value (one secret matching two credentials) runs here on it, and
//! its message names fields, never values.

use std::collections::BTreeMap;
use std::path::Path;

use super::{RefusalClass, ReplaceError, SecretStep};
use crate::config::{Config, EnvOverlay, PENDING_SLOT_PREFIX, reserved_slot_reference};
use crate::config_persistence::keyedit::{Segment, SlotId, Template};
use crate::config_persistence::lock::Locked;
use crate::config_reload::ReloadContext;
use crate::config_reload::reload_context::EvaluatedReload;
use crate::config_reload::reload_context::refusals::BeforeApplyKind;

/// Each slot's `env:` reference and the stand-in its name resolves to: a
/// fresh random value per slot per save, so two slots never stand in as
/// the same credential, shaped so a digest field still parses as one.
pub(super) fn stand_ins(
    template: &Template,
) -> (BTreeMap<SlotId, String>, BTreeMap<String, String>) {
    let (mut refs, mut pending) = (BTreeMap::new(), BTreeMap::new());
    for (n, id) in template.slot_ids().enumerate() {
        let name = format!("{PENDING_SLOT_PREFIX}{n}");
        refs.insert(id.clone(), format!("env:{name}"));
        pending.insert(name, stand_in(id));
    }
    (refs, pending)
}

fn stand_in(id: &SlotId) -> String {
    let digest = matches!(id.0.last(), Some(Segment::Key(key)) if key.ends_with("key_sha256"));
    if digest {
        format!("sha256:{}", hex::encode(rand::random::<[u8; 32]>()))
    } else {
        format!("mcpgw-pending-{}", hex::encode(rand::random::<[u8; 16]>()))
    }
}

/// One submitted bearer token that is also an API key's credential in the
/// config the save makes: one secret would match two credentials (ADR-022).
fn refuse_shared_credentials(
    step: &SecretStep,
    config: &Config,
    overlay: &EnvOverlay,
) -> Result<(), ReplaceError> {
    // ponytail: the bearer slot only; an API key slot's digest is checked
    // against the others once the save core's field table names key slots.
    let Some(bearer) = step.values.iter().find(|v| v.field == "auth.bearer_token") else {
        return Ok(());
    };
    // Not text: the loader refuses it after the write, with its own message.
    let Ok(bearer) = std::str::from_utf8(bearer.value.as_bytes()) else {
        return Ok(());
    };
    // A key that cannot be compared refuses the bearer, never drops out of
    // the comparison. Fixed text: the resolver's error is not quoted.
    let unreadable = |name: &str, field: &str| {
        ReplaceError::Refused(format!(
            "auth.api_keys['{name}'].{field} cannot be read, so the new bearer token \
             cannot be checked against it; fix that key first"
        ))
    };
    let mut keys = Vec::with_capacity(config.auth.api_keys.len());
    for key in &config.auth.api_keys {
        let name = key.name.as_str();
        let current = (key.resolve_digest(overlay)).map_err(|_| unreadable(name, "key_sha256"))?;
        let previous = (key.resolve_previous_digest(overlay))
            .map_err(|_| unreadable(name, "previous_key_sha256"))?;
        keys.push((name, current, previous));
    }
    crate::gateway::auth::refuse_shared_digests(Some(bearer), keys)
        .map_err(|e| ReplaceError::Refused(e.to_string()))
}

impl ReloadContext {
    /// The refusals the reload transaction answers before it applies
    /// anything, in its order, for a candidate the config writer validates
    /// before any store entry exists. The reload still runs them again on the
    /// written bytes; this only refuses earlier.
    fn refuse_candidate(&self, evaluated: EvaluatedReload) -> Result<(), ReplaceError> {
        let invalid = |reason| ReplaceError::ReloadRefused {
            class: RefusalClass::Invalid,
            reason,
        };
        if let Some(refusal) =
            crate::security::posture::reload_refusal(self.live_config.running(), &evaluated.config)
        {
            return Err(invalid(refusal));
        }
        self.restart_only_refusal(&evaluated).map_err(invalid)?;
        if evaluated.patch.is_empty() {
            return Ok(());
        }
        if let Some(refusal) = self.before_apply_refusal(&evaluated.config, &evaluated.patch) {
            return Err(ReplaceError::ReloadRefused {
                class: match refusal.kind {
                    BeforeApplyKind::NetworkPosture => RefusalClass::Posture,
                    BeforeApplyKind::AccountBinding | BeforeApplyKind::CapabilityClash => {
                        RefusalClass::Invalid
                    }
                },
                reason: refusal.text,
            });
        }
        self.live_config
            .prepare(evaluated.config, &evaluated.overlay)
            .map(drop)
            .map_err(|reason| {
                invalid(crate::config_reload::reload_context::nothing_published(
                    &reason,
                ))
            })
    }

    /// Refuse `template`, before any entry exists, when the reload would
    /// refuse it: its load, the posture, restart-only fields, the checks
    /// before apply and the generation build, on stand-ins for its secrets.
    pub(super) async fn validate_template(
        &self,
        target: &Path,
        template: &Template,
        step: Option<&SecretStep>,
    ) -> Result<(), ReplaceError> {
        // The loader's rule: a reference, never a comment that mentions it.
        let reserved = std::str::from_utf8(template.bytes()).ok();
        if let Some((name, line)) = reserved.and_then(reserved_slot_reference) {
            return Err(ReplaceError::Refused(format!(
                "the new config references {name} on line {line}; names starting \
                 {PENDING_SLOT_PREFIX} are reserved for the config writer, so rename it"
            )));
        }
        let (refs, pending) = stand_ins(template);
        let text = template.clone().fill(&refs).map_err(|_| {
            ReplaceError::Refused("the new config's secret slots could not be checked".to_string())
        })?;
        let text = String::from_utf8(text).map_err(|_| {
            ReplaceError::Refused("the new gateway.yaml is not UTF-8 text".to_string())
        })?;
        let (file, env_paths) = (target.to_path_buf(), self.env.env_paths().clone());
        // The bytes being replaced, as the writer reads them: a firewall rule
        // is carried from them, which a hand edit since the last reload may
        // have changed; bytes that do not load carry nothing.
        let (evaluated, replaced) = tokio::task::spawn_blocking(move || {
            let replaced = Config::load_literal_with_text(&file).ok().map(|(c, _)| c);
            (
                Config::load_pending(&file, &text, &env_paths, pending),
                replaced,
            )
        })
        .await
        .map_err(|e| ReplaceError::Failed(format!("the config check task failed: {e}")))?;
        let evaluated = evaluated.map_err(|e| ReplaceError::ReloadRefused {
            class: RefusalClass::Invalid,
            reason: format!("Failed to parse config: {e}"),
        })?;
        if let Some(step) = step {
            refuse_shared_credentials(step, &evaluated.config, &evaluated.overlay)?;
        }
        #[cfg(not(feature = "firewall"))]
        let _ = replaced;
        // A replacement writes every rule: one the firewall-on load refuses
        // goes in only as carried over unchanged, and none while it runs.
        #[cfg(feature = "firewall")]
        {
            let refused = |e: String| ReplaceError::ReloadRefused {
                class: RefusalClass::Invalid,
                reason: format!("Failed to validate config: {e}"),
            };
            crate::security::firewall::refuse_while_running(
                self.live_config.running(),
                &evaluated.config,
            )
            .map_err(refused)?;
            crate::security::firewall::refuse_authored(replaced.as_ref(), &evaluated.config)
                .map_err(refused)?;
        }
        let patch = crate::config_reload::compute_diff(&self.live_config.get(), &evaluated.config);
        self.refuse_candidate(EvaluatedReload {
            config: evaluated.config,
            patch,
            overlay: evaluated.overlay,
            secret_refs: evaluated.secret_refs,
            inputs: evaluated.inputs,
            configured: evaluated.configured,
        })
    }

    /// `Err(NoConfigFile)` when the file read under this lock is gone now.
    /// Read from the disk, never from the lock's snapshot: a recovery since
    /// the lock was taken may have restored it. A link that no longer names
    /// the locked target, or points at a missing one, is `Failed`, never a
    /// missing config.
    pub(super) fn still_there(
        locked: &Locked,
        config: &std::path::Path,
    ) -> Result<(), ReplaceError> {
        match locked.absent(config) {
            Ok(true) => Err(ReplaceError::NoConfigFile),
            Ok(false) => Ok(()),
            Err(why) => Err(ReplaceError::Failed(why)),
        }
    }
}

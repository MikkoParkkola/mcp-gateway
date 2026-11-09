// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The refusals [`ReloadContext`] answers before a reload applies anything:
//! each says nothing was started, stopped or published (moved from
//! `reload_context.rs`).

use crate::config::Config;
use crate::config_reload::{ConfigPatch, POSTURE_REFUSED_PREFIX};

use super::{EvaluatedReload, ReloadContext};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BeforeApplyKind {
    NetworkPosture,
    AccountBinding,
    CapabilityClash,
}

#[derive(Debug)]
pub(super) struct BeforeApply {
    pub(super) kind: BeforeApplyKind,
    pub(super) text: String,
}

impl ReloadContext {
    /// The refusals a reload answers before `apply_patch` stops or starts any
    /// backend: each says nothing was started, stopped or published.
    pub(super) fn before_apply_refusal(
        &self,
        new_config: &Config,
        patch: &ConfigPatch,
    ) -> Option<BeforeApply> {
        // Before `apply_patch`, which stops and starts backends: a refusal that
        // ran after it could not say nothing was applied. And before the
        // publish, which is what the origin gate would re-read.
        if let Some(refusal) =
            crate::gateway::reload_posture_refusal(self.live_config.running(), new_config)
        {
            // What a restart does with this same file is the operator's next
            // decision, and it differs. A file that also enables authentication
            // is right on a restart and only wrong to apply live; a file that
            // just declares the name refuses at the next start, planned or not.
            let restart = if refusal.restart_would_also_refuse {
                "This configuration is on disk, so the next start, including an \
                 unplanned one, will refuse to serve. Revert it, or close the \
                 tool paths."
            } else {
                // "accepts", not "is safe". The one file that reaches this
                // branch while still leaving the tools open is the one that
                // sets the escape hatch, and calling that safe would have the
                // gateway endorse a choice the operator made deliberately and
                // owns.
                // "would not refuse it for this reason", not "accepts it".
                // `network_bind_refusal` is the only question asked here; a
                // restart still reads the whole file and can fail on a missing
                // env: reference, an unreadable certificate, or anything else
                // validation catches. Promising acceptance is how an operator
                // restarts a working gateway into a different outage — the same
                // overclaiming that cost this message three earlier rewrites.
                "A restart would not refuse it for this reason, and applies the \
                 parts a reload cannot."
            };
            // Two bounded facts, and no summary of "what is still in force".
            //
            // The clause that kept being wrong went out with its cause. Env
            // files once reached the PROCESS environment inside `Config::load`
            // before it returned, so a refused candidate had already mutated
            // the process that refused it — that was the defect,
            // and it is closed: the candidate's env files build an `EnvOverlay`
            // that is published only on success (`self.env.set(overlay)`, below
            // and unreachable from this path), the overlay parses in memory
            // (`dotenvy::from_read_iter`, `src/config/env_overlay.rs:362`)
            // rather than through `dotenvy::dotenv`, and `rg set_var src/` is
            // empty.
            //
            // Say that, not "impossible". `#![deny(unsafe_code)]` is not
            // `forbid`, an `#[allow]` overrides it, and neither binds a
            // dependency. What holds this closed is the ABSENT call site plus
            // the parse path — a switch to `dotenvy::from_path` would reopen
            // it, and that is the line to watch.
            //
            // The summary is still not written, for a different reason: this
            // check asks `network_bind_refusal` and nothing else, while a
            // restart reads the whole file. Claiming more than the two facts
            // below is how a security message starts the next report.
            return Some(BeforeApply {
                kind: BeforeApplyKind::NetworkPosture,
                text: format!(
                    "{POSTURE_REFUSED_PREFIX} {} No backend was started or stopped, \
                     and no configuration was published. {restart}",
                    refusal.reason
                ),
            });
        }

        // A changed account binding cannot reuse the credentials minted under
        // the descriptor it replaces: the descriptor's authority, resource,
        // issuer, client id and requested scopes define the account key and the
        // descriptor revision every existing lease carries. Eager replacement
        // of those is not implemented in this slice, so this refuses and
        // mutates nothing rather than pretending a live replacement happened.
        // Compared against what is RUNNING, so it stays true until a restart.
        if let Some(reason) = crate::config::account_bindings::reload_binding_refusal(
            self.live_config.running(),
            new_config,
        ) {
            return Some(BeforeApply {
                kind: BeforeApplyKind::AccountBinding,
                text: format!(
                    "{POSTURE_REFUSED_PREFIX} {reason} No backend was started or stopped, and no \
                     configuration was published."
                ),
            });
        }

        self.refuse_capability_name_clash(patch)
            .err()
            .map(|text| BeforeApply {
                kind: BeforeApplyKind::CapabilityClash,
                text,
            })
    }

    /// A refusal when `evaluated` changes a security field only a restart
    /// applies: message signing, the signature chain or the record key.
    pub(super) fn restart_only_refusal(
        &self,
        evaluated: &EvaluatedReload,
    ) -> std::result::Result<(), String> {
        let (running, proposed) = (&self.live_config.running().security, &evaluated.config);
        let (env, overlay) = (self.env.startup(), &evaluated.overlay);
        let signing = (running.message_signing)
            .restart_changed_field(&proposed.security.message_signing, env, overlay)
            .map_err(|error| error.to_string())?;
        let (was, now) = (&running.signature_chain, &proposed.security.signature_chain);
        let chain =
            crate::config::SignatureChainConfig::restart_changed_field(was.as_ref(), now.as_ref());
        // The record key keys every record and subscription handle
        // for the process's lifetime, so a changed reference waits for a restart.
        let record_key = (running.record_principal_key != proposed.security.record_principal_key)
            .then(|| "record_principal_key".to_owned());
        let field = (signing.map(|f| format!("message_signing.{f}")))
            .or_else(|| chain.map(|f| format!("signature_chain.{f}")))
            .or(record_key);
        field.map_or(Ok(()), |field| {
            Err(format!(
                "config reload refused: security.{field} requires restart"
            ))
        })
    }

    /// The capabilities section applies only at restart, so the attached
    /// capability backend keeps its name through a reload that renames it. A
    /// backend registered under that name would be judged as itself and
    /// answered by the capability; load refuses the pair, and so does this.
    fn refuse_capability_name_clash(&self, patch: &ConfigPatch) -> std::result::Result<(), String> {
        let Some(cap) = self.capabilities.as_ref() else {
            return Ok(());
        };
        let Some((name, _)) = patch
            .backends_added
            .iter()
            .chain(&patch.backends_modified)
            .find(|(name, _)| *name == cap.name)
        else {
            return Ok(());
        };
        Err(format!(
            "{POSTURE_REFUSED_PREFIX} backends.{name} has the name of the running capability \
             backend, and a capabilities.name change applies only at restart. Restart first, \
             or rename the backend. No backend was started or stopped, and no configuration \
             was published."
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_reload::compute_diff;
    use crate::config_reload::replace_test_support::setup;

    /// K1: red oracle is `NetworkPosture` rather than the stub `CapabilityClash`.
    #[test]
    fn k1_network_posture_kind() {
        let (_dir, _path, ctx) = setup();
        let old = ctx.live_config.get();
        let mut new = (*old).clone();
        new.server.public_url = Some("https://gw.example.com".to_owned());
        let refusal = ctx
            .before_apply_refusal(&new, &compute_diff(&old, &new))
            .unwrap();
        assert_eq!(refusal.kind, BeforeApplyKind::NetworkPosture);
    }

    /// K1: red oracle is `AccountBinding` rather than the stub `CapabilityClash`.
    #[test]
    fn k1_account_binding_kind() {
        let (_dir, _path, ctx) = setup();
        let old = ctx.live_config.get();
        let mut new = (*old).clone();
        new.backends.get_mut("a").unwrap().account = Some("work".to_owned());
        let refusal = ctx
            .before_apply_refusal(&new, &compute_diff(&old, &new))
            .unwrap();
        assert_eq!(refusal.kind, BeforeApplyKind::AccountBinding);
    }

    /// K1: oracle is `CapabilityClash`; this control already passes the stub.
    #[test]
    fn k1_capability_clash_kind() {
        use crate::capability::{CapabilityBackend, CapabilityExecutor};
        use std::sync::Arc;

        let (_dir, path, _) = setup();
        let ctx = crate::config_reload::replace_test_support::unshared(&path).with_capabilities(
            Some(Arc::new(CapabilityBackend::new(
                "edits",
                Arc::new(CapabilityExecutor::new()),
            ))),
        );
        let old = ctx.live_config.get();
        let mut new = (*old).clone();
        new.backends
            .insert("edits".to_owned(), new.backends["a"].clone());
        let refusal = ctx
            .before_apply_refusal(&new, &compute_diff(&old, &new))
            .unwrap();
        assert_eq!(refusal.kind, BeforeApplyKind::CapabilityClash);
    }
}

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Identity-grant startup helpers, moved out of `mod.rs` unchanged; that file
//! is over the 800-line ceiling.

use std::path::PathBuf;
use std::sync::Arc;

use tracing::{error, warn};

use super::expand_home_path;
use crate::{Error, Result};

/// The grant sink a reload publishes into, or `None` when grants are off.
///
/// Rebuilt from config at the `ReloadContext` sites rather than threaded out
/// of `build_meta_mcp`: the path is `config.security.identity_grants.path`
/// either way, and `expand_home_path` is the same resolution startup used.
pub(super) fn identity_grant_sink_for(
    config: &crate::config::IdentityGrantsConfig,
    meta_mcp: &crate::gateway::meta_mcp::MetaMcp,
) -> Option<Arc<crate::config_reload::IdentityGrantSink>> {
    if !config.enabled {
        return None;
    }
    let (store, epoch) = meta_mcp.identity_grant_sink();
    Some(Arc::new(crate::config_reload::IdentityGrantSink::new(
        store,
        epoch,
        expand_home_path(&config.path),
    )))
}

pub(super) async fn load_configured_identity_grants(
    config: &crate::config::IdentityGrantsConfig,
) -> Result<Option<(PathBuf, crate::identity_grants::LocalIdentityGrantStore)>> {
    if !config.enabled {
        return Ok(None);
    }

    let path = expand_home_path(&config.path);
    match crate::identity_grants::load_identity_grants_file(&path).await {
        Ok(grants) => Ok(Some((path, grants))),
        Err(e) if config.fail_on_error => Err(Error::Config(e)),
        Err(e) => {
            // Bound outside the macro, so its head carries plain locals.
            let shown = path.display();
            warn!(
                error = %e,
                path = %shown,
                "Failed to load local identity grants; personal capabilities without matching grants will fail closed"
            );
            Ok(None)
        }
    }
}

/// How long startup waits for a CLI change holding the grant journal lock.
const STARTUP_LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// Startup grant audit (design section 6 steps 3-6): build the grant sink,
/// attach an auditor when a governance store is open, reconcile the grant
/// file and journal under the journal lock, write the startup snapshot, and
/// serve exactly the rows it recorded. Runs before any listener binds or any
/// stdio line is read.
///
/// Fail closed: if the reconciliation or the snapshot cannot be recorded
/// (including a journal lock that stays busy), this run serves no grants and
/// returns no sink, so no later reload publishes any either.
///
/// # Errors
///
/// [`Error::Config`] when `fail_on_error` is set and the grant file cannot be
/// read under the journal lock: the same refusal the first load gives.
pub(super) async fn start_identity_grant_audit(
    config: &crate::config::Config,
    meta_mcp: &crate::gateway::meta_mcp::MetaMcp,
    store: Option<&Arc<dyn crate::control_plane::ControlPlaneStore>>,
    store_dir: &std::path::Path,
) -> Result<Option<Arc<crate::config_reload::IdentityGrantSink>>> {
    let Some(sink) = identity_grant_sink_for(&config.security.identity_grants, meta_mcp) else {
        return Ok(None);
    };
    let Some(store) = store else {
        return Ok(Some(sink));
    };
    let path = expand_home_path(&config.security.identity_grants.path);
    let auditor = Arc::new(crate::config_reload::grant_audit::GrantAuditor::new(
        Arc::clone(store),
        store_dir,
        &path,
    ));
    let outcome = audit_startup(
        &auditor,
        &path,
        config.security.identity_grants.fail_on_error,
    )
    .await;
    if let Err(StartupFailure::Unreadable(reason)) = &outcome
        && config.security.identity_grants.fail_on_error
    {
        return Err(Error::Config(reason.clone()));
    }
    let (live, epoch) = meta_mcp.identity_grant_sink();
    let publish = |rows| {
        crate::gateway::publish_identity_grants(
            &live,
            &epoch,
            crate::identity_grants::LocalIdentityGrantStore::from_grants(rows),
        );
    };
    match outcome {
        Ok(rows) => {
            publish(rows);
            let sink = Arc::into_inner(sink)
                .expect("the sink was just built")
                .with_auditor(auditor);
            Ok(Some(Arc::new(sink)))
        }
        Err(StartupFailure::Unreadable(_)) => {
            // Tolerated (`fail_on_error: false`): the empty set was recorded
            // and is the baseline, and the sink stays for the next reload.
            publish(Vec::new());
            let sink = Arc::into_inner(sink)
                .expect("the sink was just built")
                .with_auditor(auditor);
            Ok(Some(Arc::new(sink)))
        }
        Err(StartupFailure::Unrecorded(reason)) => {
            let shown_path = path.display();
            error!(%reason, path = %shown_path, "identity grant changes could not be recorded at startup; serving no grants until restart");
            publish(Vec::new());
            // No sink: every reload this run leaves grants empty. The next
            // start recovers and snapshots first (design section 6 step 6).
            Ok(None)
        }
    }
}

/// Why the startup audit served no grants.
enum StartupFailure {
    /// The grant file could not be read; the empty set is recorded.
    Unreadable(String),
    /// Something could not be recorded; the run serves no grants.
    Unrecorded(String),
}

impl From<String> for StartupFailure {
    fn from(reason: String) -> Self {
        Self::Unrecorded(reason)
    }
}

/// Reconcile, record and snapshot under the journal lock; the rows returned
/// are the rows recorded.
async fn audit_startup(
    auditor: &crate::config_reload::grant_audit::GrantAuditor,
    path: &std::path::Path,
    fail_on_error: bool,
) -> std::result::Result<Vec<crate::identity_grants::IdentityGrant>, StartupFailure> {
    use crate::config_reload::grant_audit::Recorded;
    let read = crate::identity_grants::journal::read_locked(path, STARTUP_LOCK_WAIT)
        .await
        .ok_or_else(|| "the grant journal lock stayed busy".to_string())?;
    let rows = match read.grants {
        Ok(file) => file.grants,
        // Serve and record the empty set, but do not reconcile: an
        // unreadable file is not a removal. The recorded empty set becomes
        // the baseline, so a file later written directly reads as
        // `out_of_band`. The caller refuses the start instead when
        // `fail_on_error` is set.
        // Refusing the start writes nothing: no baseline, no snapshot.
        Err(reason) if fail_on_error => return Err(StartupFailure::Unreadable(reason)),
        Err(reason) => {
            let shown_path = path.display();
            warn!(%reason, path = %shown_path, "identity grants unreadable at startup; serving none until a reload reads them");
            auditor.seed_empty_baseline()?;
            auditor.snapshot(&[], chrono::Utc::now())?;
            drop(read.guard);
            return Err(StartupFailure::Unreadable(reason));
        }
    };
    let prepared = auditor.prepare(&rows, &read.journal).map_err(|r| r.0)?;
    if let Recorded::Unrecorded(reason) = auditor.record(prepared) {
        return Err(reason.into());
    }
    auditor.snapshot(&rows, chrono::Utc::now())?;
    drop(read.guard);
    Ok(rows)
}

/// The stdio half: stdio opens no governance store for anything else, so it
/// opens one here when grants are on, then runs the same startup audit. The
/// returned sink holds the store (and its lease) for the process lifetime;
/// after a failed startup audit there is no sink and grants stay empty.
///
/// # Errors
///
/// The store refusal of [`super::build_control_plane_store`].
pub(super) async fn stdio_identity_grants(
    config: &crate::config::Config,
    config_path: Option<&std::path::Path>,
    meta_mcp: &crate::gateway::meta_mcp::MetaMcp,
) -> Result<Option<Arc<crate::config_reload::IdentityGrantSink>>> {
    if !config.security.identity_grants.enabled {
        return Ok(None);
    }
    let base = super::control_plane_base(config, config_path);
    let store = super::build_control_plane_store(config, &base)?;
    start_identity_grant_audit(config, meta_mcp, store.as_ref(), &base.path).await
}

#[cfg(test)]
#[path = "identity_grants_tests.rs"]
mod tests;

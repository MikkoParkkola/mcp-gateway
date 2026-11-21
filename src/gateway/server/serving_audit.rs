// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The serving audit (WIRE.4): the record key and the transparency log a gateway serves with,
//! resolved and opened once while the gateway is built. Every metadata build reuses them, so a
//! served gateway has one log and one key, and a log that did not open is never opened later.

use std::path::Path;
use std::sync::Arc;

use tracing::{info, warn};

use super::persistence;
use crate::config::{Config, LiveEnv};
use crate::config_reload::startup_settle::{ServingLog, StartupSession, finish_start};
use crate::gateway::record_principal::RecordPrincipalKey;
use crate::security::TransparencyLogger;
use crate::{Error, Result};

/// What every metadata build of one gateway shares. `log` is `None` when logging is off or its
/// best-effort open failed; either way it stays `None`.
#[derive(Clone)]
pub(super) struct ServingAudit {
    pub(super) record_key: Arc<RecordPrincipalKey>,
    pub(super) log: Option<Arc<TransparencyLogger>>,
}

/// Open the serving audit, then settle the serve load's startup session with that same log
/// before anything else of the gateway is built; the config lock goes with the session. A
/// construction without a session has nothing to settle here.
pub(super) async fn open_and_settle(
    config: &Config,
    env: &LiveEnv,
    data_dir: &Path,
    session: Option<StartupSession>,
) -> Result<ServingAudit> {
    let (audit, log) = open(config, env, data_dir)?;
    if let Some(session) = session {
        #[cfg(all(test, unix))]
        crate::config_reload::serve_seams::reached(
            session.target(),
            crate::config_reload::serve_seams::Point::AfterServingOpen,
        );
        Box::pin(finish_start(session, log))
            .await
            .map_err(|class| Error::Config(class.to_string()))?;
    }
    Ok(audit)
}

/// Resolve the record key under `data_dir` and open the configured log, once. Also returns what
/// the startup gate settles with: the open log, logging off, or a best-effort open that failed.
fn open(config: &Config, env: &LiveEnv, data_dir: &Path) -> Result<(ServingAudit, ServingLog)> {
    persistence::ensure_data_dir(data_dir);
    let record_key = Arc::new(crate::gateway::record_principal::resolve_key(
        config
            .security
            .record_principal_key
            .as_ref()
            .map(crate::config::RecordPrincipalKeyRef::as_str),
        &env.get(),
        data_dir,
    )?);
    let Some(tl_cfg) = config.audit_log() else {
        return Ok((
            ServingAudit {
                record_key,
                log: None,
            },
            ServingLog::Off,
        ));
    };
    let tl_cfg = Arc::new(tl_cfg);
    // Auth on: the log is required (D1-a) and a failed append
    // withholds the call's result (D1-f).
    let auth_on = config.auth.enabled;
    let policy = if auth_on {
        crate::security::audit::AuditFailurePolicy::FailClosed
    } else {
        crate::security::audit::AuditFailurePolicy::BestEffort
    };
    match crate::security::TransparencyLogger::open(tl_cfg) {
        Ok(logger) => {
            let logger = Arc::new(
                logger
                    .with_failure_policy(policy)
                    .with_record_key(Arc::clone(&record_key)),
            );
            info!("Transparency log enabled");
            let log = Some(Arc::clone(&logger));
            Ok((ServingAudit { record_key, log }, ServingLog::Open(logger)))
        }
        // Two writers of one log fork its chain, so this refuses
        // whatever the auth setting.
        Err(e) if crate::security::transparency_log::is_lease_held(&e) => {
            Err(Error::Config(format!("refusing to start: {e}")))
        }
        Err(e) if auth_on => Err(Error::Config(format!(
            "auth is enabled, so the audit log (security.transparency_log) must \
                         open: {e}"
        ))),
        Err(e) => {
            warn!(error = %e, "Failed to open transparency log — continuing without it");
            Ok((
                ServingAudit {
                    record_key,
                    log: None,
                },
                ServingLog::Failed,
            ))
        }
    }
}

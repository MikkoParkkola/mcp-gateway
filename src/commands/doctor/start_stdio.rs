// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `doctor --start-stdio`: start each stdio backend the way the gateway does,
//! and report why one that dies before `initialize` died (#526).
//!
//! Opt-in because it runs the configured commands, with their side effects.
//! The default doctor only checks that each command is on `PATH`.

use std::time::Duration;

use mcp_gateway::config::{BackendConfig, TransportConfig};
use mcp_gateway::transport::{StdioTransport, Transport as _, isolated_package_manager_env};

use super::CheckResult;

/// Longest a single start may take here, whatever the backend's own timeout.
const START_CAP: Duration = Duration::from_secs(15);

/// Which stdio check doctor runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StdioProbe {
    /// Check the command is on `PATH`; run nothing.
    Locate,
    /// Start each stdio backend and complete `initialize`.
    Start,
}

/// Start `backend` through the same transport, env and cwd the gateway uses,
/// then close it. `None` for a non-stdio backend.
pub(super) async fn start_stdio_backend(
    name: &str,
    backend: &BackendConfig,
) -> Option<CheckResult> {
    let TransportConfig::Stdio {
        command,
        cwd,
        protocol_version,
    } = &backend.transport
    else {
        return None;
    };
    let label = format!("Backend '{name}' start (--start-stdio)");
    if let Some(profile) = &backend.runtime_profile {
        // A runtime profile launches the command inside a sandbox the doctor
        // does not build, so a local start would be a different launch. Said
        // out loud, never a pass and never a missing row.
        return Some(
            CheckResult::warn(
                &label,
                format!(
                    "skipped: runs under runtime profile {profile}; \
                     doctor does not launch profiled backends"
                ),
            )
            .with_category("backend_stdio"),
        );
    }
    let timeout = backend.timeout.min(START_CAP);
    let transport = StdioTransport::new(
        command,
        isolated_package_manager_env(name, command, backend.env.clone()),
        cwd.clone(),
        timeout,
        protocol_version.clone(),
    );
    let started = tokio::time::timeout(timeout, transport.start()).await;
    let _ = transport.close().await;
    Some(match started {
        Ok(Ok(())) => {
            CheckResult::pass(&label, "initialize completed").with_category("backend_stdio")
        }
        Ok(Err(error)) => {
            let detail = match transport.start_failure_excerpt() {
                Some(excerpt) if !excerpt.is_empty() => format!("{error}\nstderr:\n{excerpt}"),
                _ => error.to_string(),
            };
            CheckResult::fail(&label, detail).with_category("backend_stdio")
        }
        Err(_) => CheckResult::fail(
            &label,
            format!(
                "no answer to initialize within {}s (capped at 15s)",
                timeout.as_secs()
            ),
        )
        .with_category("backend_stdio"),
    })
}

#[cfg(all(test, unix))]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::commands::doctor::{CheckStatus, check_stdio_backend};

    fn stdio(command: &str, env: &[(&str, &str)]) -> BackendConfig {
        BackendConfig {
            transport: TransportConfig::Stdio {
                command: command.to_string(),
                cwd: None,
                protocol_version: None,
            },
            env: env
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect::<HashMap<_, _>>(),
            timeout: Duration::from_secs(30),
            ..BackendConfig::default()
        }
    }

    /// T7: the same cause the gateway logs, through the backend's own env.
    #[tokio::test]
    async fn t7_start_stdio_reports_the_exit_and_the_stderr_tail() {
        let backend = stdio(
            r#"sh -c '[ "$NEEDS" = yes ] && { echo cause-canary >&2; exit 3; }; exit 9'"#,
            &[("NEEDS", "yes")],
        );
        let result = start_stdio_backend("b", &backend)
            .await
            .expect("a stdio row");
        assert_eq!(result.status, CheckStatus::Fail);
        assert!(
            result.detail.contains("exit status: 3"),
            "{}",
            result.detail
        );
        assert!(result.detail.contains("cause-canary"), "{}", result.detail);
    }

    /// T7d: a profiled backend is reported as skipped, by name: a warning,
    /// never a pass, and never launched.
    #[tokio::test]
    async fn t7d_a_profiled_backend_is_reported_skipped_not_passed() {
        let dir = tempfile::tempdir().expect("dir");
        let marker = dir.path().join("launched");
        let mut backend = stdio(&format!("sh -c 'touch {}'", marker.display()), &[]);
        backend.runtime_profile = Some("sandboxed".to_string());
        let result = start_stdio_backend("b", &backend)
            .await
            .expect("a row, not silence");
        assert_eq!(result.status, CheckStatus::Warn, "{}", result.detail);
        assert!(
            result
                .detail
                .contains("skipped: runs under runtime profile sandboxed")
                && result
                    .detail
                    .contains("doctor does not launch profiled backends"),
            "{}",
            result.detail
        );
        assert!(!marker.exists(), "a profiled backend was launched");
    }

    /// T7b: the default doctor runs nothing.
    #[test]
    fn t7b_the_default_check_does_not_launch() {
        let dir = tempfile::tempdir().expect("dir");
        let marker = dir.path().join("launched");
        let backend = stdio(&format!("sh -c 'touch {}'", marker.display()), &[]);
        let _ = check_stdio_backend("b", &backend.transport);
        assert!(!marker.exists(), "the default doctor launched the backend");
    }

    /// T7c: a healthy backend passes and is closed afterwards.
    #[tokio::test]
    async fn t7c_a_backend_that_answers_passes() {
        let reply = r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25"}}"#;
        let backend = stdio(
            &format!("sh -c 'read l; echo {reply:?}; cat >/dev/null'"),
            &[],
        );
        let result = start_stdio_backend("b", &backend)
            .await
            .expect("a stdio row");
        assert_eq!(result.status, CheckStatus::Pass, "{}", result.detail);
    }
}

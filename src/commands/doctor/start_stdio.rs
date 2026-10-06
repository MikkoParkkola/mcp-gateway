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
    /// `Start`, and a start that exits early also shows the child's
    /// sanitized stderr tail under a may-contain-secrets banner.
    StartShowingStderr,
}

impl StdioProbe {
    /// The probe `--start-stdio` and `--show-stderr` select. The CLI refuses
    /// `--show-stderr` alone.
    #[must_use]
    pub const fn from_flags(start_stdio: bool, show_stderr: bool) -> Self {
        match (start_stdio, show_stderr) {
            (false, _) => Self::Locate,
            (true, false) => Self::Start,
            (true, true) => Self::StartShowingStderr,
        }
    }
}

/// The stdio row for `backend` under `probe`.
pub(super) async fn stdio_row(
    probe: StdioProbe,
    name: &str,
    backend: &BackendConfig,
) -> Option<CheckResult> {
    match probe {
        StdioProbe::Locate => super::check_stdio_backend(name, &backend.transport),
        StdioProbe::Start | StdioProbe::StartShowingStderr => {
            start_stdio_backend(name, backend, probe).await
        }
    }
}

/// Start `backend` through the same transport, env and cwd the gateway uses,
/// then close it. `None` for a non-stdio backend.
pub(super) async fn start_stdio_backend(
    name: &str,
    backend: &BackendConfig,
    probe: StdioProbe,
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
    let transport = StdioTransport::new(
        command,
        isolated_package_manager_env(name, command, backend.env.clone()),
        cwd.clone(),
        backend.timeout,
        protocol_version.clone(),
    );
    if let Some(bytes) = backend.max_frame_bytes {
        transport.set_max_frame_bytes(bytes);
    }
    // The backend's own timeout bounds each request inside `start`; the cap
    // bounds the whole start, spawn and handshake included. An early exit's
    // error names its status, class and matched needle, never the child's
    // stderr text (MIK-7978).
    let started = tokio::time::timeout(START_CAP, transport.start()).await;
    let _ = transport.close().await;
    Some(match started {
        Ok(Ok(())) => {
            CheckResult::pass(&label, "initialize completed").with_category("backend_stdio")
        }
        Ok(Err(error)) => {
            let mut detail = error.to_string();
            if probe == StdioProbe::StartShowingStderr {
                detail.push_str(&stderr_section(&transport.last_failure_stderr()));
            }
            CheckResult::fail(&label, detail).with_category("backend_stdio")
        }
        Err(_) => CheckResult::fail(
            &label,
            format!("start did not finish within {}s", START_CAP.as_secs()),
        )
        .with_category("backend_stdio"),
    })
}

/// The `--show-stderr` lines, banner first: masking is best effort.
fn stderr_section(lines: &[String]) -> String {
    if lines.is_empty() {
        return "\n  (no stderr captured)".to_string();
    }
    let mut section =
        "\n  stderr tail (may contain secrets: masking is best effort, review before sharing):"
            .to_string();
    for line in lines {
        section.push_str("\n    ");
        section.push_str(line);
    }
    section
}

// Unix-only (W-L5): the probed backends are `sh -c` scripts, which Windows does not provide.
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

    /// T7e: the flag selects the launch; without it nothing runs.
    #[tokio::test]
    async fn t7e_the_start_probe_launches_and_the_locate_probe_does_not() {
        let backend = stdio("sh -c 'echo dispatch-canary >&2; exit 5'", &[]);
        let started = stdio_row(StdioProbe::Start, "b", &backend)
            .await
            .expect("row");
        assert!(
            started.detail.contains("exit status: 5"),
            "{}",
            started.detail
        );
        let located = stdio_row(StdioProbe::Locate, "b", &backend).await;
        assert!(
            located.is_none_or(|r| !r.detail.contains("exit status")),
            "the locate probe ran the command"
        );
    }

    /// T7f: a start that never finishes is cut at the cap, whatever the
    /// backend's own (per-request) timeout.
    #[tokio::test(start_paused = true)]
    async fn t7f_a_hung_start_ends_at_the_cap() {
        let mut backend = stdio("sh -c 'exec sleep 7200'", &[]);
        backend.timeout = Duration::from_secs(3600);
        // The clock is paused, so this is virtual time: the message names the
        // cap whichever bound fired, and only the elapsed time tells them apart.
        let began = tokio::time::Instant::now();
        let result = start_stdio_backend("b", &backend, StdioProbe::Start)
            .await
            .expect("a stdio row");
        let elapsed = began.elapsed();
        assert!(
            (START_CAP..START_CAP * 4).contains(&elapsed),
            "the cap, not the backend timeout, ended the start: {elapsed:?}"
        );
        assert_eq!(result.status, CheckStatus::Fail, "{}", result.detail);
        assert!(
            result.detail.contains("did not finish within 15s"),
            "{}",
            result.detail
        );
    }

    /// MIK-7978: the row names the early exit's class and needle, never the
    /// child's stderr text. Test idea from #1759 (terafin).
    #[tokio::test]
    async fn an_early_exit_row_names_the_class_not_the_stderr() {
        let sentinel = format!("ghp_{}", "q7".repeat(17));
        let backend = stdio(
            &format!("sh -c 'echo \"Error: Cannot find module x {sentinel}\" >&2; exit 3'"),
            &[],
        );
        let row = start_stdio_backend("b", &backend, StdioProbe::Start)
            .await
            .expect("a stdio row");
        assert!(!row.detail.contains(&sentinel), "{}", row.detail);
        assert!(row.detail.contains("missing_module"), "{}", row.detail);
        assert!(row.detail.contains("exit status: 3"), "{}", row.detail);
    }

    /// T7: the same cause the gateway logs, through the backend's own env.
    #[tokio::test]
    async fn t7_start_stdio_reports_the_exit_and_its_class() {
        let backend = stdio(
            r#"sh -c '[ "$NEEDS" = yes ] && { echo "x: command not found" >&2; exit 3; }; exit 9'"#,
            &[("NEEDS", "yes")],
        );
        let result = start_stdio_backend("b", &backend, StdioProbe::Start)
            .await
            .expect("a stdio row");
        assert_eq!(result.status, CheckStatus::Fail);
        assert!(
            result.detail.contains("exit status: 3"),
            "{}",
            result.detail
        );
        assert!(result.detail.contains("missing_file"), "{}", result.detail);
    }

    /// T7d: a profiled backend is reported as skipped, by name: a warning,
    /// never a pass, and never launched.
    #[tokio::test]
    async fn t7d_a_profiled_backend_is_reported_skipped_not_passed() {
        let dir = tempfile::tempdir().expect("dir");
        let marker = dir.path().join("launched");
        let mut backend = stdio(&format!("sh -c 'touch {}'", marker.display()), &[]);
        backend.runtime_profile = Some("sandboxed".to_string());
        let result = start_stdio_backend("b", &backend, StdioProbe::Start)
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
        let result = start_stdio_backend("b", &backend, StdioProbe::Start)
            .await
            .expect("a stdio row");
        assert_eq!(result.status, CheckStatus::Pass, "{}", result.detail);
    }

    /// MIK-7978 STDERR.3: `--show-stderr` adds the sanitized tail under a
    /// banner; the credential in it stays masked.
    #[tokio::test]
    async fn show_stderr_adds_the_sanitized_tail_under_a_banner() {
        let backend = stdio(
            "sh -c 'echo \"Error: Cannot find module tail-7978\" >&2; \
             echo \"Authorization: Bearer tok-7978\" >&2; exit 3'",
            &[],
        );
        let shown = start_stdio_backend("b", &backend, StdioProbe::StartShowingStderr)
            .await
            .expect("a stdio row");
        assert_eq!(shown.status, CheckStatus::Fail, "{}", shown.detail);
        assert!(
            shown.detail.contains("may contain secrets"),
            "{}",
            shown.detail
        );
        assert!(
            shown.detail.contains("Error: Cannot find module tail-7978"),
            "{}",
            shown.detail
        );
        assert!(!shown.detail.contains("tok-7978"), "{}", shown.detail);
        let hidden = start_stdio_backend("b", &backend, StdioProbe::Start)
            .await
            .expect("a stdio row");
        assert!(!hidden.detail.contains("tail-7978"), "{}", hidden.detail);
        assert!(
            !hidden.detail.contains("may contain secrets"),
            "{}",
            hidden.detail
        );
    }

    /// STDERR.3: `--show-stderr` needs `--start-stdio`, and the two select
    /// the showing probe.
    #[test]
    fn show_stderr_requires_start_stdio() {
        use clap::Parser as _;
        use mcp_gateway::cli::{Cli, Command};
        assert!(Cli::try_parse_from(["mcp-gateway", "doctor", "--show-stderr"]).is_err());
        let cli = Cli::try_parse_from(["mcp-gateway", "doctor", "--start-stdio", "--show-stderr"])
            .expect("both flags parse");
        let Some(Command::Doctor {
            start_stdio,
            show_stderr,
            ..
        }) = cli.command
        else {
            panic!("not the doctor command");
        };
        assert_eq!(
            StdioProbe::from_flags(start_stdio, show_stderr),
            StdioProbe::StartShowingStderr
        );
        assert_eq!(StdioProbe::from_flags(true, false), StdioProbe::Start);
        assert_eq!(StdioProbe::from_flags(false, false), StdioProbe::Locate);
    }
}

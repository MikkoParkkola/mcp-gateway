// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The bounded Node oracle runner used by `hardened_signing_e2e.rs` (MIK-8381, MIK-8610).

use std::process::Stdio;
use std::time::Duration;

use tokio::io::AsyncWriteExt as _;

/// How long one oracle run may take. Twelve tests each start `node` at once,
/// and a loaded Windows runner has taken more than 30 s to finish one
/// (MIK-8381), so the bound is generous; a run that still exceeds it is killed
/// and reported, never left waiting.
pub(crate) const ORACLE_LIMIT: Duration = Duration::from_secs(120);

/// One oracle run: its exit status (`None` if it was killed at the limit),
/// whatever it wrote to stderr, and how long it ran.
pub(crate) struct OracleRun {
    pub(crate) status: Option<std::process::ExitStatus>,
    pub(crate) stderr: String,
    pub(crate) elapsed: Duration,
    limit: Duration,
}

impl OracleRun {
    /// The panic text for a run killed at the limit, carrying what it wrote.
    pub(crate) fn timeout_message(&self) -> String {
        format!(
            "signing oracle did not exit within {:?} (elapsed {:?}); killed it; stderr: {:?}",
            self.limit, self.elapsed, self.stderr
        )
    }
}

/// When an oracle's `limit` starts counting.
pub(crate) enum LimitFrom {
    /// At spawn: start-up counts against the limit (the real oracle's hang guard).
    Spawn,
    /// Once this marker is in the oracle's stderr: start-up does not count.
    Marker(&'static str),
}

/// Run `command` with `input` on stdin and at most `limit` to take it and
/// exit. Stderr goes to a named temporary file, read only through a fresh
/// handle, so no reader waits on a pipe a stalled child or a grandchild could
/// hold open, and what it wrote is kept even when the child is killed at the
/// limit.
pub(crate) async fn run_oracle(
    mut command: tokio::process::Command,
    input: &[u8],
    limit: Duration,
    from: LimitFrom,
) -> OracleRun {
    use std::io::Read as _;
    let named = tempfile::NamedTempFile::new().expect("oracle stderr file");
    let spawned = std::time::Instant::now();
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::from(
            named.as_file().try_clone().expect("oracle stderr handle"),
        ))
        .kill_on_drop(true)
        .spawn()
        .expect("node is required for the independent signing oracle");
    let mut stdin = Some(child.stdin.take().expect("oracle stdin"));
    // Stderr is read only through a fresh handle, whose file offset the
    // child never shares.
    let read_stderr = || {
        let mut file = named.reopen().expect("reopen oracle stderr");
        let mut stderr = String::new();
        let _ = file.read_to_string(&mut stderr);
        stderr
    };
    let started = match from {
        LimitFrom::Spawn => spawned,
        LimitFrom::Marker(marker) => {
            if let Some(mut stdin) = stdin.take() {
                // A child that exits before reading closes the pipe; its status says why.
                let _ = stdin.write_all(input).await;
            }
            loop {
                let stderr = read_stderr();
                if stderr.contains(marker) {
                    break std::time::Instant::now();
                }
                if child.try_wait().expect("oracle process").is_some() {
                    // Gone before running: its status and stderr are reported as usual.
                    break spawned;
                }
                if spawned.elapsed() >= ORACLE_LIMIT {
                    let _ = child.kill().await;
                    panic!(
                        "the oracle never wrote {marker:?} within {ORACLE_LIMIT:?} (hang guard); stderr: {stderr:?}"
                    );
                }
                // timing: precondition
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    };
    let finished = tokio::time::timeout(limit, async {
        // A child that exits before reading closes the pipe; its status says why.
        if let Some(mut stdin) = stdin.take() {
            let _ = stdin.write_all(input).await;
        }
        child.wait().await
    })
    .await;
    let status = if let Ok(status) = finished {
        Some(status.expect("oracle process"))
    } else {
        // An oracle that exits just as the limit passes cannot be killed
        // (Windows refuses); it is gone either way.
        let _ = child.kill().await;
        None
    };
    let elapsed = started.elapsed();
    let stderr = read_stderr();
    OracleRun {
        status,
        stderr,
        elapsed,
        limit,
    }
}

/// A stand-in oracle: `node -e <script>`, the same runtime the real one needs.
pub(crate) fn fake_oracle(script: &str) -> tokio::process::Command {
    let mut command = tokio::process::Command::new("node");
    command.arg("-e").arg(script);
    command
}

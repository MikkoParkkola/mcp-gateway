// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The bounded Node oracle runner every signing suite uses (MIK-8381, MIK-8610,
//! MIK-8701): `tests/common/signing_verifier.mjs`, run once warm per test
//! binary, then once per verify under the caller's own bound.

use std::io::Write as _;
use std::process::Stdio;
use std::time::Duration;

use tokio::io::AsyncWriteExt as _;

/// How long the first `node` launch of a test binary may take (MIK-8701). A
/// cold Windows runner stalled two concurrent first launches for the full 30 s
/// per-verify bound, then ran the same verifies in under a second; the warm-up
/// takes that cost once, under this bound, so no verify bound counts it.
const WARM_LIMIT: Duration = Duration::from_secs(300);

/// How long a marker-timed oracle may take to write its marker (hang guard).
const MARKER_HANG_GUARD: Duration = Duration::from_secs(120);

/// Where a run was when its limit ran out (MIK-8701.ORACLE.2). A spawn that
/// fails outright panics at once with its own message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Stage {
    /// Starting the process: `spawn` itself returned after the limit.
    Spawn,
    /// Writing the input to the oracle's stdin.
    Write,
    /// Waiting for the oracle to exit.
    Wait,
}

/// One oracle run: its exit status (`None` if it was killed at the limit),
/// whatever it wrote to stderr, how long it ran, and the stage reached.
pub(crate) struct OracleRun {
    pub(crate) status: Option<std::process::ExitStatus>,
    pub(crate) stderr: String,
    pub(crate) elapsed: Duration,
    pub(crate) stage: Stage,
    limit: Duration,
}

impl OracleRun {
    /// The panic text for a run killed at the limit, carrying what it wrote.
    pub(crate) fn timeout_message(&self) -> String {
        format!(
            "signing oracle did not exit within {:?} (elapsed {:?}, stage {:?}); killed it; stderr: {:?}",
            self.limit, self.elapsed, self.stage, self.stderr
        )
    }
}

/// Run `command` with `input` on stdin and at most `limit` to take it and
/// exit. With `marker`, the limit starts once that text is in the oracle's
/// stderr, so start-up does not count; without, it starts at spawn. Stderr
/// goes to a named temporary file, read only through a fresh handle, so no
/// reader waits on a pipe a stalled child or a grandchild could hold open, and
/// what it wrote is kept even when the child is killed at the limit.
pub(crate) async fn run_oracle(
    mut command: tokio::process::Command,
    input: &[u8],
    limit: Duration,
    marker: Option<&'static str>,
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
        .unwrap_or_else(|error| {
            panic!("spawn: node is required for the independent signing oracle: {error}")
        });
    let mut stdin = Some(child.stdin.take().expect("oracle stdin"));
    // Stderr is read only through a fresh handle, whose file offset the
    // child never shares.
    let read_stderr = || {
        let mut file = named.reopen().expect("reopen oracle stderr");
        let mut stderr = String::new();
        let _ = file.read_to_string(&mut stderr);
        stderr
    };
    let started = match marker {
        None => spawned,
        Some(marker) => {
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
                if spawned.elapsed() >= MARKER_HANG_GUARD {
                    let _ = child.kill().await;
                    panic!(
                        "the oracle never wrote {marker:?} within {MARKER_HANG_GUARD:?} (hang guard); stderr: {stderr:?}"
                    );
                }
                // timing: precondition
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    };
    // One budget from `started`: a spawn slow enough to use it all is reported
    // as the spawn stage, not hidden by a timer that starts after it.
    let remaining = limit.saturating_sub(started.elapsed());
    let mut stage = Stage::Write;
    let run = tokio::time::timeout(remaining, async {
        // A child that exits before reading closes the pipe; its status says why.
        if let Some(mut stdin) = stdin.take() {
            let _ = stdin.write_all(input).await;
        }
        stage = Stage::Wait;
        child.wait().await
    });
    // `timeout` polls its future once before it checks the deadline, so an
    // already spent budget is answered here, before a write could move on.
    let finished = if remaining.is_zero() {
        drop(run);
        stage = Stage::Spawn;
        None
    } else {
        run.await.ok()
    };
    let status = if let Some(status) = finished {
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
        stage,
        limit,
    }
}

/// The real oracle: `node tests/common/signing_verifier.mjs`.
fn verifier() -> tokio::process::Command {
    let mut command = tokio::process::Command::new("node");
    command.arg(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/common/signing_verifier.mjs"),
    );
    command
}

/// The first `node` launch of this test binary, run once (MIK-8701.ORACLE.1).
/// Empty input makes the verifier load, fail to parse and exit: any status is
/// a warm runtime. Concurrent first callers wait on the one run; if the test
/// running it is torn down mid-run, the next caller runs it again.
async fn warm() {
    static WARM: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();
    WARM.get_or_init(|| async {
        let run = run_oracle(verifier(), b"", WARM_LIMIT, None).await;
        assert!(
            run.status.is_some(),
            "signing oracle warm-up: {}",
            run.timeout_message()
        );
        // Straight to the stderr handle, not `eprintln!`: libtest captures the
        // macro for a passing test, and CI must show the cold-start cost.
        let _ = writeln!(
            std::io::stderr(),
            "signing oracle warm-up took {:?}",
            run.elapsed
        );
    })
    .await;
}

/// Verify with the independent oracle: `input` is the verifier's JSON input
/// (`{"wire": .., "options": ..}`), `limit` the caller's per-verify bound,
/// which a cold first launch never counts against (MIK-8701).
pub(crate) async fn verify(input: &serde_json::Value, limit: Duration) -> OracleRun {
    warm().await;
    run_oracle(verifier(), input.to_string().as_bytes(), limit, None).await
}

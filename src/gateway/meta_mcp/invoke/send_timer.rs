// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The guard that times one backend send for the web UI's
//! latency history.
//!
//! Each leaf send (an MCP transport `tools/call`, a CLI capability's run, a
//! capability's HTTP request) starts one after every local step, so waits,
//! start-up and local refusals are never timed. It notes into the call's
//! [`DispatchNotes`](super::audit::DispatchNotes), where the count reads it:
//! one sample per counted call.

use std::time::{Duration, Instant};

use crate::counters::End;

/// Times one backend send. Finish it with how the send ended; drop it
/// unfinished and it notes [`End::Cancelled`] (the send future was dropped,
/// as a timeout wrapper drops it); [`SendTimer::discard`] notes nothing.
#[derive(Debug)]
pub(crate) struct SendTimer {
    started: Option<Instant>,
}

impl SendTimer {
    /// Start timing a send that is about to go out.
    pub(crate) fn start() -> Self {
        Self::start_if(true)
    }

    /// Start timing when `on` (a `tools/call` send); otherwise an inert
    /// timer that notes nothing.
    pub(crate) fn start_if(on: bool) -> Self {
        #[cfg(test)]
        if on {
            seam::note_start();
        }
        Self {
            started: on.then(Instant::now),
        }
    }

    /// Note how the send that returned `result` ended, and hand it back.
    pub(crate) fn finish_with<T>(self, result: crate::Result<T>) -> crate::Result<T> {
        self.finish(Self::end_of(&result));
        result
    }

    /// The send ended `end`: note its time. Notes at most once.
    pub(crate) fn finish(mut self, end: End) {
        if let Some(started) = self.started.take() {
            super::audit::note_backend(elapsed(started), end);
        }
    }

    /// Nothing reached the backend after all: note nothing.
    pub(crate) fn discard(mut self) {
        self.started = None;
    }

    /// How a send that returned `result` ended: an answer (a tool's
    /// `isError` included), the backend timeout, or any other failure.
    pub(crate) fn end_of<T>(result: &crate::Result<T>) -> End {
        match result {
            Ok(_) => End::Answered,
            Err(crate::Error::BackendTimeout(_)) => End::TimedOut,
            Err(_) => End::Failed,
        }
    }
}

impl Drop for SendTimer {
    fn drop(&mut self) {
        if let Some(started) = self.started.take() {
            super::audit::note_backend(elapsed(started), End::Cancelled);
        }
    }
}

/// The send's time: the injected test duration when a row set one.
fn elapsed(started: Instant) -> Duration {
    #[cfg(test)]
    if let Some(injected) = seam::injected() {
        return injected;
    }
    started.elapsed()
}

/// Rows set every send's time on this thread, so no row depends on a real
/// clock (the `drain_seam.rs` pattern). Production never compiles it.
#[cfg(test)]
pub(crate) mod seam {
    use std::cell::Cell;
    use std::time::Duration;

    thread_local! {
        static INJECTED: Cell<Option<Duration>> = const { Cell::new(None) };
        static STARTS: Cell<u64> = const { Cell::new(0) };
    }

    pub(super) fn note_start() {
        STARTS.with(|s| s.set(s.get() + 1));
    }

    /// Timers started on this thread so far: a row reads it before and
    /// after, so it can tell a wait that started no timer.
    pub(crate) fn starts() -> u64 {
        STARTS.with(Cell::get)
    }

    pub(super) fn injected() -> Option<Duration> {
        INJECTED.with(Cell::get)
    }

    /// Every send timed on this thread takes `elapsed` until [`clear`].
    pub(crate) fn inject(elapsed: Duration) {
        INJECTED.with(|i| i.set(Some(elapsed)));
    }

    pub(crate) fn clear() {
        INJECTED.with(|i| i.set(None));
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{SendTimer, seam};
    use crate::counters::End;
    use crate::gateway::meta_mcp::invoke::audit::with_dispatch_scope;

    /// Test plan row 28: a finished timer notes once; its drop notes nothing
    /// more. A timer dropped unfinished notes Cancelled.
    #[tokio::test]
    async fn timer_notes_at_most_once() {
        seam::inject(Duration::from_millis(7));
        let ((), notes) = with_dispatch_scope(async {
            SendTimer::start_if(true).finish(End::Answered);
        })
        .await;
        assert_eq!(
            notes.backend_sample(),
            Some((Duration::from_millis(7), End::Answered))
        );
        let ((), notes) = with_dispatch_scope(async {
            drop(SendTimer::start());
        })
        .await;
        assert_eq!(
            notes.backend_sample(),
            Some((Duration::from_millis(7), End::Cancelled))
        );
        let ((), notes) = with_dispatch_scope(async {
            SendTimer::start_if(false).finish(End::Answered);
            SendTimer::start().discard();
        })
        .await;
        seam::clear();
        assert_eq!(
            notes.backend_sample(),
            None,
            "inert and discarded timers note nothing"
        );
    }

    /// Test plan row 26: a call's rounds (a bridged retry) add up into one
    /// sample; the last round's end is the call's.
    #[tokio::test]
    async fn a_calls_rounds_sum_into_one_sample() {
        let ((), notes) = with_dispatch_scope(async {
            seam::inject(Duration::from_millis(30));
            SendTimer::start().finish(End::TimedOut);
            seam::inject(Duration::from_millis(12));
            SendTimer::start().finish(End::Answered);
        })
        .await;
        seam::clear();
        assert_eq!(
            notes.backend_sample(),
            Some((Duration::from_millis(42), End::Answered))
        );
    }
}

/// Test plan row 30: every leaf backend send sits in a timed scope, and no
/// timer wraps the capability dispatch branch (that would time a send twice).
#[cfg(test)]
mod send_site_scan {
    use std::path::{Path, PathBuf};

    use crate::test_source_text::production_text;

    /// Every `.rs` file under `dir`, recursively.
    fn rust_files(dir: &Path) -> Vec<PathBuf> {
        let mut files = Vec::new();
        let mut dirs = vec![dir.to_path_buf()];
        while let Some(dir) = dirs.pop() {
            for entry in std::fs::read_dir(&dir).expect("a scanned directory") {
                let path = entry.expect("entry").path();
                if path.is_dir() {
                    dirs.push(path);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    files.push(path);
                }
            }
        }
        files
    }

    /// The send primitives each tree may call only from its timed file.
    const SITES: [(&str, &[&str], &str); 2] = [
        (
            "src/backend",
            &[".request_with_headers(", ".request_with_task_capability("],
            "src/backend/ops/attempt.rs",
        ),
        (
            "src/capability/executor",
            &[".send().await", "client.execute("],
            "src/capability/executor/client.rs",
        ),
    ];

    /// Sends that are never a `tools/call`, so never a call's latency: the
    /// era discovery probe and the catalogue list drain.
    const UNTIMED: [(&str, &str); 2] = [
        (
            "src/backend/era.rs",
            "the era probe (DISCOVER_METHOD), never a tools/call",
        ),
        (
            "src/backend/list_drain.rs",
            "catalogue list pages, never a tools/call",
        ),
    ];

    /// Violations in `(relative path, production text)` pairs: a primitive
    /// outside its timed file, a timed file without a timer, a CLI run that
    /// is not timed, or a timer around the capability dispatch branch.
    fn violations(files: &[(String, String)]) -> Vec<String> {
        let mut found = Vec::new();
        for (tree, primitives, timed) in SITES {
            for (path, text) in files.iter().filter(|(p, _)| p.starts_with(tree)) {
                for primitive in primitives {
                    let untimed = UNTIMED.iter().any(|(p, _)| p == path);
                    if text.contains(primitive) && path != timed && !untimed {
                        found.push(format!("{path}: {primitive} outside {timed}"));
                    }
                }
                if path == timed && !text.contains("SendTimer::start") {
                    found.push(format!("{path}: the timed send file starts no SendTimer"));
                }
            }
        }
        for (path, text) in files {
            if path == "src/capability/executor/cli_run.rs" {
                let spawn = text.find("wrap.spawn()");
                let timer = text.find("SendTimer::start()");
                if !matches!((spawn, timer), (Some(s), Some(t)) if s < t)
                    || !text.contains("timer.finish_with(")
                {
                    found.push(format!("{path}: the CLI run is not timed after its spawn"));
                }
            }
            if path == "src/capability/executor/mod.rs" && text.contains("SendTimer") {
                found.push(format!(
                    "{path}: a timer around the dispatch branch times a send twice"
                ));
            }
        }
        found
    }

    #[test]
    fn every_send_has_a_timer() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut files = Vec::new();
        for tree in ["src/backend", "src/capability/executor"] {
            for path in rust_files(&root.join(tree)) {
                let rel = path
                    .strip_prefix(root)
                    .expect("under the root")
                    .to_string_lossy()
                    .replace('\\', "/");
                // Test files and test-module directories (`*_tests.rs`,
                // `*_tests/`, `tests/`) are not production sends.
                let test_only = rel.split('/').any(|part| {
                    part == "tests" || part.ends_with("_tests") || part.ends_with("_tests.rs")
                });
                if test_only {
                    continue;
                }
                let text = production_text(&std::fs::read_to_string(&path).expect("readable"));
                files.push((rel, text));
            }
        }
        assert!(files.len() > 10, "the scan read the trees: {}", files.len());
        let found = violations(&files);
        assert!(found.is_empty(), "{found:#?}");
    }

    /// The scanner names a planted untimed send and a timer on the branch.
    #[test]
    fn the_scan_names_planted_violations() {
        let files = vec![
            (
                "src/backend/ops/attempt.rs".to_owned(),
                "SendTimer::start_if(x); t.request_with_headers(a)".to_owned(),
            ),
            (
                "src/backend/new_path.rs".to_owned(),
                "transport.request_with_headers(a)".to_owned(),
            ),
            (
                "src/capability/executor/mod.rs".to_owned(),
                "let t = SendTimer::start();".to_owned(),
            ),
            (
                "src/capability/executor/client.rs".to_owned(),
                "SendTimer::start(); r.send().await".to_owned(),
            ),
            (
                "src/capability/executor/cli_run.rs".to_owned(),
                "wrap.spawn(); SendTimer::start(); timer.finish_with(r)".to_owned(),
            ),
        ];
        let found = violations(&files);
        assert_eq!(found.len(), 2, "{found:#?}");
        assert!(found[0].contains("new_path.rs"), "{found:#?}");
        assert!(found[1].contains("executor/mod.rs"), "{found:#?}");
    }
}

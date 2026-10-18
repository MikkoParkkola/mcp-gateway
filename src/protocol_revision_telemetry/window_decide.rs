// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! U1 v2 decision: the sealed prefix of clean HTTP segments, judged against
//! the operator's declaration. Test-only: the operator runs it through the
//! ignored `u1_production_decision` row, so it adds no public surface.

use std::fmt::Write as _;
use std::io;
use std::time::Duration;

use super::window::{Segment, WindowV2, load, window_paths};
use super::{RetirementBlocked, Snapshot, Transport, distribution_table, retire_revisions};

/// Milliseconds allowed between one segment's seal and the next start.
pub(crate) const RESTART_BUDGET_MS: u64 = 300_000;

/// The operator's declaration. Provenance comes from here, never the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Declaration {
    pub(crate) population: Vec<Transport>,
    pub(crate) listen: String,
    pub(crate) exe_prefix: String,
}

/// Why the v2 window cannot certify a decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WindowBlocked {
    Retirement(RetirementBlocked),
    PopulationMismatch,
    UncleanSegment,
    ConcurrentHttpWriters,
    ForeignWriter,
    CoverageGap,
    NoSealedSegment,
}

/// The sealed span a decision was computed over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SealedSpan {
    pub(crate) started_at: u64,
    pub(crate) ended_at_ms: u64,
    pub(crate) segments: usize,
    pub(crate) snapshot: Snapshot,
}

/// Evaluate the sealed prefix of clean HTTP segments against `declaration`.
pub(crate) fn decide(
    window: &WindowV2,
    declaration: &Declaration,
) -> (Option<SealedSpan>, Result<Vec<String>, WindowBlocked>) {
    let span = sealed_span(window);
    let outcome = gate(window, declaration, span.as_ref());
    (span, outcome)
}

fn sealed_span(window: &WindowV2) -> Option<SealedSpan> {
    let sealed: Vec<&Segment> = window
        .http_segments
        .iter()
        .take_while(|segment| segment.closed_cleanly)
        .collect();
    let (first, last) = (sealed.first()?, sealed.last()?);
    let mut snapshot = Snapshot::default();
    for segment in &sealed {
        // Every counter sum was checked on read, so saturating only guards
        // arithmetic that validation already bounded.
        add_saturating(&mut snapshot, &segment.snapshot);
    }
    Some(SealedSpan {
        started_at: first.opened_at,
        ended_at_ms: last.sealed_at_ms?,
        segments: sealed.len(),
        snapshot,
    })
}

fn gate(
    window: &WindowV2,
    declaration: &Declaration,
    span: Option<&SealedSpan>,
) -> Result<Vec<String>, WindowBlocked> {
    if declaration.population != [Transport::Http] || window.stdio.total > 0 {
        return Err(WindowBlocked::PopulationMismatch);
    }
    let segments = &window.http_segments;
    if segments.iter().any(|segment| {
        segment.listen != declaration.listen || !segment.exe.starts_with(&declaration.exe_prefix)
    }) {
        return Err(WindowBlocked::ForeignWriter);
    }
    // Only the newest segment may be unclosed: it is outside the span.
    let clean_prefix = segments.iter().take_while(|s| s.closed_cleanly).count();
    if clean_prefix + 1 < segments.len() {
        return Err(WindowBlocked::UncleanSegment);
    }
    for pair in segments.windows(2) {
        // A clean predecessor always has its seal time (validated on read).
        let Some(sealed_ms) = pair[0].sealed_at_ms else {
            return Err(WindowBlocked::UncleanSegment);
        };
        if pair[1].process_started_at_ms < sealed_ms {
            return Err(WindowBlocked::ConcurrentHttpWriters);
        }
        if pair[1].process_started_at_ms - sealed_ms > RESTART_BUDGET_MS {
            return Err(WindowBlocked::CoverageGap);
        }
    }
    let span = span.ok_or(WindowBlocked::NoSealedSegment)?;
    if span.snapshot.total == 0 {
        return Err(WindowBlocked::PopulationMismatch);
    }
    let elapsed_ms = span
        .ended_at_ms
        .saturating_sub(span.started_at.saturating_mul(1_000));
    retire_revisions(&span.snapshot, Duration::from_millis(elapsed_ms))
        .map_err(WindowBlocked::Retirement)
}

fn add_saturating(target: &mut Snapshot, delta: &Snapshot) {
    for (into, from) in [
        (&mut target.by_revision, &delta.by_revision),
        (&mut target.by_client, &delta.by_client),
        (&mut target.by_transport, &delta.by_transport),
    ] {
        for (key, value) in from {
            let entry = into.entry(key.clone()).or_insert(0);
            *entry = entry.saturating_add(*value);
        }
    }
    target.unattributed = target.unattributed.saturating_add(delta.unattributed);
    target.total = target.total.saturating_add(delta.total);
}

/// Parse the operator's declaration. Every value is required; `~` is not
/// expanded, so the prefix must be absolute.
pub(crate) fn parse_declaration(
    population: Option<&str>,
    listen: Option<&str>,
    exe_prefix: Option<&str>,
) -> io::Result<Declaration> {
    let population = match required(population, "U1_POPULATION")?.as_str() {
        "http" => vec![Transport::Http],
        other => {
            return Err(invalid_input(format!(
                "U1_POPULATION={other}: only `http` can be certified"
            )));
        }
    };
    let listen = required(listen, "U1_LISTEN")?;
    listen
        .parse::<std::net::SocketAddr>()
        .map_err(|error| invalid_input(format!("U1_LISTEN: {error}")))?;
    let exe_prefix = required(exe_prefix, "U1_EXE_PREFIX")?;
    if !std::path::Path::new(&exe_prefix).is_absolute() {
        return Err(invalid_input(
            "U1_EXE_PREFIX must be an absolute path".to_string(),
        ));
    }
    Ok(Declaration {
        population,
        listen,
        exe_prefix,
    })
}

fn required(value: Option<&str>, name: &str) -> io::Result<String> {
    value
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string)
        .ok_or_else(|| invalid_input(format!("{name} is required")))
}

fn invalid_input(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

/// The operator's command, fully qualified so `--exact` selects one test:
/// `cargo test --lib <this> -- --ignored --exact --nocapture`, with
/// `U1_DATA_DIR`, `U1_POPULATION=http`, `U1_LISTEN` and `U1_EXE_PREFIX`.
/// The runbook checks the output says `1 passed`.
pub(crate) const OPERATOR_TEST: &str =
    "protocol_revision_telemetry::window_decide::tests::u1_production_decision";

/// Run the decision for the operator: read the declaration and the window
/// named by `env`, write `decision.json` beside the window, and return the
/// printed report (distribution table, per-writer list, span, outcome).
pub(crate) fn run_operator(env: &dyn Fn(&str) -> Option<String>) -> io::Result<String> {
    let data_dir = required(env("U1_DATA_DIR").as_deref(), "U1_DATA_DIR")?;
    let declaration = parse_declaration(
        env("U1_POPULATION").as_deref(),
        env("U1_LISTEN").as_deref(),
        env("U1_EXE_PREFIX").as_deref(),
    )?;
    let data_dir = std::path::Path::new(&data_dir);
    let window = load(data_dir)?;
    let (span, outcome) = decide(&window, &declaration);
    let mut report = String::new();
    for segment in &window.http_segments {
        writeln!(
            report,
            "writer listen={} exe={} started_ms={} sealed_ms={:?} clean={}",
            segment.listen,
            segment.exe,
            segment.process_started_at_ms,
            segment.sealed_at_ms,
            segment.closed_cleanly
        )
        .expect("writing to a String cannot fail");
    }
    if let Some(span) = &span {
        report.push_str(&distribution_table(&span.snapshot));
        writeln!(
            report,
            "span opened_at={} sealed_at_ms={} segments={}",
            span.started_at, span.ended_at_ms, span.segments
        )
        .expect("writing to a String cannot fail");
    }
    let (retire, blocked) = match &outcome {
        Ok(retire) => (retire.clone(), None),
        Err(blocked) => (Vec::new(), Some(blocked_label(*blocked))),
    };
    writeln!(report, "decision retire={retire:?} blocked={blocked:?}")
        .expect("writing to a String cannot fail");
    let decision = serde_json::json!({ "retire": retire, "blocked": blocked });
    let path = window_paths(data_dir).0.with_file_name("decision.json");
    let bytes = serde_json::to_vec_pretty(&decision)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    std::fs::write(path, bytes)?;
    Ok(report)
}

fn blocked_label(blocked: WindowBlocked) -> String {
    match blocked {
        WindowBlocked::Retirement(reason) => format!("{reason:?}"),
        other => format!("{other:?}"),
    }
}

#[cfg(test)]
#[path = "window_decide_tests.rs"]
mod tests;

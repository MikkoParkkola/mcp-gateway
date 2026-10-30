// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The text log layer's escape: every way a value reaches a text line keeps
//! a forged line out (LOGINJ.2), a normal line is unchanged (LOGINJ.4), the
//! JSON layer is untouched (LOGINJ.5), and no production text layer is built
//! any other way (LOGINJ.6).

use std::sync::{Arc, Mutex};

use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt as _;

use super::escaping;

/// The probe value: a newline that starts a forged line, and an ESC that
/// would erase it on a terminal.
const PROBE: &str = "mtls:runner\n2026-10-28T12:00:00Z  WARN forged: admin granted\x1b[2K";

/// Collects what the layer writes.
#[derive(Clone, Default)]
struct Buf(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Buf {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("buffer").extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Buf {
    type Writer = Self;
    fn make_writer(&'a self) -> Self {
        self.clone()
    }
}

impl Buf {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().expect("buffer").clone()).expect("utf-8")
    }
}

/// What the production text layer writes for `emit`, colours on or off.
fn text(ansi: bool, emit: impl FnOnce()) -> String {
    crate::test_log_capture::keep_interest_open();
    let buf = Buf::default();
    let layer = escaping(
        tracing_subscriber::fmt::layer()
            .with_ansi(ansi)
            .with_writer(buf.clone()),
    );
    tracing::subscriber::with_default(tracing_subscriber::registry().with(layer), emit);
    buf.text()
}

/// One event wrote exactly one line, with no raw CR anywhere and, with
/// colours off, no raw ESC.
fn assert_one_line(out: &str, ansi: bool) {
    assert_eq!(out.matches('\n').count(), 1, "more than one line: {out:?}");
    assert!(out.ends_with('\n'), "{out:?}");
    assert!(!out.contains('\r'), "{out:?}");
    if !ansi {
        assert!(!out.contains('\x1b'), "{out:?}");
    }
}

/// Both colour settings, as production may run either.
fn each_ansi(row: impl Fn(bool) -> String) {
    for ansi in [false, true] {
        assert_one_line(&row(ansi), ansi);
    }
}

#[test]
fn a_display_field_stays_on_one_line() {
    each_ansi(|ansi| text(ansi, || tracing::warn!(agent = %PROBE, "denied")));
    let out = text(false, || tracing::warn!(agent = %PROBE, "denied"));
    assert!(out.contains(r"mtls:runner\n2026"), "{out:?}");
    assert!(out.contains(r"\u{1b}[2K"), "{out:?}");
}

#[test]
fn an_error_display_field_stays_on_one_line() {
    each_ansi(|ansi| {
        let e = std::io::Error::other(PROBE);
        text(ansi, || tracing::warn!(error = %e, "send failed"))
    });
}

/// An error with a source, recorded as an error: the library writes its
/// source chain too.
#[derive(Debug)]
struct Chained(std::io::Error);

impl std::fmt::Display for Chained {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "outer {PROBE}")
    }
}

impl std::error::Error for Chained {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

#[test]
fn an_error_with_a_source_stays_on_one_line() {
    each_ansi(|ansi| {
        let e = Chained(std::io::Error::other(PROBE));
        text(ansi, || {
            tracing::warn!(error = &e as &(dyn std::error::Error + 'static), "failed");
        })
    });
}

#[test]
fn a_formatted_message_stays_on_one_line() {
    each_ansi(|ansi| text(ansi, || tracing::warn!("refused {PROBE}")));
}

#[test]
fn a_plain_str_message_stays_on_one_line() {
    each_ansi(|ansi| text(ansi, || tracing::warn!(message = PROBE)));
}

#[test]
fn a_field_recorded_later_on_a_span_stays_on_one_line() {
    each_ansi(|ansi| {
        text(ansi, || {
            let span = tracing::info_span!("call", agent = tracing::field::Empty);
            span.record("agent", tracing::field::display(PROBE));
            span.in_scope(|| tracing::warn!("inside"));
        })
    });
}

/// Every C0 control, DEL, every C1 control, the line and paragraph
/// separators and the bidirectional controls.
fn hostile_chars() -> impl Iterator<Item = char> {
    (0u32..0x20)
        .chain(0x7f..=0x9f)
        .chain([0x2028, 0x2029, 0x200e, 0x200f, 0x061c])
        .chain(0x202a..=0x202e)
        .chain(0x2066..=0x2069)
        .map(|c| char::from_u32(c).expect("a char"))
}

#[test]
fn every_hostile_character_is_escaped() {
    for c in hostile_chars() {
        let value = format!("a{c}b");
        let e = Chained(std::io::Error::other(value.clone()));
        for out in [
            text(false, || tracing::warn!(v = %value, "x")),
            text(false, || tracing::warn!("refused {value}")),
            text(false, || tracing::warn!(message = value.as_str())),
            text(false, || {
                tracing::warn!(error = &e as &(dyn std::error::Error + 'static), "x");
            }),
        ] {
            assert_one_line(&out, false);
            let body = out.strip_suffix('\n').expect("a terminated line");
            assert!(!body.contains(c), "{:#x} written raw: {out:?}", c as u32);
        }
    }
}

/// A `log`-crate record from a dependency: its target is written outside
/// the field formatter, so only the writer can keep it out. With colours on,
/// the formatter's own colour codes stay; the target's erase code does not.
#[test]
fn a_bridged_log_record_with_a_hostile_target_stays_on_one_line() {
    // Installed once per process; a second install is refused and harmless.
    let _ = tracing_log::LogTracer::init();
    for target in [PROBE.to_owned(), format!("{PROBE}\n")] {
        for ansi in [false, true] {
            let out = text(ansi, || {
                log::logger().log(
                    &log::Record::builder()
                        .level(log::Level::Warn)
                        .target(&target)
                        .args(format_args!("from a dependency"))
                        .build(),
                );
            });
            assert_one_line(&out, ansi);
            assert!(!out.contains("\x1b[2K"), "{out:?}");
        }
    }
}

/// What `layer` writes for `emit`.
fn written<L>(layer: L, buf: &Buf, emit: impl FnOnce()) -> String
where
    L: tracing_subscriber::Layer<tracing_subscriber::Registry> + Send + Sync + 'static,
{
    crate::test_log_capture::keep_interest_open();
    tracing::subscriber::with_default(tracing_subscriber::registry().with(layer), emit);
    buf.text()
}

/// A clean error with a source.
#[derive(Debug)]
struct Refused(std::io::Error);

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("upstream refused \"read\" (code 7)")
    }
}

impl std::error::Error for Refused {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

/// A normal event: every field kind, an error with a source, a span field.
fn normal_event() {
    let e = Refused(std::io::Error::other("connection reset"));
    let span = tracing::info_span!("call", server = "alpha", attempt = 2_u32);
    span.in_scope(|| {
        tracing::warn!(
            backend = %"alpha",
            tool = "read",
            args = ?vec![1, 2],
            latency_ms = 12_u64,
            cached = false,
            error = &e as &(dyn std::error::Error + 'static),
            "call failed: {}",
            "retry later",
        );
    });
}

/// LOGINJ.4: a normal line is byte-identical to the library's own output,
/// colours on and off.
#[test]
fn a_normal_line_is_unchanged() {
    for ansi in [false, true] {
        let (ours, theirs) = (Buf::default(), Buf::default());
        let escaped = written(
            escaping(
                tracing_subscriber::fmt::layer()
                    .without_time()
                    .with_ansi(ansi)
                    .with_writer(ours.clone()),
            ),
            &ours,
            normal_event,
        );
        let plain = written(
            tracing_subscriber::fmt::layer()
                .without_time()
                .with_ansi(ansi)
                .with_writer(theirs.clone()),
            &theirs,
            normal_event,
        );
        assert_eq!(escaped, plain, "ansi {ansi}");
    }
}

/// LOGINJ.5: the JSON layer is not wrapped, and JSON encoding keeps the probe
/// value on one line.
#[test]
fn the_json_layer_keeps_the_probe_on_one_line() {
    let buf = Buf::default();
    let out = written(
        tracing_subscriber::fmt::layer()
            .json()
            .with_writer(buf.clone()),
        &buf,
        || tracing::warn!(agent = %PROBE, "denied"),
    );
    assert_one_line(&out, false);
    let lib = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs"))
        .expect("lib.rs");
    assert!(
        lib.contains(".with(fmt::layer().json().with_writer(std::io::stderr))"),
        "the JSON layer changed"
    );
}

/// Spellings that build or install a subscriber or a text layer.
const BUILDS: &[&str] = &[
    "fmt::layer(",
    "fmt::Layer::",
    "tracing_subscriber::fmt(",
    "FmtSubscriber",
    "SubscriberBuilder",
    "subscriber::set_global_default(",
    "subscriber::with_default(",
    "subscriber::set_default(",
    "LogTracer::",
];

/// Test-only code, which may build its own capture layers (lead ruling): any
/// `*_tests.rs` file or `*_tests/` and `tests/` directory, this module's own
/// rows, and the named helpers: `src/test_log_capture.rs`, `src/test_support/`
/// (`error_capture.rs`, `interest.rs`), the `#[cfg(test)] mod log_capture` in
/// `src/gateway/session_id.rs`, and the other branch's capture in
/// `src/capability/backend_rug_pull_tests.rs` (covered by the `_tests.rs` rule).
fn test_only(rel: &str) -> bool {
    rel.ends_with("_tests.rs")
        || rel.contains("_tests/")
        || rel.contains("/tests/")
        || rel == "src/test_log_capture.rs"
        || rel.starts_with("src/test_support/")
}

fn rust_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// LOGINJ.6: production code builds a text layer or installs a subscriber
/// only in `setup_tracing`, and its text layer goes through `escaping`, so
/// no production text layer can bypass the escape.
#[test]
fn every_production_text_layer_goes_through_escaping() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rust_files(&root.join("src"), &mut files);
    rust_files(&root.join("crates"), &mut files);
    let mut stray = Vec::new();
    for path in files {
        let rel = path
            .strip_prefix(root)
            .expect("under the root")
            .to_string_lossy()
            .replace('\\', "/");
        if test_only(&rel) || rel == "src/lib.rs" {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("readable");
        // session_id.rs: only its `#[cfg(test)] mod log_capture` builds one.
        let text = match rel.as_str() {
            "src/gateway/session_id.rs" => text
                .split("mod log_capture")
                .next()
                .unwrap_or_default()
                .to_owned(),
            _ => text,
        };
        stray.extend(
            BUILDS
                .iter()
                .filter(|spelling| text.contains(*spelling))
                .map(|spelling| format!("{rel}: {spelling}")),
        );
    }
    assert!(stray.is_empty(), "built outside setup_tracing: {stray:?}");

    let lib = std::fs::read_to_string(root.join("src/lib.rs")).expect("lib.rs");
    for (at, _) in lib.match_indices("fmt::layer()") {
        let before = &lib[at.saturating_sub(80)..at];
        let after = &lib[at..];
        assert!(
            after.starts_with("fmt::layer().json()") || before.contains("log_escape::escaping("),
            "a text layer in lib.rs bypasses escaping: {}",
            &lib[at..(at + 60).min(lib.len())]
        );
    }
}

/// LOGINJ.3, rug-pull site: a changed capability file whose name carries the
/// probe is logged as one line. Holds with this escape alone, whatever name
/// the site logs.
#[tokio::test]
async fn a_changed_capability_name_cannot_forge_a_rug_pull_line() {
    use crate::capability::{
        CapabilityBackend, CapabilityExecutor, compute_capability_hash, rewrite_with_pin,
    };
    crate::test_log_capture::keep_interest_open();

    let body = "name: rugtest\ndescription: legit\nproviders:\n  primary:\n    service: rest\n    config:\n      base_url: https://caps.invalid\n      path: /v1\n";
    let pinned = rewrite_with_pin(body, &compute_capability_hash(body));
    let hostile = serde_json::to_string(PROBE).expect("a quoted name");
    for ansi in [false, true] {
        // A fresh directory and backend per mode: a detection unloads it.
        let dir = tempfile::TempDir::new().expect("a directory");
        let path = dir.path().join("rugtest.yaml");
        std::fs::write(&path, &pinned).expect("written");
        let backend = CapabilityBackend::new("caps", Arc::new(CapabilityExecutor::new()));
        backend
            .load_from_directory(dir.path().to_str().expect("utf-8"))
            .await
            .expect("loaded");
        std::fs::write(
            &path,
            pinned.replace("name: rugtest", &format!("name: {hostile}")),
        )
        .expect("tampered");

        let buf = Buf::default();
        let layer = escaping(
            tracing_subscriber::fmt::layer()
                .with_ansi(ansi)
                .with_writer(buf.clone()),
        );
        let guard = tracing::subscriber::set_default(tracing_subscriber::registry().with(layer));
        let detected = backend.detect_rug_pulls().await;
        drop(guard);
        let out = buf.text();
        assert!(!detected.is_empty(), "no rug pull detected (ansi {ansi})");
        assert!(out.contains("RUG-PULL DETECTED"), "{out:?}");
        // Other events may log here too, so the row asserts what forging
        // needs: no line starts with the planted text, and no erase code.
        assert!(
            !out.lines()
                .any(|l| l.starts_with("2026-10-28T12:00:00Z  WARN forged")),
            "a forged line: {out:?}"
        );
        assert!(!out.contains("\x1b[2K") && !out.contains('\r'), "{out:?}");
    }
}

/// The accepted residual, shown exactly that narrow: with colours on, the
/// writer lets a colour code (`ESC [ digits ; m`) in a bridged target
/// through, since the formatter writes the same codes; a clear-screen
/// (`ESC[2J`) beside it is still escaped.
#[test]
fn only_a_colour_code_in_a_bridged_target_passes_the_writer() {
    let _ = tracing_log::LogTracer::init();
    let target = "dep\x1b[31mred\x1b[2Jcleared";
    let out = text(true, || {
        log::logger().log(
            &log::Record::builder()
                .level(log::Level::Warn)
                .target(target)
                .args(format_args!("from a dependency"))
                .build(),
        );
    });
    assert_one_line(&out, true);
    assert!(
        out.contains("dep\x1b[31mred"),
        "the colour code was escaped: {out:?}"
    );
    assert!(
        out.contains(r"\u{1b}[2Jcleared"),
        "the clear-screen passed: {out:?}"
    );
    assert!(!out.contains("\x1b[2J"), "{out:?}");
}

/// The library writes a `%` value raw, and the writer lets a colour code
/// through, so only the field formatter keeps a value from recolouring the
/// line: a colour code in a field value is escaped.
#[test]
fn a_field_value_cannot_add_a_colour() {
    for ansi in [false, true] {
        let out = text(
            ansi,
            || tracing::warn!(agent = %"mtls:\x1b[31mred", "denied"),
        );
        assert_one_line(&out, ansi);
        assert!(!out.contains("\x1b[31mred"), "{out:?}");
        assert!(out.contains(r"\u{1b}[31mred"), "{out:?}");
    }
}

/// The writer lets through only the colour codes the formatter itself
/// writes: a bridged target cannot conceal what follows it.
#[test]
fn a_bridged_target_cannot_conceal_text() {
    let _ = tracing_log::LogTracer::init();
    for ansi in [false, true] {
        let out = text(ansi, || {
            log::logger().log(
                &log::Record::builder()
                    .level(log::Level::Warn)
                    .target("dep\x1b[8mhidden")
                    .args(format_args!("from a dependency"))
                    .build(),
            );
        });
        assert_one_line(&out, ansi);
        assert!(!out.contains("\x1b[8m"), "{out:?}");
    }
}

/// The message and an error rely on the library's own escape, which a base
/// layer can switch off: `escaping` switches it back on, so neither can add
/// a colour.
#[test]
fn a_message_or_an_error_cannot_add_a_colour() {
    let e = Chained(std::io::Error::other("cause \x1b[31mred"));
    for ansi in [false, true] {
        let buf = Buf::default();
        let layer = escaping(
            tracing_subscriber::fmt::layer()
                .with_ansi_sanitization(false)
                .with_ansi(ansi)
                .with_writer(buf.clone()),
        );
        let out = written(layer, &buf, || {
            tracing::warn!(message = "plain \x1b[31mred");
            tracing::warn!("formatted \x1b[31mred");
            tracing::warn!(error = &e as &(dyn std::error::Error + 'static), "x");
        });
        assert_eq!(out.matches('\n').count(), 3, "{out:?}");
        assert!(!out.contains("\x1b[31mred"), "{out:?}");
    }
}

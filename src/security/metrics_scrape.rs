// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The Prometheus metrics as a test reads them: a recorder local to the
//! test and its rendered text, one reader for every test tree.

/// Run `f` with a recorder scoped to this thread; return its output and the
/// Prometheus text. A per-test recorder: the global one is shared across
/// parallel tests and would make every delta flake.
pub(crate) fn scrape<F: std::future::Future>(f: F) -> (F::Output, String) {
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let out = telemetry_metrics::with_local_recorder(&recorder, || {
        tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(f))
    });
    (out, handle.render())
}

/// Sample lines of `name`: `# HELP`/`# TYPE` lines never start with it.
pub(crate) fn samples<'a>(rendered: &'a str, name: &str) -> impl Iterator<Item = &'a str> {
    let prefix = format!("{name}{{");
    rendered.lines().filter(move |l| l.starts_with(&prefix))
}

/// A sample's value. The exposition format writes numbers as floats.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn value(line: &str) -> u64 {
    let v: f64 = line
        .rsplit(' ')
        .next()
        .unwrap_or_default()
        .parse()
        .expect("sample value");
    v as u64
}

/// The value of the `name` series carrying every `k="v"` pair in `labels`
/// (comma separated, in any order), 0 when absent.
pub(crate) fn series(rendered: &str, name: &str, labels: &str) -> u64 {
    samples(rendered, name)
        .find(|l| labels.split(',').all(|pair| l.contains(pair)))
        .map_or(0, value)
}

/// Sum of every `name` sample whose line contains `needle`.
pub(crate) fn sum_where(rendered: &str, name: &str, needle: &str) -> u64 {
    samples(rendered, name)
        .filter(|l| l.contains(needle))
        .map(value)
        .sum()
}

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The Prometheus metrics as a test reads them: a recorder local to the
//! test and its rendered text, one reader for every test tree.

#[cfg(feature = "metrics")]
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

#[cfg(feature = "metrics")]
/// Sample lines of `name`: `# HELP`/`# TYPE` lines never start with it.
pub(crate) fn samples<'a>(rendered: &'a str, name: &str) -> impl Iterator<Item = &'a str> {
    let prefix = format!("{name}{{");
    rendered.lines().filter(move |l| l.starts_with(&prefix))
}

#[cfg(feature = "metrics")]
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

#[cfg(feature = "metrics")]
/// The value of the `name` series carrying every `k="v"` pair in `labels`
/// (comma separated, in any order), 0 when absent.
pub(crate) fn series(rendered: &str, name: &str, labels: &str) -> u64 {
    samples(rendered, name)
        .find(|l| labels.split(',').all(|pair| l.contains(pair)))
        .map_or(0, value)
}

#[cfg(feature = "metrics")]
/// Sum of every `name` sample whose line contains `needle`.
pub(crate) fn sum_where(rendered: &str, name: &str, needle: &str) -> u64 {
    samples(rendered, name)
        .filter(|l| l.contains(needle))
        .map(value)
        .sum()
}

/// The rendered metrics `f` raised, where the build has an exporter; `None`
/// without the `metrics` feature, so only a row's metric assert is skipped
/// there and the rest of the row still runs. Needs a multi-thread runtime.
#[cfg(feature = "metrics")]
pub(crate) fn scrape_if_enabled<F: std::future::Future>(f: F) -> (F::Output, Option<String>) {
    let (out, text) = scrape(f);
    (out, Some(text))
}

#[cfg(not(feature = "metrics"))]
pub(crate) fn scrape_if_enabled<F: std::future::Future>(f: F) -> (F::Output, Option<String>) {
    let out = tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(f));
    (out, None)
}

/// The meta route's refusals D4 counted under `reason` in `text`, as
/// [`scrape_if_enabled`] returned it: `None` where the build has no exporter.
#[cfg(feature = "metrics")]
pub(crate) fn meta_denials(text: Option<&str>, reason: &str) -> Option<u64> {
    let labels = format!(r#"route="meta",reason="{reason}""#);
    text.map(|text| series(text, "mcp_authz_denials_total", &labels))
}

#[cfg(not(feature = "metrics"))]
pub(crate) fn meta_denials(_text: Option<&str>, _reason: &str) -> Option<u64> {
    None
}

/// What [`meta_denials`] reads for one refusal in this build.
pub(crate) const ONE_DENIAL: Option<u64> = if cfg!(feature = "metrics") {
    Some(1)
} else {
    None
};

/// Every refusal D4 counted on `route` (`meta` or `direct`) in `text`, whatever
/// its reason, as [`scrape_if_enabled`] returned it: `None` where the build has
/// no exporter.
#[cfg(feature = "metrics")]
pub(crate) fn route_denials(text: Option<&str>, route: &str) -> Option<u64> {
    let needle = format!(r#"route="{route}""#);
    text.map(|text| sum_where(text, "mcp_authz_denials_total", &needle))
}

#[cfg(not(feature = "metrics"))]
pub(crate) fn route_denials(_text: Option<&str>, _route: &str) -> Option<u64> {
    None
}

/// What [`route_denials`] reads for a call D4 did not count, in this build.
pub(crate) const NO_DENIAL: Option<u64> = if cfg!(feature = "metrics") {
    Some(0)
} else {
    None
};

/// [`route_denials`] and, of those, the ones D4 counted under `reason`:
/// `(all, under reason)`; `None` where the build has no exporter.
#[cfg(feature = "metrics")]
pub(crate) fn route_denials_as(
    text: Option<&str>,
    route: &str,
    reason: &str,
) -> Option<(u64, u64)> {
    let labels = format!(r#"route="{route}",reason="{reason}""#);
    let under = text.map(|text| series(text, "mcp_authz_denials_total", &labels));
    route_denials(text, route).zip(under)
}

#[cfg(not(feature = "metrics"))]
pub(crate) fn route_denials_as(
    _text: Option<&str>,
    _route: &str,
    _reason: &str,
) -> Option<(u64, u64)> {
    None
}

/// What [`route_denials_as`] reads for one refusal under the asked reason.
pub(crate) const ONE_DENIAL_AS: Option<(u64, u64)> = if cfg!(feature = "metrics") {
    Some((1, 1))
} else {
    None
};

/// What [`route_denials_as`] reads for a call D4 did not count.
pub(crate) const NO_DENIAL_AS: Option<(u64, u64)> = if cfg!(feature = "metrics") {
    Some((0, 0))
} else {
    None
};

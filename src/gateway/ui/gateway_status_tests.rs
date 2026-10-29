// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The environment block's choice of name: configured, host, or default.

use super::{EnvironmentSource, environment};

#[test]
fn environment_prefers_the_configured_name() {
    let (name, source) = environment(Some("prod-eu"), Some("host-1"));
    assert_eq!(
        (name.as_str(), source),
        ("prod-eu", EnvironmentSource::Config)
    );
}

#[test]
fn environment_falls_back_to_the_host_name() {
    let (name, source) = environment(None, Some("host-1\n"));
    assert_eq!(
        (name.as_str(), source),
        ("host-1", EnvironmentSource::Hostname)
    );
}

#[test]
fn environment_is_default_when_nothing_is_readable() {
    let (name, source) = environment(None, None);
    assert_eq!(
        (name.as_str(), source),
        ("default", EnvironmentSource::Default)
    );
}

#[test]
fn a_configured_name_that_cleans_to_nothing_falls_through_to_the_host() {
    let (name, source) = environment(Some("\u{200b}  "), Some("host-1"));
    assert_eq!(
        (name.as_str(), source),
        ("host-1", EnvironmentSource::Hostname)
    );
}

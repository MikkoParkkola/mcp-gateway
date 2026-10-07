// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8002: the `base_path` matcher, on synthetic and on the real owned set.

use super::*;
use crate::gateway::routes::OWNED;

fn refused(base_path: &str) -> bool {
    WebhookConfig {
        base_path: base_path.to_string(),
        ..WebhookConfig::default()
    }
    .validate()
    .is_err()
}

fn any_overlap(owned: &[&str], base: &str) -> bool {
    owned.iter().any(|route| overlaps(base, route))
}

/// Test 4d: the matcher alone, on owned sets where no ancestor forces the
/// answer.
#[test]
fn the_matcher_handles_parameters_catch_alls_and_both_directions() {
    let cases: &[(&[&str], &[&str], &[&str])] = &[
        (&["/a/{x}"], &["/a/b", "/a/b/c", "/a"], &["/b"]),
        (&["/c/{*rest}"], &["/c/x", "/c/x/y", "/c"], &["/cx"]),
        (&["/s/t"], &["/s/t/u", "/s"], &["/s/tt", "/t"]),
        (
            &["/p/{x}/q"],
            &["/p/a/q", "/p/a/q/r", "/p", "/p/a"],
            &["/p/a/r"],
        ),
    ];
    for (owned, overlapping, apart) in cases {
        for base in *overlapping {
            assert!(any_overlap(owned, base), "{owned:?} must refuse {base}");
        }
        for base in *apart {
            assert!(!any_overlap(owned, base), "{owned:?} must accept {base}");
        }
    }
}

/// Test 4e: every real owned pattern, instantiated, is refused with and
/// without a sub-path, and so is each owned route's parent (an owned route
/// would sit under the mount).
#[test]
fn every_owned_route_its_subtree_and_its_parent_are_refused() {
    for route in OWNED {
        assert!(route.len() > 1, "the root is never owned: {route:?}");
        let instance = route
            .split('/')
            .map(|segment| {
                if segment.starts_with("{*") {
                    "x/y"
                } else if segment.starts_with('{') {
                    "x"
                } else {
                    segment
                }
            })
            .collect::<Vec<_>>()
            .join("/");
        assert!(refused(&instance), "{route}: {instance} accepted");
        assert!(
            refused(&format!("{instance}/sub")),
            "{route}: under it accepted"
        );
        if let Some((parent, _)) = route.rsplit_once('/')
            && !parent.is_empty()
            && !parent.contains('{')
        {
            assert!(refused(parent), "{route}: parent {parent} accepted");
        }
    }
}

/// The default path is accepted, and a disabled receiver is never checked.
#[test]
fn the_default_and_a_disabled_receiver_pass() {
    assert!(WebhookConfig::default().validate().is_ok());
    let disabled = WebhookConfig {
        enabled: false,
        base_path: "/mcp".to_string(),
        ..WebhookConfig::default()
    };
    assert!(disabled.validate().is_ok());
}

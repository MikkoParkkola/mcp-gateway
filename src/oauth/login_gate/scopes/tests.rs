// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8619 r4.4: the contention class nests with the login scope. A
//! `non_interactive` inside `short_contention` keeps Short, leaving a scope
//! restores what enclosed it, and a spawned task inherits nothing.

use super::{ContentionClass, contention_class, interactive, non_interactive, short_contention};

/// Short survives a nested `non_interactive`, both scopes unwind in order,
/// and a task spawned inside Short starts Long and interactive.
#[tokio::test]
async fn a_nested_non_interactive_keeps_the_short_class() {
    assert_eq!(
        contention_class(),
        ContentionClass::Long,
        "outside every scope"
    );
    assert!(interactive(), "outside every scope");

    short_contention(async {
        assert_eq!(
            contention_class(),
            ContentionClass::Short,
            "inside short_contention"
        );
        assert!(!interactive(), "inside short_contention");

        non_interactive(async {
            assert_eq!(
                contention_class(),
                ContentionClass::Short,
                "a nested non_interactive reset the class to Long"
            );
            assert!(!interactive(), "inside the nested non_interactive");
        })
        .await;

        assert_eq!(
            contention_class(),
            ContentionClass::Short,
            "leaving the inner scope lost Short"
        );
        assert!(!interactive(), "leaving the inner scope");

        let spawned = tokio::spawn(async { (contention_class(), interactive()) })
            .await
            .expect("the spawned task joins");
        assert_eq!(
            spawned,
            (ContentionClass::Long, true),
            "a spawned task inherited the scope"
        );
    })
    .await;

    assert_eq!(
        contention_class(),
        ContentionClass::Long,
        "after every scope"
    );
    assert!(interactive(), "after every scope");
}

/// A `non_interactive` outside any Short scope is Long but not interactive,
/// an inner `short_contention` turns it Short, and leaving that inner scope
/// restores Long.
#[tokio::test]
async fn a_top_level_non_interactive_is_long_and_restores_long() {
    non_interactive(async {
        assert_eq!(
            contention_class(),
            ContentionClass::Long,
            "a top-level non_interactive is Long"
        );
        assert!(!interactive(), "a top-level non_interactive");

        short_contention(async {
            assert_eq!(
                contention_class(),
                ContentionClass::Short,
                "short_contention inside non_interactive"
            );
            assert!(!interactive(), "short_contention inside non_interactive");
        })
        .await;

        assert_eq!(
            contention_class(),
            ContentionClass::Long,
            "leaving the inner short_contention lost Long"
        );
        assert!(!interactive(), "leaving the inner short_contention");
    })
    .await;

    assert_eq!(
        contention_class(),
        ContentionClass::Long,
        "after every scope"
    );
    assert!(interactive(), "after every scope");
}

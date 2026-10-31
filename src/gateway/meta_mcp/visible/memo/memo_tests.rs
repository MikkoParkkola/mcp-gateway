// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Memo semantics: the first judgement wins within a scope, a nested scope
//! reuses the outer memo, and outside any scope every read judges fresh.

use super::{VISIBILITY_MEMO, Visibility, VisibilityMemo, Withholding, with_visibility_memo};

const WITHHELD: Visibility = Visibility::Withheld(Withholding::Schema);

/// What the open scope's memo holds for `(server, tool)`; panics outside
/// a scope (the rows below check that separately).
fn recorded(server: &str, tool: &str) -> Option<Visibility> {
    VISIBILITY_MEMO
        .try_with(|memo| memo.recorded(server, tool))
        .expect("inside a visibility memo scope")
}

fn in_scope() -> bool {
    VISIBILITY_MEMO.try_with(|_| ()).is_ok()
}

#[test]
fn the_first_judgement_wins() {
    let memo = VisibilityMemo::default();
    assert_eq!(memo.record("alpha", "read", WITHHELD), WITHHELD);
    assert_eq!(memo.record("alpha", "read", Visibility::Visible), WITHHELD);
    assert_eq!(memo.recorded("alpha", "read"), Some(WITHHELD));
    assert_eq!(memo.recorded("alpha", "note"), None);
}

#[tokio::test]
async fn a_nested_scope_reuses_the_outer_memo() {
    with_visibility_memo(async {
        VISIBILITY_MEMO.with(|memo| memo.record("alpha", "read", WITHHELD));
        with_visibility_memo(async {
            assert_eq!(recorded("alpha", "read"), Some(WITHHELD));
        })
        .await;
    })
    .await;
}

#[tokio::test]
async fn outside_a_scope_there_is_no_memo_and_scopes_do_not_leak() {
    assert!(!in_scope(), "a memo outside any request scope");
    with_visibility_memo(async {
        VISIBILITY_MEMO.with(|memo| memo.record("alpha", "read", WITHHELD));
    })
    .await;
    with_visibility_memo(async {
        assert_eq!(
            recorded("alpha", "read"),
            None,
            "a second request saw the first's memo"
        );
    })
    .await;
}

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A tools notice carried across listener runs is announced only by a run on
//! the grant it was heard under.

use super::*;

fn heard_under(binding: Option<&str>) -> ToolsDebt {
    let mut debt = ToolsDebt::default();
    debt.fence = binding.map(str::to_owned);
    debt
}

#[test]
fn a_run_on_another_grant_drops_the_carried_tools_notice() {
    let mut debt = heard_under(Some("acct:fence:v1:u1:1"));
    forget_foreign_debt(&mut debt, Some("acct:fence:v1:u1:1:rotated".to_owned()));
    assert_eq!(debt.fence, None, "dropped");
}

#[test]
fn a_run_on_the_same_grant_keeps_the_carried_tools_notice() {
    let mut debt = heard_under(Some("acct:fence:v1:u1:1"));
    forget_foreign_debt(&mut debt, Some("acct:fence:v1:u1:1".to_owned()));
    assert_eq!(debt.fence.as_deref(), Some("acct:fence:v1:u1:1"), "kept");
}

#[test]
fn a_notice_heard_before_any_grant_is_not_announced_under_one() {
    let mut debt = heard_under(None);
    forget_foreign_debt(&mut debt, Some("acct:fence:v1:u1:1".to_owned()));
    assert_eq!(debt.fence, None);
}

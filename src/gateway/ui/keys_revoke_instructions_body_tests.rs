// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The refused-revocation answer: `instructions` appears only when the code is
//! one of keyedit's revocation-check codes AND the reason is that check's text.

use super::*;

const S9: &str = "to revoke key `k`: set its `expires_at` to now and reload the gateway";

fn answer(code: GiveUp, reason: &str) -> serde_json::Value {
    keyedit_refusal(code, reason, std::path::Path::new("/etc/gw/gateway.yaml"))
}

fn without_instructions(code: &str, reason: &str) -> serde_json::Value {
    serde_json::json!({
        "error": "not_written",
        "revoked": false,
        "code": code,
        "reason": reason,
        "path": "/etc/gw/gateway.yaml",
    })
}

#[test]
fn rc1_a_revocation_check_code_without_its_text_gives_no_instructions() {
    let reason = "an anchor or alias is on a line the edit would change";
    assert_eq!(
        answer(GiveUp::Anchor, reason),
        without_instructions("anchor", reason)
    );
}

#[test]
fn rc2_the_text_with_another_code_gives_no_instructions() {
    assert_eq!(answer(GiveUp::Other, S9), without_instructions("other", S9));
}

#[test]
fn rc3_both_checks_hold_so_the_instructions_are_the_reason() {
    for (code, name) in [(GiveUp::Anchor, "anchor"), (GiveUp::Flow, "flow")] {
        let mut expected = without_instructions(name, S9);
        expected["instructions"] = S9.into();
        assert_eq!(answer(code, S9), expected);
    }
}

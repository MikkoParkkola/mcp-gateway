// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Root exceptions use the same validator as live settle and verification.

use super::super::fixtures::collect_case;
use super::fixtures::{Live, ROOT, actor, payload, runtime};
use crate::security::transparency_log::settle::{
    IntentKind, Role, Unsettled, role_fields, root_recovery_fields,
};

#[test]
fn root_recovery_lands() {
    const ROW: &str = "root_recovery_lands";
    let mut failures = Vec::new();
    let expected = "one root intent with no invented predecessor";
    collect_case(&mut failures, ROW, "live_root", expected, || {
        let live = Live::new();
        let result = runtime(live.log.settle_attributed(
            &live.log.log_id(),
            "root-1",
            Role::RecoveryIntent,
            payload(ROOT),
            actor(),
        ));
        assert!(
            result.is_ok(),
            "{ROW}: marked root recovery lands through B"
        );
        let records = live.records();
        let roots: Vec<_> = records.iter().filter(|r| r["token"] == "root-1").collect();
        assert_eq!(roots.len(), 1, "{ROW}: root lands once");
        let root = roots[0].as_object().expect(ROW);
        assert_eq!(
            root.get("root"),
            Some(&serde_json::Value::Bool(true)),
            "{ROW}: explicit root marker"
        );
        assert!(
            !root.contains_key("settles"),
            "{ROW}: no invented settles token"
        );
        assert_eq!(
            root_recovery_fields(Role::RecoveryIntent, root),
            Ok(()),
            "{ROW}: shared root validator accepts"
        );
        assert_eq!(
            role_fields(Role::RecoveryIntent, root),
            Ok(()),
            "{ROW}: shared full validator accepts"
        );
        live.verify(ROW);
        Ok(())
    });
    assert!(failures.is_empty(), "{ROW}:\n{}", failures.join("\n"));
}

#[test]
fn non_root_missing_settles_invalid() {
    const ROW: &str = "non_root_missing_settles_invalid";
    let mut failures = Vec::new();
    let cases = [
        (
            Role::RecoveryIntent,
            br#"{"kind":"settle.recovery"}"#.as_slice(),
        ),
        (
            Role::RecoveryIntent,
            br#"{"kind":"settle.recovery","root":false}"#.as_slice(),
        ),
        (
            Role::RecoveryIntent,
            br#"{"kind":"settle.recovery","root":"true"}"#.as_slice(),
        ),
        (
            Role::Intent(IntentKind::Save),
            br#"{"kind":"settle.save","root":true}"#.as_slice(),
        ),
        (
            Role::Outcome,
            br#"{"intent_counter":3,"kind":"settle.save","root":true}"#.as_slice(),
        ),
    ];
    for (role, bytes) in cases {
        let case = format!("{role:?} {}", String::from_utf8_lossy(bytes));
        let expected = "Invalid; shared validator refuses; zero append";
        collect_case(&mut failures, ROW, &case, expected, || {
            let live = Live::new();
            let before = std::fs::read(&live.log_path).expect(ROW);
            let mut fields = payload(bytes);
            fields.insert("token".into(), "invalid-1".into());
            assert!(
                root_recovery_fields(role, &fields).is_err(),
                "{ROW}: shared validator refuses missing settles or foreign-role root marker"
            );
            assert!(
                role_fields(role, &fields).is_err(),
                "{ROW}: verify uses the same root restriction"
            );
            let result = runtime(live.log.settle_attributed(
                &live.log.log_id(),
                "invalid-1",
                role,
                payload(bytes),
                actor(),
            ));
            assert!(
                matches!(result, Err(Unsettled::Invalid(_))),
                "{ROW}: B returns Invalid before append"
            );
            assert_eq!(
                std::fs::read(&live.log_path).expect(ROW),
                before,
                "{ROW}: zero append and counter change"
            );
            Ok(())
        });
    }
    assert!(failures.is_empty(), "{ROW}:\n{}", failures.join("\n"));
}

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `refusals_for` on synthetic `Inspection` values (#1718). Windows
//! normalises GENERIC_* on store, so only a synthetic DACL can carry them.

use super::*;
use crate::config::Protects;
use windows_sys::Win32::Foundation::{GENERIC_ALL, GENERIC_EXECUTE, GENERIC_READ, GENERIC_WRITE};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_ALL_ACCESS, FILE_APPEND_DATA, FILE_GENERIC_READ, FILE_WRITE_ATTRIBUTES,
    FILE_WRITE_DATA, FILE_WRITE_EA, WRITE_DAC, WRITE_OWNER,
};

fn me() -> Sid {
    Sid::from_parts(5, &[21, 1, 2, 3, 1001])
}
fn other() -> Sid {
    Sid::from_parts(5, &[21, 1, 2, 3, 1002])
}
fn everyone() -> Sid {
    Sid::from_parts(1, &[0])
}
fn system() -> Sid {
    Sid::from_parts(5, &[18])
}
fn admins() -> Sid {
    Sid::from_parts(5, &[32, 544])
}

fn allow(sid: Sid, mask: u32) -> Ace {
    Ace::Allowed {
        flags: 0,
        mask,
        sid,
    }
}

/// Owner-only, protected, owned by the user, plus `extra`.
fn with(extra: Vec<Ace>) -> Inspection {
    let mut dacl = vec![allow(me(), FILE_ALL_ACCESS)];
    dacl.extend(extra);
    Inspection {
        owner: Some(me()),
        dacl: Some(dacl),
        protected: true,
    }
}

fn integrity(i: &Inspection) -> Vec<PrivacyRefusal> {
    refusals_for(i, &me(), Protects::Integrity)
}

const WRITE_BITS: [(&str, u32); 9] = [
    ("FILE_WRITE_DATA", FILE_WRITE_DATA),
    ("FILE_APPEND_DATA", FILE_APPEND_DATA),
    ("FILE_WRITE_EA", FILE_WRITE_EA),
    ("FILE_WRITE_ATTRIBUTES", FILE_WRITE_ATTRIBUTES),
    ("DELETE", DELETE),
    ("WRITE_DAC", WRITE_DAC),
    ("WRITE_OWNER", WRITE_OWNER),
    ("GENERIC_WRITE", GENERIC_WRITE),
    ("GENERIC_ALL", GENERIC_ALL),
];

#[test]
fn integrity_accepts_a_foreign_read_ace() {
    for mask in [
        FILE_GENERIC_READ,
        GENERIC_READ,
        GENERIC_READ | GENERIC_EXECUTE,
    ] {
        let found = integrity(&with(vec![allow(everyone(), mask)]));
        assert!(found.is_empty(), "WT-ASSERT I-READ {mask:#x}: {found:?}");
    }
}

#[test]
fn integrity_refuses_each_foreign_write_bit() {
    for (name, bit) in WRITE_BITS {
        let found = integrity(&with(vec![allow(everyone(), FILE_GENERIC_READ | bit)]));
        assert_eq!(
            found,
            vec![PrivacyRefusal::ForeignSid("S-1-1-0".into())],
            "WT-ASSERT I-WRITE {name}"
        );
    }
}

#[test]
fn integrity_lets_system_and_administrators_write() {
    for sid in [system(), admins()] {
        let found = integrity(&with(vec![allow(
            sid.clone(),
            FILE_ALL_ACCESS | GENERIC_ALL,
        )]));
        assert!(
            found.is_empty(),
            "WT-ASSERT I-TRUSTED {}: {found:?}",
            sid.to_sddl()
        );
    }
}

#[test]
fn integrity_accepts_inheritance_and_a_read_only_user() {
    let mut i = with(vec![allow(everyone(), FILE_GENERIC_READ)]);
    i.protected = false;
    i.dacl = Some(vec![
        Ace::Allowed {
            flags: 0x10,
            mask: FILE_GENERIC_READ,
            sid: me(),
        },
        allow(everyone(), FILE_GENERIC_READ),
    ]);
    let found = integrity(&i);
    assert!(found.is_empty(), "WT-ASSERT I-INHERIT: {found:?}");
}

#[test]
fn integrity_refuses_a_null_dacl_and_an_undecoded_ace() {
    let mut null = with(vec![]);
    null.dacl = None;
    assert_eq!(
        integrity(&null),
        vec![PrivacyRefusal::NullDacl],
        "WT-ASSERT I-NULL"
    );
    let other_ace = with(vec![Ace::Other { ace_type: 9 }]);
    assert_eq!(
        integrity(&other_ace),
        vec![PrivacyRefusal::OtherAceType(9)],
        "WT-ASSERT I-OTHER"
    );
}

#[test]
fn integrity_owner_must_be_the_user_system_or_administrators() {
    for owner in [me(), system(), admins()] {
        let mut i = with(vec![]);
        i.owner = Some(owner.clone());
        let found = integrity(&i);
        assert!(
            found.is_empty(),
            "WT-ASSERT I-OWNER-OK {}: {found:?}",
            owner.to_sddl()
        );
    }
    let mut foreign = with(vec![]);
    foreign.owner = Some(other());
    assert_eq!(
        integrity(&foreign),
        vec![PrivacyRefusal::ForeignOwner(other().to_sddl())],
        "WT-ASSERT I-OWNER-FOREIGN"
    );
    let mut missing = with(vec![]);
    missing.owner = None;
    assert_eq!(
        integrity(&missing),
        vec![PrivacyRefusal::Unreadable],
        "WT-ASSERT I-OWNER-NONE"
    );
}

#[test]
fn integrity_reports_every_rule_broken() {
    let mut i = with(vec![allow(other(), FILE_WRITE_DATA)]);
    i.owner = Some(other());
    assert_eq!(
        integrity(&i),
        vec![
            PrivacyRefusal::ForeignSid(other().to_sddl()),
            PrivacyRefusal::ForeignOwner(other().to_sddl()),
        ],
        "WT-ASSERT I-ALL"
    );
}

#[test]
fn secrecy_is_exactly_refusals() {
    let cases = [
        with(vec![allow(everyone(), FILE_GENERIC_READ)]),
        with(vec![allow(system(), FILE_ALL_ACCESS)]),
        Inspection {
            owner: Some(system()),
            ..with(vec![])
        },
        with(vec![]),
    ];
    for i in &cases {
        assert_eq!(
            refusals_for(i, &me(), Protects::Secrecy),
            refusals(i, &me()),
            "WT-ASSERT S-SAME {i:?}"
        );
    }
    assert_eq!(
        refusals_for(&cases[0], &me(), Protects::Secrecy),
        vec![PrivacyRefusal::ForeignSid("S-1-1-0".into())],
        "WT-ASSERT S-READ"
    );
}

/// The fallback for a path no command may be printed for (an apostrophe is
/// outside the allowlist) still gives the repair for the file's class.
#[test]
fn unrunnable_path_fallback_is_class_correct() {
    let path = r"C:\dir\it's.txt";
    let found = [PrivacyRefusal::ForeignSid("S-1-1-0".into())];
    let me = user_sid_string().expect("the runner's SID");

    let secret = windows_remediation(path, &found, Protects::Secrecy);
    let trust = windows_remediation(path, &found, Protects::Integrity);

    assert!(
        secret.contains("no command is printed"),
        "WT-ASSERT F0: {secret}"
    );
    assert!(
        secret.contains(&format!(
            "grant Full control to the account with SID {me} alone"
        )),
        "WT-ASSERT F-SECRET: {secret}"
    );
    assert!(
        trust.contains("remove write, delete, change-permissions and take-ownership rights"),
        "WT-ASSERT F-TRUST-REMOVE: {trust}"
    );
    assert!(
        trust.contains("keep read access"),
        "WT-ASSERT F-TRUST-KEEP: {trust}"
    );
    assert!(
        !trust.contains("alone"),
        "WT-ASSERT F-TRUST-NOT-OWNER-ONLY: {trust}"
    );
}

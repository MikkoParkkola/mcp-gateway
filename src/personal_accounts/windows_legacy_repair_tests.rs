// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! W-T10c to W-T10h: a 3.x token file swapped for a link is refused, and the
//! printed remediation repairs what it can and only instructs on unsafe paths.

use super::*;

// W-T10c: a 3.x token swapped for a symlink after the path check and before
// the open is refused: the open does not follow it.
#[test]
fn wt10c_legacy_token_swapped_for_a_link_refuses() {
    use crate::private_fs::test_support::plant_owner_only;
    let (root, path) = legacy_token("W-T10c");
    // Both files owner-only through the native plant (read back), so the
    // only thing the swap changes is what the open is pointed at.
    plant_owner_only("W-T10c", &path);
    let target = root.path().join("private_target.json");
    std::fs::copy(&path, &target).unwrap();
    plant_owner_only("W-T10c", &target);
    let control = read_legacy_source(&path);
    if control.is_err() {
        fixture_fail(
            "W-T10c",
            &format!("the private token itself must read: {control:?}"),
        );
    }
    let (link, to) = (path.clone(), target.clone());
    instrument::set_hook(Some(Box::new(move |which, p| {
        if which == Hook::BeforeRecordOpen && p == link {
            std::fs::remove_file(&link).unwrap();
            std::os::windows::fs::symlink_file(&to, &link).unwrap();
        }
    })));
    let read = read_legacy_source(&path);
    instrument::set_hook(None);
    assert!(
        matches!(read, Err(SourceRefusal::NotPrivate { .. })),
        "WT-ASSERT W-T10c: a link swapped in before the open was followed: {read:?}"
    );
}

// W-T10d: a deny naming the user is removed by the printed repair.
#[test]
fn wt10d_remediation_removes_a_user_deny() {
    let (_root, path) = legacy_token("W-T10d");
    let user = crate::private_fs::test_support::user_sid();
    crate::private_fs::test_support::plant_owner_only("W-T10d", &path);
    icacls("W-T10d", &path, &["/deny", &format!("*{user}:(WD)")]);
    let text = read_legacy_source(&path)
        .err()
        .map(|r| r.to_string())
        .unwrap_or_default();
    assert!(
        text.contains("NoReadWrite"),
        "WT-FIXTURE W-T10d: the planted deny did not fail P3: {text}"
    );
    crate::private_fs::test_support::run_printed_repair("W-T10d", &text);
    let after = read_legacy_source(&path);
    assert!(
        after.is_ok(),
        "WT-ASSERT W-T10d: still refused after the printed repair: {after:?}"
    );
}

// W-T10e: an ACE type the judge refuses (a conditional callback ACE) is
// removed by the printed repair too.
#[test]
fn wt10e_remediation_removes_an_unsupported_ace() {
    let (_root, path) = legacy_token("W-T10e");
    let user = crate::private_fs::test_support::user_sid();
    let sddl = format!("O:{user}D:P(A;;FA;;;{user})(XA;;FR;;;WD;(Member_of {{SID(BA)}}))");
    let back = crate::private_fs::test_support::plant_any("W-T10e", &path, &sddl);
    let text = read_legacy_source(&path)
        .err()
        .map(|r| r.to_string())
        .unwrap_or_default();
    if !text.contains("OtherAceType") {
        fixture_fail("W-T10e", &format!("planted {back}; refusal was {text}"));
    }
    crate::private_fs::test_support::run_printed_repair("W-T10e", &text);
    let after = read_legacy_source(&path);
    assert!(
        after.is_ok(),
        "WT-ASSERT W-T10e: still refused after the printed repair: {after:?}"
    );
}

// W-T10f: a path outside the allowed character set gets repair
// instructions and no runnable line; the path's quote characters never reach
// a command.
#[test]
fn wt10f_unsafe_path_gets_instructions_only() {
    let root = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    // The repair lines run in a PowerShell started in this process's working
    // directory, so a relative marker name lands there if code ever runs. The
    // folder name must be one valid component: no separator, no colon.
    let name = format!("wt10f-marker-{:x}", rand::random::<u64>());
    let marker = std::env::current_dir().unwrap().join(&name);
    // A folder name that would end a naive single-quoted literal and run code.
    let hostile = format!("oauth\u{2019}; New-Item '{name}' ;\u{2018}");
    let parent = root.path().join(hostile);
    std::fs::create_dir(&parent).unwrap();
    let user = crate::private_fs::test_support::user_sid();
    let sddl = format!("O:{user}D:P(A;OICI;FA;;;{user})(A;OICI;FR;;;BU)");
    crate::private_fs::test_support::plant_sddl("W-T10f", &parent, &sddl, &sddl);
    let path = parent.join("0123456789abcdef_tokens.json");
    std::fs::write(&path, LEGACY).unwrap();
    let text = read_legacy_source(&path)
        .err()
        .map(|r| r.to_string())
        .unwrap_or_default();
    if !text.contains("S-1-5-32-545") {
        fixture_fail(
            "W-T10f",
            &format!("the inherited grant did not refuse: {text}"),
        );
    }
    assert!(
        !text.contains("run these lines") && text.contains("no command is printed"),
        "WT-ASSERT W-T10f: a runnable line was printed for a path outside the allowed set: {text}"
    );
    assert_eq!(
        crate::private_fs::test_support::run_printed_repair("W-T10f", &text),
        0,
        "WT-ASSERT W-T10f: the instructions carried a runnable line"
    );
    assert!(!marker.exists(), "WT-ASSERT W-T10f: code from the path ran");
}

// W-T10h: a path inside the allowed set (letters, digits, space and
// `\ : . _ - ( )`) gets runnable lines, and they repair the file.
#[test]
fn wt10h_allowed_path_gets_a_working_runnable_repair() {
    let root = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let parent = root.path().join("oauth dir (3.x)_v-1.0");
    std::fs::create_dir(&parent).unwrap();
    let user = crate::private_fs::test_support::user_sid();
    let sddl = format!("O:{user}D:P(A;OICI;FA;;;{user})(A;OICI;FR;;;BU)");
    crate::private_fs::test_support::plant_sddl("W-T10h", &parent, &sddl, &sddl);
    let path = parent.join("0123456789abcdef_tokens.json");
    std::fs::write(&path, LEGACY).unwrap();
    let text = read_legacy_source(&path)
        .err()
        .map(|r| r.to_string())
        .unwrap_or_default();
    assert!(
        text.contains("run these lines"),
        "WT-ASSERT W-T10h: no runnable line for an allowed path: {text}"
    );
    assert!(
        crate::private_fs::test_support::run_printed_repair("W-T10h", &text) > 0,
        "WT-ASSERT W-T10h: the refusal printed no repair lines: {text}"
    );
    let after = read_legacy_source(&path);
    assert!(
        after.is_ok(),
        "WT-ASSERT W-T10h: still refused after the printed repair: {after:?}"
    );
}

// W-T10g: a NULL DACL on a foreign-owned file reports both, so one printed
// repair fixes both.
#[test]
fn wt10g_null_dacl_and_foreign_owner_repaired_in_one_pass() {
    let (_root, path) = legacy_token("W-T10g");
    let back =
        crate::private_fs::test_support::plant_any("W-T10g", &path, "O:BAD:NO_ACCESS_CONTROL");
    let text = read_legacy_source(&path)
        .err()
        .map(|r| r.to_string())
        .unwrap_or_default();
    if !text.contains("NullDacl") {
        fixture_fail("W-T10g", &format!("planted {back}; refusal was {text}"));
    }
    assert!(
        text.contains("ForeignOwner"),
        "WT-ASSERT W-T10g: a NULL DACL hid the foreign owner: {text}"
    );
    crate::private_fs::test_support::run_printed_repair("W-T10g", &text);
    let after = read_legacy_source(&path);
    assert!(
        after.is_ok(),
        "WT-ASSERT W-T10g: still refused after one printed repair: {after:?}"
    );
}

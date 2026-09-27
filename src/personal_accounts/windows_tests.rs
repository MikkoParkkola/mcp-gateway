// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Store-level Windows rows for the personal-account store (test plan §3).
//! Each decisive assertion starts `WT-ASSERT <row>`.

use super::commit::{empty_store, reopen};
use super::{AccountError, AccountLookup, PersonalAccountStore, alice, config, grant};
use crate::private_fs::test_support::{assert_owner_only, fixture_fail, icacls};
use crate::private_fs::{Hook, Trace, instrument};
use std::path::{Path, PathBuf};

/// Store files, found by listing (the record basename is random).
fn record_file(dir: &Path) -> PathBuf {
    std::fs::read_dir(dir)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|x| x == "json"))
        .unwrap_or_else(|| fixture_fail("records", "no record file"))
}

fn committed() -> (tempfile::TempDir, super::StoreConfig) {
    let (root, settings, store) = empty_store(8);
    assert_eq!(store.commit_grant(&alice(), &grant()), Ok(()));
    drop(store);
    (root, settings)
}

// W-T1 (store level): every object the store creates is owner-only.
#[test]
fn wt1_store_objects_are_owner_only() {
    let (_root, settings) = committed();
    assert_owner_only("W-T1/records-dir", &settings.store_dir, true);
    assert_owner_only("W-T1/authority-dir", &settings.authority_dir, true);
    assert_owner_only(
        "W-T1/authority.json",
        &settings.authority_dir.join("authority.json"),
        false,
    );
    assert_owner_only("W-T1/record", &record_file(&settings.store_dir), false);
    assert_owner_only(
        "W-T1/lock",
        &settings.authority_dir.join(".personal-accounts.lock"),
        false,
    );
}

// W-T4: a foreign ACE on each file the store reads refuses that read.
#[test]
fn wt4_authority_json() {
    let (_root, settings) = committed();
    icacls(
        "W-T4/authority",
        &settings.authority_dir.join("authority.json"),
        &["/grant", "*S-1-1-0:R"],
    );
    assert_eq!(
        PersonalAccountStore::open(settings).err(),
        Some(AccountError::StorageUnavailable),
        "WT-ASSERT W-T4/authority"
    );
}

#[test]
fn wt4_record() {
    let (_root, settings) = committed();
    icacls(
        "W-T4/record",
        &record_file(&settings.store_dir),
        &["/grant", "*S-1-1-0:R"],
    );
    assert!(
        reopen(&settings).lookup(&alice()).is_err(),
        "WT-ASSERT W-T4/record: a record other users can read was served"
    );
}

#[test]
fn wt4_lock_sidecar() {
    let (_root, settings) = committed();
    icacls(
        "W-T4/lock",
        &settings.authority_dir.join(".personal-accounts.lock"),
        &["/grant", "*S-1-1-0:R"],
    );
    assert!(
        PersonalAccountStore::open(settings).is_err(),
        "WT-ASSERT W-T4/lock: a shared custody sidecar was accepted"
    );
}

// W-T4 on a store directory (the account store's R1).
#[test]
fn wt4_store_directory() {
    let (_root, settings) = committed();
    icacls("W-T4/dir", &settings.store_dir, &["/grant", "*S-1-1-0:R"]);
    assert_eq!(
        PersonalAccountStore::open(settings).err(),
        Some(AccountError::InvalidConfiguration),
        "WT-ASSERT W-T4/dir"
    );
}

// W-T5: a junction anywhere in the configured path.
#[test]
fn wt5_junction_in_store_path_refuses() {
    let root = tempfile::tempdir().unwrap();
    let real = root.path().join("real");
    std::fs::create_dir(&real).unwrap();
    let link = root.path().join("j");
    let made = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(&link)
        .arg(&real)
        .status();
    if !made.is_ok_and(|s| s.success()) {
        fixture_fail("W-T5", "mklink /J failed");
    }
    let mut settings = config(root.path());
    settings.store_dir = link.join("records");
    settings.authority_dir = link.join("authority");
    assert_eq!(
        PersonalAccountStore::initialize(settings).err(),
        Some(AccountError::InvalidConfiguration),
        "WT-ASSERT W-T5"
    );
}

// W-T7: lexical path rule, one test per case. Relative and parent-component
// cases are refused by the shared check already (regression guards).
fn refused_path(path: &str) -> bool {
    let root = tempfile::tempdir().unwrap();
    let mut settings = config(root.path());
    settings.store_dir = PathBuf::from(path).join("records");
    settings.authority_dir = PathBuf::from(path).join("authority");
    PersonalAccountStore::initialize(settings).err() == Some(AccountError::InvalidConfiguration)
}

macro_rules! path_case {
    ($name:ident, $path:expr) => {
        #[test]
        fn $name() {
            assert!(
                refused_path($path),
                "WT-ASSERT W-T7/{}: {} accepted",
                stringify!($name),
                $path
            );
        }
    };
}
path_case!(wt7_unc, r"\\localhost\C$\mgw-wt7");
path_case!(wt7_verbatim_unc, r"\\?\UNC\localhost\C$\mgw-wt7");
path_case!(wt7_device, r"\\.\C:\mgw-wt7");
path_case!(wt7_globalroot, r"\\?\GLOBALROOT\Device\mgw-wt7");
path_case!(wt7_drive_relative, r"C:mgw-wt7");
path_case!(wt7_root_relative, r"\mgw-wt7");
path_case!(wt7_relative, r"mgw-wt7");
path_case!(wt7_parent_component, r"C:\a\..\mgw-wt7");

// W-T18: an ancestor swapped for a junction between the path walk and the
// directory open is caught by the final-path check.
#[test]
fn wt18_path_swap_between_walk_and_open_refuses() {
    let root = tempfile::tempdir().unwrap();
    let a = root.path().join("a");
    let other = root.path().join("other");
    // A valid private store of the same user, somewhere else.
    let mut decoy = config(root.path());
    decoy.store_dir = other.join("records");
    decoy.authority_dir = other.join("authority");
    drop(PersonalAccountStore::initialize(decoy).unwrap());
    let mut settings = config(root.path());
    settings.store_dir = a.join("records");
    settings.authority_dir = a.join("authority");
    drop(PersonalAccountStore::initialize(settings.clone()).unwrap());
    let swap = std::sync::Once::new();
    let (a2, other2) = (a.clone(), other.clone());
    instrument::set_hook(Some(Box::new(move |which, _path| {
        if which == Hook::AfterPathWalk {
            swap.call_once(|| {
                std::fs::rename(&a2, a2.with_extension("orig")).unwrap();
                let ok = std::process::Command::new("cmd")
                    .args(["/C", "mklink", "/J"])
                    .arg(&a2)
                    .arg(&other2)
                    .status()
                    .is_ok_and(|s| s.success());
                assert!(ok, "WT-FIXTURE W-T18: junction swap failed");
            });
        }
    })));
    let opened = PersonalAccountStore::open(settings);
    instrument::set_hook(None);
    assert_eq!(
        opened.err(),
        Some(AccountError::InvalidConfiguration),
        "WT-ASSERT W-T18"
    );
}

// W-T22: durability calls, in order, per commit.
#[test]
fn wt22_durability_calls_are_made() {
    let (_root, _settings, store) = empty_store(8);
    let _ = instrument::take_trace();
    assert_eq!(store.commit_grant(&alice(), &grant()), Ok(()));
    let trace = instrument::take_trace();
    let replace_at = trace
        .iter()
        .position(|t| matches!(t, Trace::Replace { .. }));
    assert!(
        trace.first().is_some_and(|t| *t == Trace::SyncFile(true))
            && trace.contains(&Trace::Replace {
                write_through: true
            })
            && replace_at.is_some_and(|i| trace[i + 1..].contains(&Trace::SyncDir(true))),
        "WT-ASSERT W-T22: {trace:?}"
    );
}

// W-T24: a record is judged on the handle actually opened.
#[test]
fn wt24_record_is_judged_on_the_open_handle() {
    let (_root, settings) = committed();
    let store = reopen(&settings);
    let record = record_file(&settings.store_dir);
    let planted = record.clone();
    instrument::set_hook(Some(Box::new(move |which, path| {
        if which == Hook::BeforeRecordOpen && path == planted {
            icacls("W-T24", &planted, &["/grant", "*S-1-1-0:R"]);
        }
    })));
    let looked = store.lookup(&alice());
    instrument::set_hook(None);
    assert!(
        !matches!(looked, Ok(AccountLookup::Connected(_))),
        "WT-ASSERT W-T24: served a record that turned foreign before open"
    );
}

fn version(record: &super::GrantRecord) -> super::GrantVersion {
    super::GrantVersion {
        generation: record.generation.clone(),
        token_revision: record.token_revision,
        authorization_epoch: record.authorization_epoch,
        descriptor_revision: record.descriptor_revision.clone(),
    }
}

fn refreshed(record: &super::GrantRecord) -> super::GrantRecord {
    let mut next = record.clone();
    next.token_revision += 1;
    next.access_token = format!("synthetic-refreshed-access-r{}", next.token_revision);
    next
}

// W-T17 (regression guard): readers close inside the lock, so every replace
// of a lookup-then-refresh succeeds on its first attempt.
#[test]
fn wt17_reader_closes_before_replace() {
    let (_root, settings) = committed();
    let store = reopen(&settings);
    assert!(matches!(
        store.lookup(&alice()),
        Ok(AccountLookup::Connected(_))
    ));
    let _ = (instrument::take_trace(), instrument::take_attempts());
    let first = grant();
    assert!(
        store
            .refresh_tokens(&alice(), &version(&first), &refreshed(&first))
            .is_ok()
    );
    let replaces = instrument::take_trace()
        .iter()
        .filter(|t| matches!(t, Trace::Replace { .. }))
        .count();
    let attempts = instrument::take_attempts();
    assert_eq!(
        u32::try_from(replaces).unwrap(),
        attempts,
        "WT-ASSERT W-T17: a replace needed a retry with no outside holder"
    );
}

/// Run `body` on its own thread (the hooks are thread-local) under a watchdog,
/// so an unbounded retry fails the test instead of hanging CI.
fn with_watchdog(row: &'static str, body: impl FnOnce() + Send + 'static) {
    let (done, wait) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        body();
        let _ = done.send(());
    });
    match wait.recv_timeout(std::time::Duration::from_secs(10)) {
        Ok(()) => worker.join().unwrap(),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            panic!("WT-ASSERT {row}: the commit did not finish within 10 s")
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            if let Err(panic) = worker.join() {
                std::panic::resume_unwind(panic);
            }
        }
    }
}

// W-T20 A: an outside holder of authority.json that lets go after the first
// failed attempt; the commit then succeeds on attempt two.
#[test]
fn wt20_external_holder_released_after_one_attempt() {
    with_watchdog("W-T20/A", || {
        let (_root, settings) = committed();
        let store = reopen(&settings);
        let holder = std::fs::File::open(settings.authority_dir.join("authority.json")).unwrap();
        let holder = std::cell::RefCell::new(Some(holder));
        instrument::set_hook(Some(Box::new(move |which, _| {
            if which == Hook::ReplaceRetry {
                holder.borrow_mut().take();
            }
        })));
        let _ = instrument::take_attempts();
        let first = grant();
        let result = store.refresh_tokens(&alice(), &version(&first), &refreshed(&first));
        instrument::set_hook(None);
        let attempts = instrument::take_attempts();
        assert!(result.is_ok(), "WT-ASSERT W-T20/A: {result:?}");
        // One replace for the record, two for the manifest.
        assert_eq!(attempts, 3, "WT-ASSERT W-T20/A: attempts");
    });
}

// W-T20 B: an outside holder that never lets go; the commit refuses after
// exactly three manifest attempts and nothing is acknowledged.
#[test]
fn wt20_external_holder_never_released() {
    with_watchdog("W-T20/B", || {
        let (_root, settings) = committed();
        let store = reopen(&settings);
        let holder = std::fs::File::open(settings.authority_dir.join("authority.json")).unwrap();
        let _ = instrument::take_attempts();
        let first = grant();
        let result = store.refresh_tokens(&alice(), &version(&first), &refreshed(&first));
        let attempts = instrument::take_attempts();
        assert_eq!(
            result.err(),
            Some(AccountError::StorageUnavailable),
            "WT-ASSERT W-T20/B"
        );
        assert_eq!(attempts, 4, "WT-ASSERT W-T20/B: attempts");
        drop(holder);
        // Release custody first: a reopen beside a live store is refused.
        drop(store);
        assert!(
            matches!(reopen(&settings).lookup(&alice()), Ok(AccountLookup::Connected(r)) if r.token_revision == first.token_revision),
            "WT-ASSERT W-T20/B: the refused refresh was acknowledged"
        );
    });
}

const LEGACY: &str = r#"{"access_token":"legacy-3x-access-token","token_type":"Bearer","refresh_token":"legacy-3x-refresh-token","expires_at":4102444800,"scope":"read write"}"#;

/// A 3.x token written the 3.x way (`fs::write`, inherited DACL) under a
/// parent whose inheritable DACL grants the user and BUILTIN\Users read.
fn legacy_token(row: &str) -> (tempfile::TempDir, PathBuf) {
    let root = tempfile::tempdir().unwrap();
    let parent = root.path().join("oauth");
    std::fs::create_dir(&parent).unwrap();
    let user = crate::private_fs::test_support::user_sid();
    let sddl = format!("O:{user}D:P(A;OICI;FA;;;{user})(A;OICI;FR;;;BU)");
    crate::private_fs::test_support::plant_sddl(row, &parent, &sddl, &sddl);
    let path = parent.join("0123456789abcdef_tokens.json");
    std::fs::write(&path, LEGACY).unwrap();
    icacls(row, &path, &["/setowner", &format!("*{user}")]);
    (root, path)
}

use crate::personal_accounts::storage::migration_source::{SourceRefusal, read_legacy_source};

// W-T10: an inherited-ACL 3.x token is refused, and the refusal names the
// foreign SID it inherited.
#[test]
fn wt10_legacy_token_inherited_acl_refuses() {
    let (_root, path) = legacy_token("W-T10");
    let refusal = read_legacy_source(&path).err();
    assert!(
        matches!(refusal, Some(SourceRefusal::NotPrivate { .. })),
        "WT-ASSERT W-T10: {refusal:?}"
    );
    let text = refusal.map(|r| r.to_string()).unwrap_or_default();
    assert!(
        text.contains("S-1-5-32-545"),
        "WT-ASSERT W-T10/message: {text}"
    );
}

// W-T10b: the icacls sequence the refusal prints turns a refused file into an
// accepted one.
#[test]
fn wt10b_legacy_token_remediation_works() {
    let (_root, path) = legacy_token("W-T10b");
    icacls("W-T10b", &path, &["/grant", "*S-1-1-0:R"]);
    icacls("W-T10b", &path, &["/setowner", "*S-1-5-32-544"]);
    let text = read_legacy_source(&path)
        .err()
        .map(|r| r.to_string())
        .unwrap_or_default();
    assert!(
        text.contains("S-1-1-0") && text.contains("S-1-5-32-544"),
        "WT-ASSERT W-T10b/message: {text}"
    );
    let commands: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("icacls "))
        .collect();
    assert!(
        !commands.is_empty(),
        "WT-ASSERT W-T10b: the refusal printed no icacls commands: {text}"
    );
    for command in commands {
        // Verbatim, as a user pastes it: cmd does not parse the escaped
        // quotes `Command::args` would add around the embedded `"`s.
        use std::os::windows::process::CommandExt as _;
        let ran = std::process::Command::new("cmd")
            .arg("/C")
            .raw_arg(command)
            .status();
        if !ran.is_ok_and(|s| s.success()) {
            fixture_fail("W-T10b", &format!("remediation command failed: {command}"));
        }
    }
    assert!(
        read_legacy_source(&path).is_ok(),
        "WT-ASSERT W-T10b: still refused after remediation"
    );
}

// W-T16: while a store is open its directories are pinned, so the parent
// cannot be renamed away or replaced (probe E6: error 5 for ancestors), and
// the store still reads its own record afterwards.
#[test]
fn wt16_open_store_blocks_ancestor_swap() {
    let root = tempfile::tempdir().unwrap();
    let parent = root.path().join("a");
    let mut settings = config(root.path());
    settings.store_dir = parent.join("records");
    settings.authority_dir = parent.join("authority");
    settings.max_entries = 8;
    let store = PersonalAccountStore::initialize(settings.clone()).unwrap();
    assert_eq!(store.commit_grant(&alice(), &grant()), Ok(()));
    let renamed = std::fs::rename(&parent, root.path().join("a2"));
    assert!(
        renamed.is_err(),
        "WT-ASSERT W-T16: an open store's parent was renamed"
    );
    assert!(
        matches!(store.lookup(&alice()), Ok(AccountLookup::Connected(_))),
        "WT-ASSERT W-T16: the store no longer reads its own record"
    );
}

/// Rows run only by the privileged CI step (`--ignored win_privileged::`).
mod win_privileged {
    use super::*;

    fn env(row: &str, var: &str) -> String {
        std::env::var(var).unwrap_or_else(|_| fixture_fail(row, &format!("{var} unset")))
    }

    // W-T14: a second, non-admin local account cannot open what the store
    // wrote, while it CAN read a control file beside it (so the denial comes
    // from the objects' own DACLs, not from the parent or the launch).
    #[test]
    #[ignore = "needs the privileged CI step"]
    fn wt14_second_user_cannot_read() {
        let row = "W-T14";
        let (user, pass) = (env(row, "MGW_PROBE_USER"), env(row, "MGW_PROBE_PASS"));
        let base = PathBuf::from(format!(r"C:\mgwt-{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();
        icacls(row, &base, &["/grant", "*S-1-5-32-545:(OI)(CI)RX"]);
        let control = base.join("control.txt");
        std::fs::write(&control, b"control").unwrap();
        let mut settings = config(&base);
        settings.max_entries = 8;
        let store = PersonalAccountStore::initialize(settings.clone()).unwrap();
        assert_eq!(store.commit_grant(&alice(), &grant()), Ok(()));
        drop(store);
        let targets = [
            ("control", control.clone()),
            ("authority", settings.authority_dir.join("authority.json")),
            ("record", record_file(&settings.store_dir)),
        ];
        // No child process: a service session cannot reliably start one under
        // another account. The second user's token comes from LogonUser, and
        // each read runs impersonated, so the kernel checks that token against
        // each file's DACL.
        let paths: Vec<String> = targets
            .iter()
            .map(|(name, path)| format!("@('{name}','{}')", path.display()))
            .collect();
        let script = format!(
            r#"Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices;
public static class MgwLogon {{
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  public static extern bool LogonUserW(string u, string d, string p, int type, int prov, out IntPtr tok);
}}
'@
$t = [IntPtr]::Zero
if (-not [MgwLogon]::LogonUserW('{user}', '.', '{pass}', 2, 0, [ref]$t)) {{
  if (-not [MgwLogon]::LogonUserW('{user}', '.', '{pass}', 3, 0, [ref]$t)) {{ throw ('LogonUser failed: ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error()) }}
}}
$h = New-Object Microsoft.Win32.SafeHandles.SafeAccessTokenHandle $t
$id = New-Object System.Security.Principal.WindowsIdentity $t
$id.Groups | ForEach-Object {{ $_.Value }}
foreach ($pair in @({list})) {{
  $name = $pair[0]; $path = $pair[1]
  $ok = [System.Security.Principal.WindowsIdentity]::RunImpersonated($h, [Func[bool]] {{
    try {{ [System.IO.File]::ReadAllBytes($path) | Out-Null; $true }} catch {{ $false }} }})
  if ($ok) {{ "READ $name" }} else {{ "DENIED $name" }}
}}"#,
            list = paths.join(","),
        );
        let exit = std::process::Command::new("powershell")
            .env_remove("PSModulePath")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .output();
        let text = exit
            .as_ref()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default();
        let stderr = exit
            .as_ref()
            .map(|o| String::from_utf8_lossy(&o.stderr).into_owned())
            .unwrap_or_default();
        if !exit.as_ref().is_ok_and(|o| o.status.success()) {
            fixture_fail(
                row,
                &format!("the second user's token failed: {text} {stderr}"),
            );
        }
        if text.contains("S-1-5-32-544") {
            fixture_fail(row, "the second user's token holds Administrators");
        }
        if !text.contains("READ control") {
            fixture_fail(
                row,
                &format!("the second user could not read the control file: {text} {stderr}"),
            );
        }
        for name in ["authority", "record"] {
            assert!(
                text.contains(&format!("DENIED {name}")),
                "WT-ASSERT W-T14/{name}: a second user read it: {text}"
            );
        }
    }
}

// W-T26: residue at the next scratch name the store draws is skipped, not
// written or removed, and the commit succeeds on a fresh name.
#[test]
fn wt26_scratch_residue_does_not_block_commit() {
    use crate::personal_accounts::storage::commit::next_scratch;
    let (_root, settings, store) = empty_store(8);
    let residue = settings.authority_dir.join(".authority.json.r26.tmp");
    std::fs::write(&residue, b"someone else's").unwrap();
    // The record and the manifest each draw once; both draws get the suffix.
    next_scratch::push("r26");
    next_scratch::push("r26");
    assert_eq!(
        store.commit_grant(&alice(), &grant()),
        Ok(()),
        "WT-ASSERT W-T26: residue at the drawn scratch name blocked the commit"
    );
    assert_eq!(
        std::fs::read(&residue).ok().as_deref(),
        Some(&b"someone else's"[..]),
        "WT-ASSERT W-T26: the residue was written or removed"
    );
    drop(store);
    assert!(matches!(
        reopen(&settings).lookup(&alice()),
        Ok(AccountLookup::Connected(_))
    ));
}

// W-T16b: between judging the store directories and taking custody, only the
// held directory handles keep the judged directory in place; a rename attempted
// in that window is refused and the store opens over what it judged.
#[test]
fn wt16b_judged_directory_is_held_until_custody() {
    let (_root, settings) = committed();
    let moved = std::sync::Arc::new(std::sync::Mutex::new(None));
    let (seen, dir) = (std::sync::Arc::clone(&moved), settings.store_dir.clone());
    instrument::set_hook(Some(Box::new(move |which, _path| {
        if which == Hook::AfterDirJudged {
            let result = std::fs::rename(&dir, dir.with_extension("moved"));
            *seen.lock().unwrap() = Some(result.is_ok());
        }
    })));
    let opened = PersonalAccountStore::open(settings);
    instrument::set_hook(None);
    assert_eq!(
        *moved.lock().unwrap(),
        Some(false),
        "WT-ASSERT W-T16b: the judged store directory was renamed before custody"
    );
    assert!(
        matches!(
            opened.map(|s| s.lookup(&alice())),
            Ok(Ok(AccountLookup::Connected(_)))
        ),
        "WT-ASSERT W-T16b: the store did not open over what it judged"
    );
}

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8833 E8/E8.1: the core-dump guard. LEASE-T10 judges each call's failure
//! through `classify`; LEASE-T11 applies the real guard in a child process and
//! reads the result back with rustix's own getters.

use super::{DumpGuard, classify};

fn failed() -> std::io::Result<()> {
    Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
}

/// LEASE-T10: each call's failure is named, so the lease refusal says which.
#[test]
fn lease_t10_each_failed_call_is_named() {
    assert_eq!(classify(&Ok(()), Some(&Ok(()))), DumpGuard::Applied);
    assert_eq!(
        classify(&Ok(()), None),
        DumpGuard::Applied,
        "no dumpable call here"
    );
    assert_eq!(
        classify(&failed(), Some(&Ok(()))),
        DumpGuard::Failed("setrlimit_core")
    );
    assert_eq!(
        classify(&Ok(()), Some(&failed())),
        DumpGuard::Failed("prctl_dumpable")
    );
    assert_eq!(
        classify(&failed(), Some(&failed())),
        DumpGuard::Failed("setrlimit_core"),
        "the first failed call is named"
    );
    assert_eq!(DumpGuard::Applied.refusal_detail(), None);
    assert_eq!(
        DumpGuard::Failed("prctl_dumpable").refusal_detail(),
        Some("prctl_dumpable")
    );
    assert_eq!(
        DumpGuard::Unsupported.refusal_detail(),
        Some("platform_unsupported")
    );
}

/// The child half of LEASE-T11: runs only when its parent sets the variable.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn lease_t11_child() {
    if std::env::var_os("MCPGW_DUMP_GUARD_CHILD").is_none() {
        return;
    }
    assert_eq!(super::ensure(), DumpGuard::Applied);
    let limit = rustix::process::getrlimit(rustix::process::Resource::Core);
    assert_eq!(
        (limit.current, limit.maximum),
        (Some(0), Some(0)),
        "{limit:?}"
    );
    assert_eq!(
        rustix::process::dumpable_behavior().ok(),
        Some(rustix::process::DumpableBehavior::NotDumpable)
    );
}

/// LEASE-T11: on Linux the guard leaves a zero core limit and a process that
/// is not dumpable. Run in a child, since both are process-wide and one-way.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn lease_t11_linux_guard_is_observable() {
    let exe = std::env::current_exe().expect("test binary");
    let out = std::process::Command::new(exe)
        .args([
            "--exact",
            "security::dump_guard::tests::lease_t11_child",
            "--test-threads=1",
        ])
        .env("MCPGW_DUMP_GUARD_CHILD", "1")
        .output()
        .expect("child runs");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && text.contains("1 passed"),
        "child guard failed: {text}{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

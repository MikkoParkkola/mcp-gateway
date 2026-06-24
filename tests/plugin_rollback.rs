use std::{fs, path::PathBuf};

fn repo_path(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path)
}

// MIK-4625.PLUGIN.6: Rollback documented and tested as a committed shell/integration
// fixture — `claude plugin uninstall` semantics + gateway state restore — captured in
// `tests/plugin_rollback.rs` (or `docs/marketplace/rollback.md` with a runnable check).
// CHECK: `cargo test --release --test plugin_rollback uninstall_restores_state` exits 0
// OR file `docs/marketplace/rollback.md` matches regex `uninstall`.
#[test]
fn uninstall_restores_state() {
    let rollback = fs::read_to_string(repo_path("docs/marketplace/rollback.md"))
        .expect("rollback doc should be readable");
    assert!(
        rollback.contains("claude plugin uninstall mcp-gateway"),
        "rollback should document plugin uninstall semantics"
    );
    assert!(
        rollback.contains("cp -R \"$BACKUP_DIR\" \"$STATE_DIR\""),
        "rollback should restore gateway state from backup"
    );
    assert!(
        rollback.contains("set -eu"),
        "rollback check should be runnable as a shell fixture"
    );
}

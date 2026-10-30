// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Windows rows: the resolve and compare halves of the W table on a real
//! `TempDir`, and the verbatim UNC comparison through the resolver seam (W5b,
//! W10, W11, W14, R14). Run in Windows CI. Batch 4c.

use std::sync::Arc;
use std::time::Instant;

use serde_json::json;

use super::super::*;
use super::seam::{forced, real, seamed};
use super::tree::{Fx, Seen, both, root_rule};

/// W10, W11: the `TempDir` inside path spelt with backslashes, forward
/// slashes, a verbatim prefix and changed case is allowed; each spelling's
/// outside twin gives the root finding.
#[test]
fn w10_w11_spellings_of_an_inside_path() {
    let fx = Fx::new(&["path"], FirewallAction::Block);
    let base = fx.dir.path().to_string_lossy().into_owned();
    let verbatim = std::fs::canonicalize(fx.dir.path())
        .expect("canonical")
        .to_string_lossy()
        .into_owned();
    let spellings = [
        (
            "backslash",
            format!(r"{base}\safe\f"),
            format!(r"{base}\outside\f"),
        ),
        (
            "forward",
            format!("{base}/safe/f").replace('\\', "/"),
            format!("{base}/outside/f").replace('\\', "/"),
        ),
        (
            "verbatim",
            format!(r"{verbatim}\safe\f"),
            format!(r"{verbatim}\outside\f"),
        ),
        (
            "case",
            format!(r"{base}\SAFE\F").to_uppercase(),
            format!(r"{base}\OUTSIDE\F").to_uppercase(),
        ),
    ];
    for (row, inside, outside) in spellings {
        assert_eq!(
            both(&fx, "read_file", &json!({"path": inside})),
            Seen::Allowed,
            "{row}"
        );
        assert_eq!(
            both(&fx, "read_file", &json!({"path": outside})),
            Seen::Outside(FirewallAction::Block),
            "{row}"
        );
    }
}

/// Answers every read as if `C:\safe` were a disk folder and the UNC share
/// existed, so a row compares verbatim forms without a server.
struct Shares;

impl Resolve for Shares {
    fn resolve(&self, op: &ResolveOp, _deadline: Instant) -> std::io::Result<Resolved> {
        match op {
            ResolveOp::Metadata(_) => Ok(Resolved::Kind(EntryKind::Directory)),
            ResolveOp::ReadDir(_) => Ok(Resolved::Entries(Vec::new())),
            ResolveOp::Canonicalize(p) => {
                let s = p.to_string_lossy();
                let verbatim = if let Some(unc) = s.strip_prefix(r"\\?\") {
                    unc.to_string()
                } else if let Some(share) = s.strip_prefix(r"\\") {
                    format!(r"UNC\{share}")
                } else {
                    s.into_owned()
                };
                Ok(Resolved::Path(format!(r"\\?\{verbatim}").into()))
            }
        }
    }
}

/// W5b, W14: a UNC path and a verbatim UNC path under a disk root give the
/// root finding; control: a disk path under the root is allowed.
#[test]
fn w5b_w14_unc_paths_under_a_disk_root_are_outside() {
    let fx = Fx::with_rules(|_| {
        vec![root_rule(
            "read_file",
            &[r"C:\safe".to_string()],
            &["path"],
            FirewallAction::Block,
        )]
    });
    let fx = seamed(fx, |fw| fw.with_resolver(Arc::new(Shares)));
    let outside = Seen::Outside(FirewallAction::Block);
    assert_eq!(
        both(&fx, "read_file", &json!({"path": r"\\server\share\x"})),
        outside,
        "W5b"
    );
    let unc = r"\\?\UNC\server\share\x";
    assert_eq!(
        both(&fx, "read_file", &json!({"path": unc})),
        outside,
        "W14"
    );
    assert_eq!(
        both(&fx, "read_file", &json!({"path": r"C:\safe\x"})),
        Seen::Allowed
    );
}

/// R14: a path on a drive that does not exist has no existing prefix:
/// `unresolvable`. Skipped, with the reason logged, if every letter tried
/// is mounted.
#[test]
fn r14_no_existing_prefix_is_unresolvable() {
    let Some(drive) = ['Q', 'R', 'W', 'X']
        .into_iter()
        .find(|d| real(&ResolveOp::Metadata(format!(r"{d}:\").into())).is_err())
    else {
        eprintln!("R14 skipped: drives Q, R, W and X are all mounted on this runner");
        return;
    };
    let fx = Fx::new(&["path"], FirewallAction::Block);
    let args = json!({"path": format!(r"{drive}:\x\y")});
    assert_eq!(forced(&fx, &args), Some(RootReason::Unresolvable));
}

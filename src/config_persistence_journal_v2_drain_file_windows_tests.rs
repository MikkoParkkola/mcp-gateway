// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Off Unix the file drain fails closed: no owner check exists there yet, so a present file is
//! refused and kept as found. An absent file is nothing to drain.

use super::super::super::fixtures::config;
use super::super::DrainError;
use super::super::fixtures::{reopen, runtime};
use super::super::handover::abandoned_path;
use super::drain_abandoned;

#[test]
fn drain_refuses_off_unix() {
    const ROW: &str = "drain_refuses_off_unix";
    let (_dir, path, locked) = config();
    let mut session = reopen(locked);
    assert_eq!(
        runtime(drain_abandoned(&mut session, None)),
        Ok(()),
        "{ROW}: no file, nothing to drain"
    );
    let planted = b"12\tnot-a-checksum\tnot-a-frame\n".to_vec();
    std::fs::write(abandoned_path(&path), &planted).expect("a planted file");
    assert_eq!(
        runtime(drain_abandoned(&mut session, None)),
        Err(DrainError::FileRefused),
        "{ROW}: refused before any read"
    );
    assert_eq!(
        std::fs::read(abandoned_path(&path)).expect("the file is kept"),
        planted,
        "{ROW}: byte-identical"
    );
}

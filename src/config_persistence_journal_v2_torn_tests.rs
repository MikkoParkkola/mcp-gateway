// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Real partial bytes and complete-without-newline controls for D7.

use std::io::Write as _;
use std::sync::Arc;

use serde_json::Value;

use super::super::fixtures::collect_case;
use super::crash_fixtures::setup;
use super::fixtures::{Live, OUTCOME, WRITER, payload, retry, runtime, terminal_count};
use crate::config_persistence::crash_fs::{self, Mode};
use crate::security::transparency_log::TransparencyLogger;
use crate::security::transparency_log::settle::Role;

pub(super) fn cases(failures: &mut Vec<String>, row: &str) {
    for complete in [false, true] {
        let case = if complete {
            "valid_no_newline"
        } else {
            "invalid_partial"
        };
        let expected = "observe real tail; repair chain; one logical terminal";
        collect_case(failures, row, case, expected, || {
            torn_case(row, complete);
            Ok(())
        });
    }
}

fn torn_case(row: &str, complete: bool) {
    let live = Live::new();
    let mut owner = setup(&live, row);
    if complete {
        runtime(
            live.log
                .settle(&live.log.log_id(), WRITER, Role::Outcome, payload(OUTCOME)),
        )
        .expect("seed complete terminal control");
    }
    let original_terminal = complete.then(|| {
        live.records()
            .into_iter()
            .find(|record| record["token"] == WRITER && record["event"] == Role::Outcome.event())
            .expect("complete terminal before newline removal")
    });
    let Live {
        dir,
        resolved,
        path,
        log_path,
        log,
        config,
    } = live;
    drop(log);
    let mut raw = std::fs::read(&log_path).expect(row);
    if complete {
        assert_eq!(
            raw.pop(),
            Some(b'\n'),
            "{row}: complete control starts newline terminated"
        );
        std::fs::write(&log_path, &raw).expect(row);
    } else {
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&log_path)
            .expect(row);
        file.write_all(b"{\"event\":").expect(row);
        file.sync_all().expect(row);
        raw.extend_from_slice(b"{\"event\":");
    }
    let overlay = crash_fs::arm_config(&path);
    crash_fs::cut(&resolved, Mode::KeepAll);
    drop(overlay);
    assert_eq!(
        std::fs::read(&log_path).expect(row),
        raw,
        "{row}: torn bytes visible before logger repair"
    );
    let log = Arc::new(TransparencyLogger::open(Arc::clone(&config)).expect("reopen torn logger"));
    log.keep_test_dir(Arc::clone(&dir));
    let live = Live {
        dir,
        resolved,
        path,
        log_path,
        log,
        config,
    };
    if let Some(original) = original_terminal {
        preserved_terminal(&live, &original, row);
    }
    retry(&mut owner, &live, row);
    assert_eq!(
        terminal_count(&live.records(), WRITER),
        1,
        "{row}: equal surviving terminal retries collapse"
    );
    super::crash_assertions::accounted(&live.records(), row, &[WRITER.to_owned()]);
    live.verify(row);
}

fn preserved_terminal(live: &Live, original: &Value, row: &str) {
    let records = live.records();
    let terminals: Vec<_> = records
        .iter()
        .filter(|record| record["token"] == WRITER && record["event"] == Role::Outcome.event())
        .collect();
    assert_eq!(
        terminals.len(),
        1,
        "{row}: complete terminal survives reopen before retry"
    );
    assert_eq!(
        terminals[0]["counter"], original["counter"],
        "{row}: original counter preserved"
    );
    assert_eq!(
        terminals[0]["entry_hash"], original["entry_hash"],
        "{row}: original hash preserved"
    );
    assert_eq!(
        terminals[0], original,
        "{row}: complete original contents preserved"
    );
}

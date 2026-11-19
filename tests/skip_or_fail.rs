// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rows for the shared skip helper: a test that skips because its host lacks something prints a
//! skip line, except where `TESTS_REQUIRE_ALL` is set (CI), where the skip is a failure that
//! names the requirement. The helper runs in a child of this test binary so each row owns its
//! environment.

use std::process::{Command, Output};

const REQUIREMENT: &str = "a planted requirement";

fn child(required: bool) -> Output {
    let mut cmd = Command::new(std::env::current_exe().expect("this test binary"));
    cmd.args(["--ignored", "--exact", "the_skip_child", "--nocapture"])
        .env_remove("TESTS_REQUIRE_ALL");
    if required {
        cmd.env("TESTS_REQUIRE_ALL", "1");
    }
    cmd.output().expect("the child runs")
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// Run only by the rows below, never on its own.
#[test]
#[ignore = "run by the rows below, in a child with its own environment"]
fn the_skip_child() {
    mcp_gateway::gateway::test_helpers::skip_or_fail(REQUIREMENT);
}

#[test]
fn without_the_required_variable_a_skip_prints_its_line_and_passes() {
    let out = child(false);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stderr(&out).contains(&format!("skipped: {REQUIREMENT}")),
        "{}",
        stderr(&out)
    );
}

#[test]
fn with_the_required_variable_a_skip_fails_and_names_the_requirement() {
    let out = child(true);
    assert!(!out.status.success(), "{}", stderr(&out));
    assert!(
        stderr(&out).contains(&format!(
            "required here but unavailable on this host: {REQUIREMENT}"
        )),
        "{}",
        stderr(&out)
    );
}

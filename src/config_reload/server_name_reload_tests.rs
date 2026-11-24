// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A reload whose file names a server with a control character is refused like a start, and the running config
//! stays as it was.

use super::reload_test_support::reload_after;

const ONE_SERVER: &str = "backends:\n  steady:\n    command: \"true\"\n";

#[test]
fn a_reload_naming_a_server_with_a_line_feed_is_refused_and_the_running_config_stays() {
    let with_bad_name = format!("{ONE_SERVER}  \"ok\\nFORGED x\":\n    command: \"true\"\n");
    let (outcome, running) = reload_after(ONE_SERVER, &with_bad_name);
    let Err(why) = outcome else {
        panic!("a reload naming a server with a line feed must be refused");
    };
    assert!(why.contains("control character"), "{why:?}");
    assert!(
        !why.chars().any(char::is_control),
        "the refusal carries a raw control character: {why:?}"
    );
    let names: Vec<String> = running.get().backends.keys().cloned().collect();
    assert_eq!(names, ["steady"], "the running config changed");
}

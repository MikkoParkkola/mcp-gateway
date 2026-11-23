// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A reload whose file names a server with a control character is refused like a start, and the running config
//! stays as it was.

use super::{LiveConfig, load_config_patch};
use crate::gateway::test_helpers::write_owner_only;

const ONE_SERVER: &str = "backends:\n  steady:\n    command: \"true\"\n";

#[test]
fn a_reload_naming_a_server_with_a_line_feed_is_refused_and_the_running_config_stays() {
    let scratch = tempfile::tempdir().expect("a scratch dir");
    let file = scratch.path().join("gateway.yaml");
    write_owner_only(&file, ONE_SERVER).expect("the first file");
    let first = crate::config::Config::load_evaluated(Some(&file)).expect("the first file loads");
    let running = std::sync::Arc::new(LiveConfig::new(first.config.clone()));
    let environment = crate::config::LiveEnv::new(first.overlay, first.env_paths);

    let with_bad_name = format!("{ONE_SERVER}  \"ok\\nFORGED x\":\n    command: \"true\"\n");
    write_owner_only(&file, with_bad_name).expect("the second file");
    let outcome = load_config_patch(&file, &running, &environment);
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

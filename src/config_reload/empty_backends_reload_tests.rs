// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8299: a `backends:` section with every entry commented out reads as
//! YAML null. A reload of such a file is "no backends", as a startup load is,
//! not a refusal.

use std::sync::Arc;

use super::*;
use crate::config::{Config, LiveEnv};
use crate::gateway::test_helpers::write_owner_only;

#[test]
fn a_reload_reads_an_empty_backends_section_as_none() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("gateway.yaml");
    write_owner_only(&config, "backends:\n  tavily:\n    command: \"true\"\n")
        .expect("write config");
    let startup = Config::load_evaluated(Some(&config)).expect("startup loads");
    let live = Arc::new(LiveConfig::new(startup.config.clone()));
    let env = LiveEnv::new(startup.overlay, startup.env_paths);

    write_owner_only(&config, "backends:\n  # tavily:\n  #   command: \"true\"\n")
        .expect("comment it out");
    let evaluated = load_config_patch(&config, &live, &env)
        .unwrap_or_else(|e| panic!("a reload of an empty backends section is refused: {e}"));
    assert!(
        evaluated.config.backends.is_empty(),
        "{:?}",
        evaluated.config.backends.keys()
    );
}

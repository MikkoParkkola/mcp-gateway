// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use std::path::Path;

pub(crate) fn fixture(home: &Path, name: &str) -> String {
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/mik_8398")
        .join(name);
    let target = home.join(name);
    mcp_gateway::gateway::test_helpers::write_owner_only(
        &target,
        std::fs::read(&source).expect("fixture"),
    )
    .expect("copy");
    target.to_str().expect("utf-8").to_owned()
}

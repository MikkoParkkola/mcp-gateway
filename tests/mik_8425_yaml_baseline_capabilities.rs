// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8425 MIG.0: the typed capability definition `serde_yaml` 0.9.34 builds
//! from every file in `capabilities/`, recorded before the parser is
//! replaced.
//!
//! Each row is the digest of `parse_capability`'s result as JSON with object
//! keys sorted (definitions hold `HashMap`s, which serialize in a different
//! order each run), or the refusal. The SHA-256 pin is over the file text,
//! so it does not depend on the parser and is not recorded here.
//!
//! Limit: the JSON form is the definition's `Serialize` output. A field that
//! serialization skips (`skip`, or `skip_serializing_if` at its default) is
//! not covered by the digest. `trees.tsv` covers the same files as untyped
//! trees, so a skipped field that the parser reads differently still shows
//! there.

#[path = "common/mik_8425_golden.rs"]
mod golden;

use mcp_gateway::capability::parse_capability;

/// Capability files recorded on 2026-10-17: 143. At least this many must
/// still be comparable (unchanged since recording).
const MIN_COMPARED: usize = 120;

fn reading(text: &str) -> String {
    match parse_capability(text) {
        Ok(definition) => match golden::canonical_digest(&definition) {
            Ok(digest) => digest,
            Err(error) => format!("JSON-ERR {}", golden::one_line(&error.to_string())),
        },
        Err(error) => format!("ERR {}", golden::one_line(&error.to_string())),
    }
}

/// Every unchanged capability file parses to the definition recorded with
/// `serde_yaml` 0.9.34.
#[test]
fn every_capability_parses_as_recorded() {
    golden::assert_keyed_golden("capabilities.tsv", MIN_COMPARED, reading);
}

/// Prints the golden for review; never part of a normal run.
#[test]
#[ignore = "records tests/fixtures/mik_8425_yaml/capabilities.tsv; run with --ignored --nocapture"]
fn record_capabilities_golden() {
    let paths = golden::files_under("capabilities", &["yaml", "yml"]);
    print!(
        "----- BEGIN capabilities.tsv -----\n{}----- END capabilities.tsv -----\n",
        golden::keyed_rows(&paths, reading)
    );
}

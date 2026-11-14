// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! NORM.2: the NFC crates are pinned exactly in `Cargo.toml`, read the same
//! way from the source tree and from the manifest `cargo package` writes.

/// The NFC crates that must be pinned exactly.
const NFC_CRATES: [&str; 4] = [
    "icu_normalizer",
    "icu_normalizer_data",
    "icu_properties",
    "icu_properties_data",
];

/// Whether `path` (a table name without its brackets) holds dependencies:
/// `dependencies`, `dev-dependencies` or `build-dependencies`, plain or under
/// a `target.<spec>` table.
fn is_dependency_table(path: &str) -> bool {
    ["dependencies", "dev-dependencies", "build-dependencies"]
        .iter()
        .any(|kind| {
            path == *kind || (path.starts_with("target.") && path.ends_with(&format!(".{kind}")))
        })
}

/// Every place `manifest` names `krate` as a dependency, as the text that
/// carries its version, comments removed. Two forms: an inline entry in a
/// dependency table (`krate = "=1"` or `krate = { version = "=1", .. }`), as
/// the source tree writes it, and a table of its own (`[dependencies.krate]`
/// with its `version` line), as `cargo package` writes the manifest of the
/// published crate. A table with no version line comes back as its header.
fn dependency_entries(manifest: &str, krate: &str) -> Vec<String> {
    let mut entries = Vec::new();
    let mut section = String::new();
    let mut open: Option<String> = None;
    for raw in manifest.lines() {
        let line = raw.split('#').next().unwrap_or_default().trim();
        if let Some(path) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            entries.extend(open.take());
            section = path.to_owned();
            if path
                .strip_suffix(&format!(".{krate}"))
                .is_some_and(is_dependency_table)
            {
                open = Some(line.to_owned());
            }
        } else if let Some(table) = &open {
            if line.starts_with("version") {
                entries.push(format!("{table} {line}"));
                open = None;
            }
        } else if is_dependency_table(&section)
            && (line.starts_with(&format!("{krate} =")) || line.starts_with(&format!("{krate}=")))
        {
            entries.push(line.to_owned());
        }
    }
    entries.extend(open);
    entries
}

/// What is wrong with the NFC pins in `manifest`, one line per crate.
fn pin_problems(manifest: &str) -> Vec<String> {
    let mut problems = Vec::new();
    for krate in NFC_CRATES {
        let entries = dependency_entries(manifest, krate);
        match entries.as_slice() {
            [entry] if entry.contains("version = \"=") || entry.contains(" = \"=") => {}
            [entry] => problems.push(format!(
                "{krate} must be pinned with an exact `=` version: {entry}"
            )),
            _ => problems.push(format!(
                "{krate} must be a direct dependency, once: {entries:?}"
            )),
        }
    }
    problems
}

/// NORM.2: the NFC crate and its data crate are pinned to an exact version in
/// `Cargo.toml`, where `cargo install` honours it (it ignores Cargo.lock), and
/// neither may become a caret range again. Read from the source tree and from
/// the packaged crate alike (the packaged manifest is cargo's normalized form).
/// Mutant: loosen either to a plain or caret version, or drop the data crate.
#[test]
fn the_nfc_crates_are_pinned_exactly_in_cargo_toml() {
    let manifest = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"),
    )
    .expect("Cargo.toml")
    .replace('\r', "");
    assert_eq!(pin_problems(&manifest), Vec::<String>::new());
}

/// NORM.2: the pin check reads both manifest forms the same way: exact pins
/// pass in each, and a loosened, missing or doubled pin is refused in each.
#[test]
fn the_pin_check_reads_both_manifest_forms() {
    const SOURCE: &str = "[dependencies]\n\
        icu_normalizer = { version = \"=2.3.0\", default-features = false, features = [\"compiled_data\"] }\n\
        icu_normalizer_data = \"=2.3.0\"\n\
        icu_properties = { version = \"=2.3.0\", default-features = false }\n\
        icu_properties_data = \"=2.3.0\"\n";
    const PACKAGED: &str = "[dependencies.icu_normalizer]\n\
        version = \"=2.3.0\"\n\
        features = [\"compiled_data\"]\n\
        default-features = false\n\n\
        [dependencies.icu_normalizer_data]\n\
        version = \"=2.3.0\"\n\n\
        [dependencies.icu_properties]\n\
        version = \"=2.3.0\"\n\
        default-features = false\n\n\
        [dependencies.icu_properties_data]\n\
        version = \"=2.3.0\"\n";
    for (form, exact) in [("source", SOURCE), ("packaged", PACKAGED)] {
        assert_eq!(
            pin_problems(exact),
            Vec::<String>::new(),
            "{form}: exact pins pass"
        );
        let loose = exact.replacen("\"=2.3.0\"", "\"2.3.0\"", 1);
        let problems = pin_problems(&loose);
        assert_eq!(problems.len(), 1, "{form}: {problems:?}");
        assert!(
            problems[0].starts_with("icu_normalizer must be pinned"),
            "{form}: a loosened pin is refused: {problems:?}"
        );
        let dropped = exact.replace("icu_properties_data", "unrelated_crate");
        assert_eq!(
            pin_problems(&dropped),
            vec!["icu_properties_data must be a direct dependency, once: []".to_owned()],
            "{form}: a missing pin is refused"
        );
        let doubled =
            format!("{exact}[target.'cfg(unix)'.dependencies]\nicu_properties_data = \"=2.3.0\"\n");
        assert_eq!(
            pin_problems(&doubled).len(),
            1,
            "{form}: a doubled pin is refused"
        );
        let commented = loose.replacen("\"2.3.0\"", "\"2.3.0\" # version = \"=2.3.0\"", 1);
        assert_eq!(
            pin_problems(&commented).len(),
            1,
            "{form}: a comment is no pin"
        );
        let decoy = format!("{exact}[package.metadata.decoy]\nicu_normalizer_data = \"=2.3.0\"\n");
        assert_eq!(
            pin_problems(&decoy),
            Vec::<String>::new(),
            "{form}: a metadata table names no dependency"
        );
        let table = format!(
            "{exact}[target.'cfg(unix)'.dependencies.icu_properties_data]\nversion = \"=2.3.0\"\n"
        );
        assert_eq!(
            pin_problems(&table).len(),
            1,
            "{form}: a target table is a second entry"
        );
    }
}

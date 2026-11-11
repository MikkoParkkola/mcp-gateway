// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Shared, test-only UI access matrix fragments with named body expansion.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

/// Attributes retained from `#@` header lines, false when absent.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(in crate::gateway) struct Attributes {
    pub(in crate::gateway) scoped: bool,
    pub(in crate::gateway) store_writes: bool,
    pub(in crate::gateway) store_reads: bool,
}

/// One route's fragment; rows contain path, method, shape, caller, answer.
/// Answers are expanded literals, including status, never `@name` references.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::gateway) struct Fragment {
    pub(in crate::gateway) slug: String,
    /// The route path, independent of the directory used to load this file.
    pub(in crate::gateway) path: String,
    pub(in crate::gateway) attributes: Attributes,
    pub(in crate::gateway) rows: Vec<[String; 5]>,
}

/// A digest-only name: the same body can occur under different statuses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::gateway) struct NamedBody {
    pub(in crate::gateway) digest: String,
    pub(in crate::gateway) meaning: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::gateway) struct Loaded {
    /// Files ordered by slug, with row order retained within each file.
    pub(in crate::gateway) files: Vec<Fragment>,
    /// Names retained for rendering expanded answers back to references.
    pub(in crate::gateway) bodies: BTreeMap<String, NamedBody>,
}

/// Read all checked-in fragments under `env!("CARGO_MANIFEST_DIR")`.
/// Feature filtering belongs to consumers, so this includes cost rows.
pub(in crate::gateway) fn rows() -> Loaded {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/gateway/router");
    load_from(
        &root.join("ui_access_matrix.d"),
        &root.join("ui_access_matrix_bodies.tsv"),
    )
    .unwrap_or_else(|error| panic!("UI access matrix: {error}"))
}

/// Load explicit paths; diagnostics use basenames and one-based line numbers.
pub(in crate::gateway) fn load_from(dir: &Path, bodies_file: &Path) -> Result<Loaded, String> {
    let mut bodies = BTreeMap::new();
    let mut definitions = BTreeMap::new();
    let mut names_by_digest = BTreeMap::new();
    for (index, line) in read(bodies_file)?.lines().enumerate() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let at = location(bodies_file, index + 1);
        let cells: Vec<_> = line.split('\t').collect();
        let [name, digest, meaning] = cells.as_slice() else {
            return Err(format!(
                "{at}: expected 3 tab-separated cells, got {}",
                cells.len()
            ));
        };
        if name.is_empty() || digest.is_empty() {
            return Err(format!("{at}: body name and digest must not be empty"));
        }
        if bodies.contains_key(*name) {
            return Err(format!("{at}: duplicate body @{name}"));
        }
        if let Some(previous) = names_by_digest.insert(digest.to_string(), name.to_string()) {
            return Err(format!("{at}: digest {digest} already named @{previous}"));
        }
        definitions.insert(name.to_string(), index + 1);
        bodies.insert(
            name.to_string(),
            NamedBody {
                digest: digest.to_string(),
                meaning: meaning.to_string(),
            },
        );
    }
    let mut paths = Vec::new();
    for entry in fs::read_dir(dir).map_err(|error| format!("{}: {error}", dir.display()))? {
        let path = entry
            .map_err(|error| format!("{}: {error}", dir.display()))?
            .path();
        if path.extension().is_some_and(|extension| extension == "tsv") {
            paths.push(path);
        }
    }
    paths.sort();
    let mut used = BTreeSet::new();
    let mut files = Vec::new();
    for path in paths {
        files.push(load_fragment(&path, &bodies, &names_by_digest, &mut used)?);
    }
    for (name, line) in definitions {
        if !used.contains(&name) {
            return Err(format!(
                "{}: body @{name} is unused",
                location(bodies_file, line)
            ));
        }
    }
    Ok(Loaded { files, bodies })
}

fn read(path: &Path) -> Result<String, String> {
    fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))
}

fn location(path: &Path, line: usize) -> String {
    format!(
        "{}:{line}",
        path.file_name().unwrap_or_default().to_string_lossy()
    )
}

fn slug(path: &str) -> Option<String> {
    if path == "/dashboard" {
        return Some("__dashboard".to_string());
    }
    path.strip_prefix("/ui/api/")
        .map(|tail| tail.replace('/', "__").replace(['{', '}'], "_"))
}

fn load_fragment(
    path: &Path,
    bodies: &BTreeMap<String, NamedBody>,
    names_by_digest: &BTreeMap<String, String>,
    used: &mut BTreeSet<String>,
) -> Result<Fragment, String> {
    let slug = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .ok_or_else(|| format!("{}: filename is not UTF-8", path.display()))?
        .to_string();
    let mut file = Fragment {
        slug,
        path: String::new(),
        attributes: Attributes::default(),
        rows: Vec::new(),
    };
    let mut keys = BTreeSet::new();
    for (index, line) in read(path)?.lines().enumerate() {
        let at = location(path, index + 1);
        if let Some(attribute) = line.strip_prefix("#@") {
            match attribute.trim() {
                "scoped" => file.attributes.scoped = true,
                "store_writes" => file.attributes.store_writes = true,
                "store_reads" => file.attributes.store_reads = true,
                unknown => return Err(format!("{at}: unknown attribute {unknown}")),
            }
            continue;
        }
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let cells: Vec<_> = line.split('\t').collect();
        let count = cells.len();
        let mut row: [String; 5] = cells
            .into_iter()
            .map(String::from)
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| format!("{at}: expected 5 tab-separated cells, got {count}"))?;
        let actual_slug =
            self::slug(&row[0]).ok_or_else(|| format!("{at}: invalid UI route {}", row[0]))?;
        if actual_slug != file.slug {
            return Err(format!(
                "{at}: path {} has slug {actual_slug}, expected {}",
                row[0], file.slug
            ));
        }
        if !file.path.is_empty() && file.path != row[0] {
            return Err(format!("{at}: multiple route paths in one fragment"));
        }
        file.path.clone_from(&row[0]);
        let key = row[..4].join("\t");
        if !keys.insert(key.clone()) {
            return Err(format!("{at}: duplicate row {key}"));
        }
        if let Some((status, digest)) = row[4].split_once(':') {
            if let Some(name) = digest.strip_prefix('@') {
                let body = bodies
                    .get(name)
                    .ok_or_else(|| format!("{at}: undefined body @{name}"))?;
                used.insert(name.to_string());
                row[4] = format!("{status}:{}", body.digest);
            } else if let Some(name) = names_by_digest.get(digest) {
                return Err(format!("{at}: inline digest {digest} must use @{name}"));
            }
        }
        file.rows.push(row);
    }
    if file.rows.is_empty() {
        return Err(format!("{}: fragment has no rows", location(path, 1)));
    }
    Ok(file)
}

impl Loaded {
    /// Render TSV contents with attributes and digest-only body references.
    pub(in crate::gateway) fn render_block(&self, file: &Fragment) -> String {
        let mut block = String::new();
        for (name, enabled) in [
            ("scoped", file.attributes.scoped),
            ("store_writes", file.attributes.store_writes),
            ("store_reads", file.attributes.store_reads),
        ] {
            if enabled {
                block.push_str("#@ ");
                block.push_str(name);
                block.push('\n');
            }
        }
        for row in &file.rows {
            let mut row = row.clone();
            if let Some((status, digest)) = row[4].split_once(':')
                && let Some((name, _)) = self.bodies.iter().find(|(_, body)| body.digest == digest)
            {
                row[4] = format!("{status}:@{name}");
            }
            block.push_str(&row.join("\t"));
            block.push('\n');
        }
        block
    }
}

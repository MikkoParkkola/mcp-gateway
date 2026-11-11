// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Reloadable per-file mismatch output and shared-body divergence diagnostics.

use std::fmt::Write as _;

use super::{Matrix, routes};
use crate::gateway::router::ui_access_matrix_rows::Loaded;

pub(super) fn check_coverage(loaded: &Loaded, computed: &Matrix) -> Result<(), String> {
    for file in &loaded.files {
        if !cfg!(feature = "cost-governance") && file.path == routes::UI_COSTS {
            continue;
        }
        let prefix = format!("{}\t", file.path);
        if !computed.keys().any(|key| key.starts_with(&prefix)) {
            return Err(format!("{}.tsv: fragment has no computed rows", file.slug));
        }
    }
    Ok(())
}

pub(super) fn render(loaded: &Loaded, computed: &Matrix) -> (String, Vec<String>) {
    let mut blocks = String::new();
    let mut divergent = Vec::new();
    for file in &loaded.files {
        if !cfg!(feature = "cost-governance") && file.path == routes::UI_COSTS {
            continue;
        }
        let mut rendered = file.clone();
        rendered.rows.clear();
        for (key, answer) in computed {
            let cells: Vec<_> = key.split('\t').collect();
            let [path, method, shape, caller] = cells.as_slice() else {
                panic!("a computed matrix key has four cells: {key:?}");
            };
            if *path == file.path {
                rendered.rows.push([
                    path.to_string(),
                    method.to_string(),
                    shape.to_string(),
                    caller.to_string(),
                    answer.clone(),
                ]);
            }
        }
        let _ = writeln!(blocks, "# file: ui_access_matrix.d/{}.tsv", file.slug);
        blocks.push_str(&loaded.render_block(&rendered));
        for row in &file.rows {
            let Some((status, digest)) = row[4].split_once(':') else {
                continue;
            };
            let Some((name, _)) = loaded.bodies.iter().find(|(_, body)| body.digest == digest)
            else {
                continue;
            };
            let key = row[..4].join("\t");
            if let Some(answer) = computed.get(&key) {
                let (actual_status, actual_digest) = answer.split_once(':').unwrap_or((answer, ""));
                if actual_status == status && actual_digest != digest {
                    divergent.push(format!(
                        "{key}: expected {status}:@{name} ({digest}), got {answer}"
                    ));
                }
            }
        }
    }
    (blocks, divergent)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::router::ui_access_matrix_rows::{
        Attributes, Fragment, NamedBody, load_from,
    };

    fn fixture(path: &str, slug: &str) -> Loaded {
        Loaded {
            files: vec![Fragment {
                slug: slug.to_string(),
                path: path.to_string(),
                attributes: Attributes {
                    scoped: true,
                    ..Attributes::default()
                },
                rows: vec![[path, "GET", "plain", "NoKey", "401:de6b55925ef7"].map(String::from)],
            }],
            bodies: [(
                "refused".to_string(),
                NamedBody {
                    digest: "de6b55925ef7".to_string(),
                    meaning: "refusal".to_string(),
                },
            )]
            .into(),
        }
    }

    #[test]
    fn rejects_a_stored_fragment_without_computed_rows() {
        let loaded = fixture(routes::UI_STATUS, "status");
        assert_eq!(
            check_coverage(&loaded, &Matrix::new()).unwrap_err(),
            "status.tsv: fragment has no computed rows"
        );
        let computed = [(
            format!("{}extra\tGET\tplain\tNoKey", routes::UI_STATUS),
            "401".into(),
        )]
        .into();
        assert!(check_coverage(&loaded, &computed).is_err());
    }

    #[test]
    fn only_exempts_uncomputed_costs_when_the_feature_is_off() {
        let loaded = fixture(routes::UI_COSTS, "costs");
        let result = check_coverage(&loaded, &Matrix::new());
        if cfg!(feature = "cost-governance") {
            assert_eq!(
                result.unwrap_err(),
                "costs.tsv: fragment has no computed rows"
            );
        } else {
            assert_eq!(result, Ok(()));
            assert_eq!(render(&loaded, &Matrix::new()), (String::new(), Vec::new()));
        }
    }

    #[test]
    fn a_printed_file_reloads_with_headers_and_named_bodies() {
        let loaded = fixture(routes::UI_STATUS, "status");
        let row = &loaded.files[0].rows[0];
        let computed = [(row[..4].join("\t"), row[4].clone())].into();
        assert_eq!(check_coverage(&loaded, &computed), Ok(()));
        let (block, divergent) = render(&loaded, &computed);
        assert!(divergent.is_empty());
        assert!(block.starts_with("# file: ui_access_matrix.d/status.tsv\n#@ scoped\n"));
        assert!(block.contains("401:@refused"));
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("fragments");
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("status.tsv"), block).unwrap();
        let bodies = root.path().join("bodies.tsv");
        std::fs::write(&bodies, "refused\tde6b55925ef7\trefusal\n").unwrap();
        assert_eq!(load_from(&dir, &bodies).unwrap(), loaded);
    }

    #[test]
    fn lists_every_changed_named_digest_only_when_its_status_matches() {
        let mut loaded = fixture(routes::UI_STATUS, "status");
        let original = loaded.files[0].rows[0].clone();
        let mut computed = Matrix::new();
        for index in 0..45 {
            let mut row = original.clone();
            row[3] = format!("caller-{index}");
            computed.insert(row[..4].join("\t"), "401:0123456789ab".into());
            loaded.files[0].rows.push(row);
        }
        let key = original[..4].join("\t");
        computed.insert(key.clone(), "403:0123456789ab".into());
        let (_, divergent) = render(&loaded, &computed);
        assert_eq!(divergent.len(), 45);
        assert!(divergent.iter().all(|line| {
            line.contains("expected 401:@refused (de6b55925ef7), got 401:0123456789ab")
        }));
        computed.insert(key.clone(), "401".into());
        assert_eq!(render(&loaded, &computed).1.len(), 46);
        computed.insert(key, "403:de6b55925ef7".into());
        let (blocks, divergent) = render(&loaded, &computed);
        assert_eq!(divergent.len(), 45);
        assert!(blocks.contains("403:@refused"));
    }
}

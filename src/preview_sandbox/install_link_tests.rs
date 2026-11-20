// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The direct-URL check on a dist-info that is a link (Unix: the rows plant
//! symbolic links).

use super::*;

/// A dist-info that is a link is the kind check's one exception: it is read
/// through like a directory. A link to a directory without `direct_url.json`
/// passes and is named among the checked, one with it refuses, and a link to
/// a file refuses as unreadable.
#[test]
fn u_direct_a_linked_dist_info_is_read_through() {
    use std::os::unix::fs::symlink;
    let linked = |target: &dyn Fn(&std::path::Path) -> std::path::PathBuf| {
        let root = tempfile::tempdir().expect("root");
        let env = tool_env(root.path(), &["a-1.0".to_owned()]);
        let site = env.join("lib/python3.12/site-packages");
        symlink(target(root.path()), site.join("x-1.0.dist-info")).expect("link");
        let mut checked = check_direct_url(&env, far());
        if let Ok(names) = checked.as_mut() {
            names.sort();
        }
        checked
    };
    let dir = |with_url: bool| {
        move |root: &std::path::Path| {
            let dir = root.join("elsewhere/x-1.0.dist-info");
            std::fs::create_dir_all(&dir).expect("target");
            std::fs::write(dir.join("METADATA"), "Metadata-Version: 2.1\n").expect("METADATA");
            if with_url {
                std::fs::write(dir.join("direct_url.json"), "{}").expect("direct_url.json");
            }
            dir
        }
    };
    assert_eq!(
        linked(&dir(false)),
        Ok(vec!["a-1.0".to_owned(), "x-1.0".to_owned()]),
        "a link to a directory without direct_url.json"
    );
    assert_eq!(
        linked(&dir(true)),
        Err(direct_url_refusal()),
        "a link to a directory with direct_url.json"
    );
    let file = |root: &std::path::Path| {
        let file = root.join("elsewhere-file");
        std::fs::write(&file, "").expect("file");
        file
    };
    assert_eq!(
        linked(&file),
        Err(Refusal::Command(
            "the install's site-packages could not be read".into()
        )),
        "a link to a file"
    );
}

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The chain without a running watcher: its directory set (every hop's
//! directory is in it, a link directory is not, a relative, absolute or
//! cross-directory target resolves, and a link cycle is an error rather than
//! a hang), the named config path, and the warning for a failed watch.

use std::collections::BTreeSet;
use std::path::Path;

use super::super::chain_dirs;
use super::{canonical, release_link, set};
use crate::test_symlink::symlink;

/// T6c: every hop's directory, canonical, and never the `..data` link path.
#[test]
fn t6c_chain_dirs_names_every_hop_and_no_link_directory() {
    let root = tempfile::tempdir().expect("root");
    let cfg = root.path().join("cfg");
    let ts1 = cfg.join("..ts1");
    std::fs::create_dir_all(&ts1).unwrap();
    std::fs::write(ts1.join("gateway.yaml"), "a: 1\n").unwrap();
    symlink("..ts1", cfg.join("..data")).unwrap();
    symlink("..data/gateway.yaml", cfg.join("gateway.yaml")).unwrap();

    let (dirs, end) = chain_dirs(&cfg.join("gateway.yaml")).expect("chain");
    assert_eq!(dirs, set(&[&cfg, &ts1]));
    assert_eq!(end, canonical(&ts1.join("gateway.yaml")));
    assert!(
        dirs.contains(&canonical(&cfg)),
        "the named link's directory stays in the set"
    );
}

/// T6c (mid-chain): a link in a third directory is part of the chain.
#[test]
fn t6c_a_mid_chain_link_directory_is_in_the_set() {
    let root = tempfile::tempdir().expect("root");
    let (c, d, e) = (
        root.path().join("c"),
        root.path().join("d"),
        root.path().join("e"),
    );
    for dir in [&c, &d, &e] {
        std::fs::create_dir_all(dir).unwrap();
    }
    std::fs::write(e.join("cfg.yaml"), "a: 1\n").unwrap();
    symlink(e.join("cfg.yaml"), d.join("l2")).unwrap();
    symlink(d.join("l2"), c.join("l")).unwrap();

    let (dirs, _) = chain_dirs(&c.join("l")).expect("chain");
    assert_eq!(dirs, set(&[&c, &d, &e]));
}

/// T6: a link cycle ends at the hop bound instead of looping.
#[test]
fn t6_a_link_cycle_is_an_error_not_a_hang() {
    let root = tempfile::tempdir().expect("root");
    let (a, b) = (root.path().join("a"), root.path().join("b"));
    symlink(&b, &a).unwrap();
    symlink(&a, &b).unwrap();
    assert!(chain_dirs(&a).is_err());
}

/// T6d: a directory link that is the file's own parent is followed, and the
/// directory holding it is in the set.
#[test]
fn t6d_a_release_directory_link_and_its_holder_are_in_the_set() {
    let root = tempfile::tempdir().expect("root");
    let r = release_link(root.path(), Path::new("rel1"));
    let (dirs, end) = chain_dirs(&r.join("current").join("cfg.yaml")).expect("chain");
    assert_eq!(dirs, set(&[&r, &r.join("rel1")]));
    assert_eq!(end, canonical(&r.join("rel1").join("cfg.yaml")));
}

/// T6e: a relative directory-link target with `..`.
#[test]
fn t6e_a_relative_target_with_parent_components() {
    let root = tempfile::tempdir().expect("root");
    let other = root.path().join("other").join("rel1");
    std::fs::create_dir_all(&other).unwrap();
    std::fs::write(other.join("cfg.yaml"), "a: 1\n").unwrap();
    let r = root.path().join("R");
    std::fs::create_dir_all(&r).unwrap();
    symlink("../other/rel1", r.join("current")).unwrap();
    let (dirs, _) = chain_dirs(&r.join("current").join("cfg.yaml")).expect("chain");
    assert_eq!(dirs, set(&[&r, &other]));
}

/// T6f: an absolute directory-link target.
#[test]
fn t6f_an_absolute_target() {
    let root = tempfile::tempdir().expect("root");
    let abs = root.path().join("R").join("rel1");
    let r = release_link(root.path(), &abs);
    let (dirs, _) = chain_dirs(&r.join("current").join("cfg.yaml")).expect("chain");
    assert_eq!(dirs, set(&[&r, &abs]));
}

/// T6g: a directory link to a directory link held in another directory.
#[test]
fn t6g_a_directory_link_chain_across_directories() {
    let root = tempfile::tempdir().expect("root");
    let (r, s) = (root.path().join("R"), root.path().join("S"));
    std::fs::create_dir_all(s.join("rel1")).unwrap();
    std::fs::create_dir_all(&r).unwrap();
    std::fs::write(s.join("rel1").join("cfg.yaml"), "a: 1\n").unwrap();
    symlink("rel1", s.join("mid")).unwrap();
    symlink(s.join("mid"), r.join("current")).unwrap();
    let (dirs, _) = chain_dirs(&r.join("current").join("cfg.yaml")).expect("chain");
    assert_eq!(dirs, set(&[&r, &s, &s.join("rel1")]));
}

/// T6h: a directory link above the file's immediate parent is resolved, not
/// watched: its holder is not in the set.
#[test]
fn t6h_a_high_directory_link_is_not_watched() {
    let root = tempfile::tempdir().expect("root");
    let sub = root.path().join("real").join("sub");
    std::fs::create_dir_all(&sub).unwrap();
    std::fs::write(sub.join("cfg.yaml"), "a: 1\n").unwrap();
    symlink(root.path().join("real"), root.path().join("hi")).unwrap();
    let (dirs, _) =
        chain_dirs(&root.path().join("hi").join("sub").join("cfg.yaml")).expect("chain");
    assert_eq!(dirs, set(&[&sub]));
}

/// T6 (directory links): a directory-link cycle ends at the same bound.
#[test]
fn t6_a_directory_link_cycle_is_an_error_not_a_hang() {
    let root = tempfile::tempdir().expect("root");
    let r = root.path().join("R");
    std::fs::create_dir_all(&r).unwrap();
    symlink("b", r.join("a")).unwrap();
    symlink("a", r.join("b")).unwrap();
    assert!(chain_dirs(&r.join("a").join("cfg.yaml")).is_err());
}

/// T12: a directory that cannot be watched warns once until it leaves the
/// wanted set, and again if it comes back and still fails.
#[test]
fn t12_a_repeated_watch_failure_warns_once() {
    use std::sync::atomic::Ordering;
    let root = tempfile::tempdir().expect("root");
    let missing = root.path().join("missing");
    let watcher = notify::recommended_watcher(|_| {}).expect("watcher");
    let chain = super::super::ChainWatch::with_names(watcher, std::sync::Arc::default());
    let wanted = BTreeSet::from([missing.clone()]);
    chain.reconcile(&wanted);
    chain.reconcile(&wanted);
    assert_eq!(
        chain.watch_warnings.load(Ordering::SeqCst),
        1,
        "warned per retry"
    );
    chain.reconcile(&BTreeSet::new());
    chain.reconcile(&wanted);
    assert_eq!(
        chain.watch_warnings.load(Ordering::SeqCst),
        2,
        "a directory that left the chain was never forgotten"
    );
}

/// T14: the config path keeps a directory link, where the parent-resolving
/// form used for event matching erases it.
#[test]
fn t14_the_named_config_path_keeps_its_directory_link() {
    let root = tempfile::tempdir().expect("root");
    let r = release_link(root.path(), Path::new("rel1"));
    let named = r.join("current").join("cfg.yaml");
    let resolved = crate::config_reload::absolute_watch_path(named.clone());
    assert_ne!(resolved, named, "premise: event matching resolves the link");
    assert_eq!(super::super::named_config_path(named.clone()), named);
}

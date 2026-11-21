// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The install path's writes moved from `tokio::fs` onto `kept_blocking`.
//! K9 pins the claim that this changes nothing in a release build: the
//! locked tokio runs each wrapped call as one blocking std call.

use std::path::Path;

/// The tokio versions whose `src/fs/write.rs`, `create_dir_all.rs`,
/// `remove_file.rs`, `remove_dir_all.rs` and `symlink.rs` were each read as
/// one `asyncify` of the std call (io-uring needs `tokio_unstable`): 1.53.1
/// at the design review, 1.54.1 from its release tag on 2026-11-17.
const REVIEWED_TOKIO_WRITE: [&str; 2] = ["1.53.1", "1.54.1"];

/// What a lock file says about tokio: `Ok` when it holds exactly one tokio,
/// from the crates.io registry, at a reviewed version.
fn tokio_lock_check(lock: &str) -> Result<(), String> {
    let tokios: Vec<(String, String)> = lock
        .split("[[package]]")
        .filter(|block| block.lines().any(|line| line == "name = \"tokio\""))
        .map(|block| {
            let field = |key: &str| {
                block
                    .lines()
                    .find_map(|line| line.strip_prefix(key))
                    .map(|value| value.trim_matches('"').to_owned())
                    .unwrap_or_default()
            };
            (field("version = "), field("source = "))
        })
        .collect();
    let [(version, source)] = tokios.as_slice() else {
        return Err(format!(
            "Cargo.lock holds {} tokio packages; exactly one was reviewed",
            tokios.len()
        ));
    };
    if !source.starts_with("registry+https://github.com/rust-lang/crates.io-index") {
        return Err(format!(
            "tokio comes from {source:?}, not the crates.io registry: a patched tokio was not reviewed"
        ));
    }
    if !REVIEWED_TOKIO_WRITE.contains(&version.as_str()) {
        return Err(format!(
            "tokio {version} is not in REVIEWED_TOKIO_WRITE: read its src/fs/write.rs, \
             create_dir_all.rs, remove_file.rs, remove_dir_all.rs and symlink.rs, and add the \
             version only if each is still one blocking step"
        ));
    }
    Ok(())
}

/// K9. The locked tokio is one reviewed registry version, and the build
/// does not set `tokio_unstable` (which tokio's io-uring write path needs,
/// however the feature got turned on). Both sides: a bumped version, a
/// second tokio and a patched source each fail, naming the cause.
#[test]
fn the_locked_tokio_runs_each_wrapped_fs_call_as_one_blocking_step() {
    let lock = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.lock"))
        .expect("Cargo.lock beside the manifest");
    assert_eq!(tokio_lock_check(&lock), Ok(()));
    const {
        assert!(
            !cfg!(tokio_unstable),
            "tokio_unstable is set for this build: tokio may write through io-uring, which the \
         install path's no-delta claim did not review"
        );
    };

    let registry = "registry+https://github.com/rust-lang/crates.io-index";
    let one = |version: &str, source: &str| {
        format!("[[package]]\nname = \"tokio\"\nversion = \"{version}\"\nsource = \"{source}\"\n")
    };
    assert_eq!(tokio_lock_check(&one("1.54.1", registry)), Ok(()));
    let bumped = tokio_lock_check(&one("9.9.9", registry)).expect_err("9.9.9 was never read");
    assert!(
        bumped.contains("tokio 9.9.9 is not in REVIEWED_TOKIO_WRITE"),
        "{bumped}"
    );
    let twice = format!("{}{}", one("1.54.1", registry), one("1.53.1", registry));
    let twice = tokio_lock_check(&twice).expect_err("two tokios");
    assert!(twice.contains("holds 2 tokio packages"), "{twice}");
    let patched = tokio_lock_check(&one(
        "1.54.1",
        "git+https://github.com/tokio-rs/tokio?branch=master",
    ))
    .expect_err("a git tokio");
    assert!(patched.contains("not the crates.io registry"), "{patched}");
}

/// Module path ("`crate::skills::installer`") to its source text. The real
/// tree is read lazily; a row plants extra or replacement modules here.
type Planted = std::collections::BTreeMap<String, String>;

/// The source of `module`: a planted text, else the file under `src/`.
fn module_text(planted: &Planted, module: &str) -> Option<String> {
    if let Some(text) = planted.get(module) {
        return Some(text.clone());
    }
    let rel = module.strip_prefix("crate")?.replace("::", "/");
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    if rel.is_empty() {
        return std::fs::read_to_string(src.join("lib.rs")).ok();
    }
    let rel = rel.trim_start_matches('/');
    std::fs::read_to_string(src.join(format!("{rel}.rs")))
        .or_else(|_| std::fs::read_to_string(src.join(rel).join("mod.rs")))
        .ok()
}

/// Every name a `use` item brings into scope, to the path it names.
fn use_names(
    tree: &syn::UseTree,
    prefix: &[String],
    names: &mut std::collections::HashMap<String, Vec<String>>,
) {
    let with = |ident: &syn::Ident| {
        let mut path = prefix.to_vec();
        path.push(ident.to_string());
        path
    };
    match tree {
        syn::UseTree::Path(p) => use_names(&p.tree, &with(&p.ident), names),
        syn::UseTree::Name(n) if n.ident == "self" => {
            if let Some(last) = prefix.last() {
                names.insert(last.clone(), prefix.to_vec());
            }
        }
        syn::UseTree::Name(n) => {
            names.insert(n.ident.to_string(), with(&n.ident));
        }
        syn::UseTree::Rename(r) => {
            names.insert(r.rename.to_string(), with(&r.ident));
        }
        syn::UseTree::Group(g) => {
            for item in &g.items {
                use_names(item, prefix, names);
            }
        }
        // ponytail: a glob import is not resolved; the install path has none.
        syn::UseTree::Glob(_) => {}
    }
}

/// One parsed module: its imports and its production free functions.
struct Module {
    uses: std::collections::HashMap<String, Vec<String>>,
    fns: std::collections::HashMap<String, syn::ItemFn>,
}

fn parse_module(text: &str) -> Module {
    let file = syn::parse_file(text).expect("a module that parses");
    let mut module = Module {
        uses: std::collections::HashMap::new(),
        fns: std::collections::HashMap::new(),
    };
    for item in file.items {
        match item {
            syn::Item::Use(u) if !crate::test_source_text::test_only(&u.attrs) => {
                use_names(&u.tree, &[], &mut module.uses);
            }
            // Same-named fns under exclusive cfgs (unix and not unix) are
            // both kept: every cfg branch is scanned.
            syn::Item::Fn(f) if !crate::test_source_text::test_only(&f.attrs) => {
                match module.fns.entry(f.sig.ident.to_string()) {
                    std::collections::hash_map::Entry::Vacant(slot) => {
                        slot.insert(f);
                    }
                    std::collections::hash_map::Entry::Occupied(mut slot) => {
                        slot.get_mut().block.stmts.extend(f.block.stmts);
                    }
                }
            }
            _ => {}
        }
    }
    module
}

/// `segments`, written in `module`, as an absolute path: `crate`, `super`
/// and `self` resolved; an external path (std, tokio) left as written.
fn absolute(module: &str, segments: &[String]) -> Vec<String> {
    let mut base: Vec<String> = module.split("::").map(str::to_owned).collect();
    let mut rest = segments;
    match rest.first().map(String::as_str) {
        Some("self") => rest = &rest[1..],
        Some("super") => {
            while rest.first().map(String::as_str) == Some("super") {
                base.pop();
                rest = &rest[1..];
            }
        }
        _ => return segments.to_vec(),
    }
    base.extend(rest.iter().cloned());
    base
}

/// The path prefixes of a filesystem entry point.
const FS_PREFIXES: [&str; 4] = [
    "std::fs::",
    "tokio::fs::",
    "std::os::unix::fs::",
    "std::os::windows::fs::",
];

/// The one helper whose closures count as kept.
const KEPT_BLOCKING: &str = "crate::skills::installer::kept_blocking";

/// What a scan found: filesystem paths reached inside a kept closure, and
/// those reached outside one, each as "`<module>::<fn>: <path>`".
#[derive(Default)]
struct Found {
    kept: std::collections::BTreeSet<String>,
    bare: Vec<String>,
}

struct Scan<'p> {
    planted: &'p Planted,
    modules: std::collections::HashMap<String, Option<std::rc::Rc<Module>>>,
    visited: std::collections::HashSet<(String, String, bool)>,
    found: Found,
}

fn segments(path: &syn::Path) -> Vec<String> {
    path.segments.iter().map(|s| s.ident.to_string()).collect()
}

impl Scan<'_> {
    fn module(&mut self, path: &str) -> Option<std::rc::Rc<Module>> {
        if !self.modules.contains_key(path) {
            let parsed =
                module_text(self.planted, path).map(|text| std::rc::Rc::new(parse_module(&text)));
            self.modules.insert(path.to_owned(), parsed);
        }
        self.modules.get(path).cloned().flatten()
    }

    /// The absolute path `written` names in `module`.
    fn resolve(&mut self, module: &str, written: &[String]) -> Vec<String> {
        let Some(first) = written.first() else {
            return Vec::new();
        };
        let Some(m) = self.module(module) else {
            return absolute(module, written);
        };
        if written.len() == 1 && m.fns.contains_key(first) {
            return absolute(module, &["self".to_owned(), first.clone()]);
        }
        if let Some(target) = m.uses.get(first) {
            let mut path = absolute(module, target);
            path.extend(written[1..].iter().cloned());
            return path;
        }
        absolute(module, written)
    }

    /// Walk fn `name` of `module`, its body inside a kept closure or not.
    fn visit_fn(&mut self, module: &str, name: &str, kept: bool) {
        if !self
            .visited
            .insert((module.to_owned(), name.to_owned(), kept))
        {
            return;
        }
        let Some(f) = self.module(module).and_then(|m| m.fns.get(name).cloned()) else {
            return;
        };
        let mut walker = Walker {
            scan: self,
            module: module.to_owned(),
            at: format!("{module}::{name}"),
            kept,
        };
        syn::visit::Visit::visit_block(&mut walker, &f.block);
    }

    /// A path reached from `at`: a filesystem entry point is recorded; a
    /// crate function, possibly behind a re-export, is walked.
    fn reached(&mut self, at: &str, kept: bool, path: &[String], depth: usize) {
        let joined = path.join("::");
        if FS_PREFIXES.iter().any(|prefix| joined.starts_with(prefix)) {
            if kept {
                self.found.kept.insert(joined);
            } else {
                self.found.bare.push(format!("{at}: {joined}"));
            }
            return;
        }
        if path.first().map(String::as_str) != Some("crate") || path.len() < 2 || depth > 8 {
            return;
        }
        let (owner, name) = (path[..path.len() - 1].join("::"), &path[path.len() - 1]);
        let Some(m) = self.module(&owner) else {
            return;
        };
        if m.fns.contains_key(name) {
            self.visit_fn(&owner, name, kept);
        } else if let Some(target) = m.uses.get(name) {
            let next = absolute(&owner, target);
            self.reached(at, kept, &next, depth + 1);
        }
    }
}

/// Visits one function body for [`Scan`].
struct Walker<'s, 'p> {
    scan: &'s mut Scan<'p>,
    module: String,
    at: String,
    kept: bool,
}

impl Walker<'_, '_> {
    /// Walk `body` as code that runs inside a held keep, then restore the
    /// state the walk had before it.
    fn in_keep<'ast>(&mut self, body: &'ast syn::Expr) {
        let before = std::mem::replace(&mut self.kept, true);
        <Self as syn::visit::Visit<'ast>>::visit_expr(self, body);
        self.kept = before;
    }
}

impl<'ast> syn::visit::Visit<'ast> for Walker<'_, '_> {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(func) = &*call.func {
            let path = self.scan.resolve(&self.module, &segments(&func.path));
            if path.join("::") == KEPT_BLOCKING {
                // Only a closure literal's body runs while the keep is held. Any
                // other argument is evaluated before the call, outside the keep.
                for arg in &call.args {
                    match arg {
                        syn::Expr::Closure(closure) => self.in_keep(&closure.body),
                        eager => self.visit_expr(eager),
                    }
                }
                return;
            }
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_path(&mut self, expr: &'ast syn::ExprPath) {
        let path = self.scan.resolve(&self.module, &segments(&expr.path));
        self.scan.reached(&self.at, self.kept, &path, 0);
    }
}

/// Scan the install path from its async entry points with `planted`
/// modules. `copy_dir_recursive` is no root: it is a blocking helper reached
/// only from inside `link_or_copy`'s kept closure, and walked from there.
fn scan_install_path(planted: &Planted) -> Found {
    let mut scan = Scan {
        planted,
        modules: std::collections::HashMap::new(),
        visited: std::collections::HashSet::new(),
        found: Found::default(),
    };
    for root in ["install_bundle_kept", "link_or_copy"] {
        scan.visit_fn("crate::skills::installer", root, false);
    }
    scan.found
}

/// The real installer with `planted` inserted as the first statement of
/// `install_bundle_kept` and `head` added before its first item.
fn installer_with(head: &str, planted: &str) -> String {
    let text = module_text(&Planted::new(), "crate::skills::installer").expect("the installer");
    let anchor = "    let dir = commands_dir.clone();\n";
    assert_eq!(
        text.matches(anchor).count(),
        1,
        "premise: one anchor in install_bundle_kept"
    );
    let first_use = text
        .find("\nuse ")
        .expect("premise: the installer has imports")
        + 1;
    let text = text.replacen(anchor, &format!("    {planted}\n{anchor}"), 1);
    format!("{}{head}\n{}", &text[..first_use], &text[first_use..])
}

/// K12. Every filesystem call the install path reaches, through any helper
/// in any module, lies inside a `kept_blocking` closure; and the scan sees
/// the kept writes it should (so an empty scan is not a pass).
#[test]
fn no_install_path_filesystem_call_bypasses_kept_blocking() {
    let found = scan_install_path(&Planted::new());
    assert_eq!(
        found.bare,
        Vec::<String>::new(),
        "calls outside kept_blocking"
    );
    for want in [
        "std::fs::create_dir_all",
        "std::fs::write",
        "std::fs::remove_dir_all",
        "std::fs::remove_file",
        "std::os::unix::fs::symlink",
        "std::fs::read_dir",
        "std::fs::copy",
    ] {
        assert!(
            found.kept.contains(want),
            "the scan never reached {want}: {:?}",
            found.kept
        );
    }
}

/// K12, both sides: each way past a call-graph walk is planted once on the
/// real installer and must fail by name.
#[test]
fn every_planted_bypass_of_kept_blocking_is_named() {
    let installer = "crate::skills::installer".to_owned();
    let cases: [(&str, Planted, &str); 7] = [
        (
            "an eager write in kept_blocking's argument",
            Planted::from([(installer.clone(), installer_with(
                "",
                "kept_blocking(keep, { std::fs::write(&bundle_dir, b\"x\")?; move || Ok(()) }).await?;",
            ))]),
            "crate::skills::installer::install_bundle_kept: std::fs::write",
        ),
        (
            "the tokio fs alias",
            Planted::from([(installer.clone(), installer_with("use tokio::fs;", "let _ = fs::write(&bundle_dir, b\"x\");"))]),
            "crate::skills::installer::install_bundle_kept: tokio::fs::write",
        ),
        (
            "a renamed alias",
            Planted::from([(installer.clone(), installer_with("use tokio::fs as disk;", "let _ = disk::write(&bundle_dir, b\"x\");"))]),
            "crate::skills::installer::install_bundle_kept: tokio::fs::write",
        ),
        (
            "a helper in the same module",
            Planted::from([(installer.clone(), installer_with(
                "fn planted_helper(p: &Path) { let _ = std::fs::write(p, b\"x\"); }",
                "planted_helper(&bundle_dir);",
            ))]),
            "crate::skills::installer::planted_helper: std::fs::write",
        ),
        (
            "a helper in another module",
            Planted::from([
                (installer.clone(), installer_with("", "super::planted::helper(&bundle_dir);")),
                (
                    "crate::skills::planted".to_owned(),
                    "pub(crate) fn helper(p: &std::path::Path) { let _ = std::fs::write(p, b\"x\"); }".to_owned(),
                ),
            ]),
            "crate::skills::planted::helper: std::fs::write",
        ),
        (
            "a directly imported function",
            Planted::from([(installer.clone(), installer_with("use tokio::fs::write;", "let _ = write(&bundle_dir, b\"x\");"))]),
            "crate::skills::installer::install_bundle_kept: tokio::fs::write",
        ),
        (
            "a pub use re-export in another module",
            Planted::from([
                (installer.clone(), installer_with("", "crate::skills::reexport::stash(&bundle_dir);")),
                ("crate::skills::reexport".to_owned(), "pub use super::deep::put as stash;".to_owned()),
                (
                    "crate::skills::deep".to_owned(),
                    "pub fn put(p: &std::path::Path) { let _ = std::fs::write(p, b\"x\"); }".to_owned(),
                ),
            ]),
            "crate::skills::deep::put: std::fs::write",
        ),
    ];
    for (name, planted, want) in cases {
        assert_eq!(
            scan_install_path(&planted).bare,
            vec![want.to_owned()],
            "planted {name}"
        );
    }
}

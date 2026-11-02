// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Full validation before any entry: a save the loader would refuse is
//! refused before the store holds anything, and the writer is reached only
//! through its audited entry point.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::reload_context::replace::{Expected, Replace, Replaced, SecretStep, replace_detached};
use super::replace_test_support::{START, WAIT, context, read, setup, to};
use crate::config_persistence::keyedit::{Segment, SlotId, Template};
use crate::gateway::test_helpers::write_owner_only;
use crate::secret_store::{FilesStore, NewSecretOwned, SecretStore, StoreError, StoreKind, Vault};
use crate::wiped_bytes::WipedBytes;

/// A credential an API key in the config already stands for.
const CRED: &[u8] = b"zq-validate-shared-credential";

/// The files store, counting every create.
struct Counting {
    inner: FilesStore,
    creates: AtomicUsize,
}

impl Counting {
    fn new(dir: &Path) -> Arc<Self> {
        Arc::new(Self {
            inner: FilesStore::new(dir),
            creates: AtomicUsize::new(0),
        })
    }

    fn creates(&self) -> usize {
        self.creates.load(Ordering::SeqCst)
    }
}

impl SecretStore for Counting {
    fn kind(&self) -> StoreKind {
        self.inner.kind()
    }
    fn limit(&self) -> usize {
        self.inner.limit()
    }
    fn probe(&self) -> Result<(), StoreError> {
        self.inner.probe()
    }
    fn exists(&self, name: &str) -> Result<bool, StoreError> {
        self.inner.exists(name)
    }
    fn create(&self, name: &str, value: &[u8]) -> Result<String, StoreError> {
        self.creates.fetch_add(1, Ordering::SeqCst);
        self.inner.create(name, value)
    }
    fn delete(&self, name: &str) -> Result<(), StoreError> {
        self.inner.delete(name)
    }
}

fn slot(keys: &[&str]) -> SlotId {
    SlotId(keys.iter().map(|k| Segment::Key((*k).to_owned())).collect())
}

/// A save of `text`, whose one `{slot}` is `keys`' secret holding `value`.
fn save(dir: &Path, store: Arc<Counting>, keys: &[&str], text: &str, value: &[u8]) -> Replace {
    let id = slot(keys);
    let filled = text.replace("{slot}", &Template::placeholder_for(&id));
    let template = Template::from_placeholders(filled.into_bytes(), &[id]).expect("one slot");
    Replace {
        expected: Expected::Any,
        compute: Box::new(move |_| Ok(template)),
        replaced: Replaced::Discard,
        secrets: Some(SecretStep {
            vault: Vault::with_lock(dir, dir.join("vault.lock")),
            store,
            values: vec![NewSecretOwned {
                field: keys.join("."),
                value: WipedBytes::new(value.to_vec()),
            }],
        }),
    }
}

/// W4, the writer's half: a template the loader's posture check refuses is
/// refused before the store holds any entry. The value checks of the save
/// core (its own half of W4) come with that core.
#[tokio::test]
async fn a_template_the_loader_refuses_is_refused_before_any_entry() {
    let (dir, path, ctx) = setup();
    let store = Counting::new(dir.path());
    // A public URL over open tools: the posture check refuses it.
    let exposed = format!(
        "server:\n  public_url: \"https://gw.public.test\"\n{START}  b:\n    http_url: \"http://127.0.0.1:9/mcp\"\n    env:\n      K: {{slot}}\n"
    );

    replace_detached(
        ctx,
        save(
            dir.path(),
            Arc::clone(&store),
            &["backends", "b", "env", "K"],
            &exposed,
            b"zq-validate-value",
        ),
        WAIT,
    )
    .await
    .expect_err("the posture refuses the template");

    assert_eq!(read(&path), START);
    assert_eq!(
        store.creates(),
        0,
        "W4: a store entry was created before the template was validated"
    );
}

/// A config whose API key `ci` stands for `CRED`, under `extra` auth lines.
fn with_key(extra: &str) -> String {
    let digest = crate::hashing::sha256_hex(CRED);
    format!(
        "auth:\n  api_keys:\n    - name: ci\n      key_sha256: \"sha256:{digest}\"\n{extra}backends:\n  a:\n    http_url: \"http://127.0.0.1:9/mcp\"\n"
    )
}

/// W5: a new bearer token that is an API key's credential is refused before
/// any store entry exists, and nothing is written.
#[tokio::test]
async fn a_bearer_duplicating_an_api_key_is_refused_before_any_store_entry() {
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("gateway.yaml");
    let base = with_key("");
    write_owner_only(&path, &base).expect("write config");
    let ctx = context(&path);
    let store = Counting::new(dir.path());

    replace_detached(
        ctx,
        save(
            dir.path(),
            Arc::clone(&store),
            &["auth", "bearer_token"],
            &with_key("  bearer_token: {slot}\n"),
            CRED,
        ),
        WAIT,
    )
    .await
    .expect_err("one secret would match two credentials");

    assert_eq!(read(&path), base);
    assert_eq!(
        store.creates(),
        0,
        "W5: a store entry was created for a bearer that duplicates an API key"
    );
}

/// W5, control: the collision is judged on the config the save makes, not
/// the running one. Removing key `ci` in the same save frees its credential
/// for the bearer.
#[tokio::test]
async fn a_running_key_removed_in_the_same_save_no_longer_collides() {
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("gateway.yaml");
    write_owner_only(&path, with_key("")).expect("write config");
    let ctx = context(&path);
    let store = Counting::new(dir.path());
    let without_key = "auth:\n  bearer_token: {slot}\nbackends:\n  a:\n    http_url: \"http://127.0.0.1:9/mcp\"\n";

    replace_detached(
        ctx,
        save(
            dir.path(),
            Arc::clone(&store),
            &["auth", "bearer_token"],
            without_key,
            CRED,
        ),
        WAIT,
    )
    .await
    .expect("the key is gone, so the bearer collides with nothing");

    assert!(read(&path).contains("bearer_token: \""), "{}", read(&path));
    assert_eq!(store.creates(), 1);
}

/// Production lines matching `hit`, as `path:line`, comments skipped.
fn lines_where(hit: impl Fn(&str) -> bool) -> Vec<String> {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    super::replace_audit_tests::production_sources(&src, &mut files);
    let mut found = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file).expect("read source");
        for (n, line) in text.lines().enumerate() {
            if !line.trim_start().starts_with("//") && hit(line) {
                let name = file.strip_prefix(&src).unwrap_or(file);
                found.push(format!(
                    "{}:{}",
                    name.to_string_lossy().replace('\\', "/"),
                    n + 1
                ));
            }
        }
    }
    found
}

/// W27: no writer entry point runs without the posture's audit.
/// `replace_detached` is called only from `replace_audited`, and an `Audit`
/// is built only by `AuditPosture::of`, never chosen by a caller.
#[test]
fn no_writer_entry_point_runs_without_the_posture_audit() {
    let callers = lines_where(|line| {
        line.contains("replace_detached(") && !line.contains("fn replace_detached")
    });
    let outside: Vec<_> = callers
        .iter()
        .filter(|at| !at.starts_with("config_reload/replace_audit.rs:"))
        .collect();
    assert!(
        outside.is_empty(),
        "W27: replace_detached is called outside replace_audited: {outside:?}"
    );
    // A construction, not a pattern: a pattern is followed by `=>` or sits
    // in a `matches!` or a `let`.
    let built = lines_where(|line| {
        (line.contains("Audit::Off") || line.contains("Audit::Required {"))
            && !line.contains("=>")
            && !line.contains("matches!")
            && !line.contains("let Audit::")
    });
    let posture = lines_where(|line| line.contains("impl AuditPosture"));
    let posture_file = posture
        .first()
        .map(|at| at.split(':').next().unwrap_or_default().to_owned());
    let stray: Vec<_> = built
        .iter()
        .filter(|at| {
            posture_file
                .as_deref()
                .is_none_or(|file| !at.starts_with(file))
        })
        .collect();
    assert!(
        stray.is_empty(),
        "W27: an Audit is built outside AuditPosture::of: {stray:?}"
    );
}

/// A recognisable secret; its YAML-escaped form differs from the raw one.
const LOUD: &[u8] = b"zq-w6\"loud\\secret";

/// Every form of `LOUD` that `text` must not hold: raw, escaped, digest.
fn loud_forms_in(text: &str) -> Vec<&'static str> {
    let raw = std::str::from_utf8(LOUD).expect("utf-8");
    let escaped = raw.replace('\\', "\\\\").replace('"', "\\\"");
    let digest = crate::hashing::sha256_hex(LOUD);
    [
        ("raw", raw.to_owned()),
        ("escaped", escaped),
        ("digest", digest),
    ]
    .into_iter()
    .filter(|(_, form)| text.contains(form.as_str()))
    .map(|(name, _)| name)
    .collect()
}

/// A store that refuses every create, with fixed text.
struct Failing;

impl SecretStore for Failing {
    fn kind(&self) -> StoreKind {
        StoreKind::Files
    }
    fn limit(&self) -> usize {
        1 << 16
    }
    fn probe(&self) -> Result<(), StoreError> {
        Ok(())
    }
    fn exists(&self, _: &str) -> Result<bool, StoreError> {
        Ok(false)
    }
    fn create(&self, _: &str, _: &[u8]) -> Result<String, StoreError> {
        Err(StoreError::Failed("the store is broken".to_owned()))
    }
    fn delete(&self, _: &str) -> Result<(), StoreError> {
        Ok(())
    }
}

/// The two refusals a writer-level save can reach today with `LOUD`: the
/// reload's (after the entries) and the store's.
async fn loud_refusals(dir: &Path) -> Vec<String> {
    let exposed = format!(
        "server:\n  public_url: \"https://gw.public.test\"\n{START}  b:\n    http_url: \"http://127.0.0.1:9/mcp\"\n    env:\n      K: {{slot}}\n"
    );
    let keys = ["backends", "b", "env", "K"];
    let mut refusals = Vec::new();
    let path = dir.join("gateway.yaml");
    write_owner_only(&path, START).expect("write config");
    let posture = save(dir, Counting::new(dir), &keys, &exposed, LOUD);
    let failure = replace_detached(context(&path), posture, WAIT)
        .await
        .expect_err("the posture refuses");
    refusals.push(format!("{failure:?}"));
    let mut broken = save(dir, Counting::new(dir), &keys, &exposed, LOUD);
    if let Some(step) = broken.secrets.as_mut() {
        step.store = Arc::new(Failing);
    }
    let failure = replace_detached(context(&path), broken, WAIT)
        .await
        .expect_err("the store refuses");
    refusals.push(format!("{failure:?}"));
    refusals
}

/// W6: no refusal message carries the submitted secret in any form. The
/// value-check refusals of the save core join this row with that core.
#[tokio::test]
async fn no_refusal_message_contains_submitted_secret_bytes() {
    let dir = tempfile::tempdir().expect("dir");
    for refusal in loud_refusals(dir.path()).await {
        let leaked = loud_forms_in(&refusal);
        assert!(
            leaked.is_empty(),
            "W6: a refusal message carries the secret ({leaked:?}): {refusal}"
        );
    }
}

/// Captured log output, shared by every thread of the row's runtime.
#[derive(Clone, Default)]
struct Sink(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Sink {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("sink").extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// W20: with tracing captured at every level on every thread the save
/// touches (the row's own, the runtime's workers and its blocking pool,
/// where the store runs), a save that stands and the two refusals above
/// leave the secret in no event, file or message. No process-wide
/// subscriber: each pool thread installs the capture as it starts.
#[test]
fn a_recognisable_secret_appears_in_no_trace_file_or_record() {
    crate::test_log_capture::keep_interest_open();
    let sink = Sink::default();
    let writer = sink.clone();
    let capture = tracing::Dispatch::new(
        tracing_subscriber::fmt()
            .json()
            .without_time()
            .with_ansi(false)
            .with_max_level(tracing::Level::TRACE)
            .with_writer(move || writer.clone())
            .finish(),
    );
    let on_start = capture.clone();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        // Each worker and blocking thread reports to the capture for its
        // whole life; the guard is never dropped.
        .on_thread_start(move || std::mem::forget(tracing::dispatcher::set_default(&on_start)))
        .build()
        .expect("runtime");
    let dir = tempfile::tempdir().expect("dir");
    let messages = tracing::dispatcher::with_default(&capture, || {
        runtime.block_on(async {
            let mut seen = loud_refusals(dir.path()).await;
            let path = dir.path().join("gateway.yaml");
            let stands = format!(
                "{START}  b:\n    http_url: \"http://127.0.0.1:9/mcp\"\n    env:\n      K: {{slot}}\n"
            );
            let keys = ["backends", "b", "env", "K"];
            let saved = replace_detached(
                context(&path),
                save(dir.path(), Counting::new(dir.path()), &keys, &stands, LOUD),
                WAIT,
            )
            .await;
            seen.push(format!("{saved:?}"));
            seen
        })
    });
    // Settling discards on the blocking pool: wait for it before reading.
    runtime.shutdown_timeout(WAIT);
    let output = String::from_utf8(sink.0.lock().expect("sink").clone()).expect("utf-8 log");
    assert!(
        !output.is_empty(),
        "premise: the capture saw the save's events"
    );
    for line in output.lines() {
        let leaked = loud_forms_in(line);
        assert!(
            leaked.is_empty(),
            "W20: a trace event carries the secret ({leaked:?}): {line}"
        );
    }
    for message in &messages {
        let leaked = loud_forms_in(message);
        assert!(
            leaked.is_empty(),
            "W20: a result carries the secret ({leaked:?}): {message}"
        );
    }
    let file = read(&dir.path().join("gateway.yaml"));
    assert!(
        loud_forms_in(&file).is_empty(),
        "W20: gateway.yaml carries the secret: {file}"
    );
}

/// Two API keys whose digests are `a` and `b`, under `auth`.
fn two_keys(a: &str, b: &str) -> String {
    format!(
        "auth:\n  api_keys:\n    - name: one\n      key_sha256: {a}\n    - name: two\n      key_sha256: {b}\nbackends:\n  a:\n    http_url: \"http://127.0.0.1:9/mcp\"\n"
    )
}

fn key_slot(at: usize) -> SlotId {
    SlotId(vec![
        Segment::Key("auth".to_owned()),
        Segment::Key("api_keys".to_owned()),
        Segment::Index(at),
        Segment::Key("key_sha256".to_owned()),
    ])
}

/// W28: each slot is checked on its own stand-in. Two distinct, valid key
/// digests are saved: one stand-in shared by both slots would make the two
/// keys one credential, and a stand-in not shaped as a digest would fail the
/// digest field's own format, so either refuses this save before any entry.
#[tokio::test]
async fn distinct_valid_secrets_pass_with_per_slot_sentinels() {
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("gateway.yaml");
    let digest = |s: &[u8]| format!("\"sha256:{}\"", crate::hashing::sha256_hex(s));
    write_owner_only(&path, two_keys(&digest(b"old-one"), &digest(b"old-two"))).expect("write");
    let ctx = context(&path);
    let store = Counting::new(dir.path());
    let (one, two) = (key_slot(0), key_slot(1));
    let text = two_keys(
        &Template::placeholder_for(&one),
        &Template::placeholder_for(&two),
    );
    let template = Template::from_placeholders(text.into_bytes(), &[one.clone(), two.clone()])
        .expect("two slots");
    let value = |s: &[u8]| {
        WipedBytes::new(format!("sha256:{}", crate::hashing::sha256_hex(s)).into_bytes())
    };
    let save = Replace {
        expected: Expected::Any,
        compute: Box::new(move |_| Ok(template)),
        replaced: Replaced::Discard,
        secrets: Some(SecretStep {
            vault: Vault::with_lock(dir.path(), dir.path().join("vault.lock")),
            store: Arc::clone(&store) as Arc<dyn SecretStore + Send + Sync>,
            values: vec![
                NewSecretOwned {
                    field: one.display(),
                    value: value(b"new-one"),
                },
                NewSecretOwned {
                    field: two.display(),
                    value: value(b"new-two"),
                },
            ],
        }),
    };

    replace_detached(ctx, save, WAIT)
        .await
        .expect("W28: two distinct valid key digests are saved");

    assert_eq!(store.creates(), 2);
}

/// A config with a comment that only mentions the reserved prefix, and the
/// reference that really collides on line 5.
const COMMENTED: &str = "# MCPGW_PENDING_SLOT_1 is reserved\nbackends:\n  a:\n    http_url: \"http://127.0.0.1:9/mcp\"\n";
const REFERENCING: &str = "backends:\n  a:\n    http_url: \"http://127.0.0.1:9/mcp\"\n    headers:\n      Authorization: \"env:MCPGW_PENDING_SLOT_3\"\n";

/// The refusal names the reserved name the operator wrote and its line, so
/// they know what to rename.
#[test]
fn a_config_naming_a_reserved_slot_says_which_name_and_line() {
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("gateway.yaml");
    write_owner_only(&path, REFERENCING).expect("write config");
    let refused = crate::config::Config::load(Some(&path))
        .expect_err("a reference to a reserved name is refused")
        .to_string();
    assert!(
        refused.contains("MCPGW_PENDING_SLOT_3") && refused.contains("line 5"),
        "the refusal names the reference and its line: {refused}"
    );
    assert!(
        refused.contains("rename"),
        "the refusal says to rename it: {refused}"
    );
}

/// A comment is not a reference: mentioning the prefix in one never stops a
/// start.
#[test]
fn a_comment_mentioning_the_reserved_prefix_still_loads() {
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("gateway.yaml");
    write_owner_only(&path, COMMENTED).expect("write config");
    crate::config::Config::load(Some(&path)).expect("a comment that mentions the prefix loads");
}

/// The writer applies the same rule: a comment that mentions the prefix does
/// not refuse a save.
#[tokio::test]
async fn a_comment_mentioning_the_reserved_prefix_does_not_refuse_a_save() {
    let (_dir, path, ctx) = setup();
    replace_detached(ctx, to(Expected::Any, COMMENTED, Replaced::Discard), WAIT)
        .await
        .expect("a comment that mentions the prefix does not refuse the save");
    assert_eq!(read(&path), COMMENTED);
}

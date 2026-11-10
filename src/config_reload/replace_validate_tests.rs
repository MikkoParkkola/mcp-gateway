// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Full validation before any entry: a save the loader would refuse is
//! refused before the store holds anything, and the writer is reached only
//! through its audited entry point.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::reload_context::replace::{
    Audit, Expected, Intent, IntentId, IntentKind, IntentSink, Replace, ReplaceError, Replaced,
    SecretStep, replace_audited, replace_detached,
};
use super::replace_test_support::{START, WAIT, context, read, refusing_context, setup, to};
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

#[path = "replace_validate_bearer_tests.rs"]
mod bearer;

/// Production lines matching `hit`, as `path:line`, comments skipped.
fn lines_where(hit: impl Fn(&str) -> bool) -> Vec<String> {
    lines_where_in(|_, _| true, hit)
}

/// As [`lines_where`], only in the files `keep` accepts, given each file's
/// `src`-relative path and its text.
fn lines_where_in(keep: impl Fn(&str, &str) -> bool, hit: impl Fn(&str) -> bool) -> Vec<String> {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    super::replace_audit_tests::production_sources(&src, &mut files);
    let mut found = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file).expect("read source");
        let name = file
            .strip_prefix(&src)
            .unwrap_or(file)
            .to_string_lossy()
            .replace('\\', "/");
        if !keep(&name, &text) {
            continue;
        }
        for (n, line) in text.lines().enumerate() {
            if !line.trim_start().starts_with("//") && hit(line) {
                found.push(format!("{name}:{}", n + 1));
            }
        }
    }
    found
}

/// Whether the file at `rel`, holding `text`, can name the writer's `Audit`:
/// a file of the writer's own module, or one with a statement that reaches it
/// through `replace` (an import, wrapped or not, or a full path). A type that
/// only shares the name, in a file that never imports the writer's, is not it.
fn names_writer_audit(rel: &str, text: &str) -> bool {
    if rel.starts_with("config_reload/replace") {
        return true;
    }
    text.split(';').any(|statement| {
        statement.contains("replace::")
            && statement
                .split(|c: char| !(c.is_alphanumeric() || c == '_'))
                .any(|word| word == "Audit")
    })
}

/// W27's scan tells the writer's `Audit` from a type that only shares its
/// name: an `Audit::Off` in a file that never imports the writer's is not
/// counted, and every way of reaching the writer's is.
#[test]
fn an_unrelated_enum_named_audit_is_not_the_writers() {
    let unrelated = "enum Audit {\n    On,\n    Off,\n}\nfn f() -> Audit {\n    Audit::Off\n}\n";
    assert!(
        !names_writer_audit("gateway/ui/backends/fixture.rs", unrelated),
        "a local enum named Audit was taken for the writer's"
    );
    for reaching in [
        "use crate::config_reload::replace::{Audit, Intent};\nfn f() -> Audit { Audit::Off }\n",
        "use super::reload_context::replace::{\n    Audit,\n    Expected,\n};\n",
        "fn f() { let _ = crate::config_reload::replace::Audit::Off; }\n",
    ] {
        assert!(
            names_writer_audit("gateway/ui/route.rs", reaching),
            "a file reaching the writer's Audit was skipped: {reaching:?}"
        );
    }
    assert!(
        names_writer_audit("config_reload/replace_slots.rs", "Audit::Off"),
        "a file of the writer's own module was skipped"
    );
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
    // in a `matches!` or a `let`. Only files that can name the writer's
    // `Audit` count; another type that shares the name is not it.
    let built = lines_where_in(names_writer_audit, |line| {
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

/// A store that refuses every create, with fixed text, counting the tries.
#[derive(Default)]
struct Failing {
    creates: AtomicUsize,
}

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
        self.creates.fetch_add(1, Ordering::SeqCst);
        Err(StoreError::Failed("the store is broken".to_owned()))
    }
    fn delete(&self, _: &str) -> Result<(), StoreError> {
        Ok(())
    }
}

/// A backend `b` whose env `K` is the secret slot: a save the writer's
/// checks accept.
fn standing() -> String {
    format!("{START}  b:\n    http_url: \"http://127.0.0.1:9/mcp\"\n    env:\n      K: {{slot}}\n")
}

const LOUD_KEYS: [&str; 4] = ["backends", "b", "env", "K"];

/// The two refusals a save of `LOUD` reaches once the writer's checks accept
/// it, each through `audit()`: the store's, on its first create, and the
/// reload's, after the entry exists. Each premise is asserted, so a row on
/// these never passes on an earlier refusal.
async fn loud_refusals(dir: &Path, audit: impl Fn() -> Audit) -> Vec<String> {
    let path = dir.join("gateway.yaml");
    write_owner_only(&path, START).expect("write config");
    let failing = Arc::new(Failing::default());
    let mut broken = save(dir, Counting::new(dir), &LOUD_KEYS, &standing(), LOUD);
    broken.secrets.as_mut().expect("a secret step").store = Arc::clone(&failing) as _;
    let store_refusal = replace_audited(context(&path), broken, audit(), WAIT)
        .await
        .expect_err("the store refuses");
    assert!(
        matches!(store_refusal, ReplaceError::Secrets(_)),
        "premise: the store's own refusal: {store_refusal:?}"
    );
    assert_eq!(
        failing.creates.load(Ordering::SeqCst),
        1,
        "premise: the save reached the store"
    );
    let store = Counting::new(dir);
    let reload_refusal = replace_audited(
        refusing_context(&path),
        save(dir, Arc::clone(&store), &LOUD_KEYS, &standing(), LOUD),
        audit(),
        WAIT,
    )
    .await
    .expect_err("the reload refuses");
    assert!(
        matches!(reload_refusal, ReplaceError::ReloadRefused(_)),
        "premise: the reload's refusal after the write: {reload_refusal:?}"
    );
    assert_eq!(
        store.creates(),
        1,
        "premise: the entry existed before the reload refused"
    );
    vec![format!("{store_refusal:?}"), format!("{reload_refusal:?}")]
}

/// W6: no refusal message carries the submitted secret in any form. The
/// value-check refusals of the save core join this row with that core.
#[tokio::test]
async fn no_refusal_message_contains_submitted_secret_bytes() {
    let dir = tempfile::tempdir().expect("dir");
    for refusal in loud_refusals(dir.path(), || Audit::Off).await {
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
    // The refused saves' directory: nothing in it may hold the secret. The
    // standing save keeps its entry, so it writes into its own.
    let dir = tempfile::tempdir().expect("dir");
    let kept = tempfile::tempdir().expect("dir");
    let record = dir.path().join("audit.record");
    let messages = tracing::dispatcher::with_default(&capture, || {
        runtime.block_on(async {
            let audited = || Audit::Required {
                sink: Box::new(FileSink(record.clone())),
                kind: IntentKind::Save { fields: Vec::new() },
                writer: None,
            };
            let mut seen = loud_refusals(dir.path(), audited).await;
            let path = kept.path().join("gateway.yaml");
            write_owner_only(&path, START).expect("write config");
            let saved = replace_detached(
                context(&path),
                save(
                    kept.path(),
                    Counting::new(kept.path()),
                    &LOUD_KEYS,
                    &standing(),
                    LOUD,
                ),
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
    assert!(record.exists(), "premise: the refused saves were audited");
    // A directory or file the walk cannot read fails the row: skipping it
    // would pass on exactly what it never looked at.
    for entry in walkdir::WalkDir::new(dir.path()) {
        let entry = entry.unwrap_or_else(|e| panic!("W20: the walk could not read {e}"));
        if !entry.file_type().is_file() {
            continue;
        }
        let bytes = std::fs::read(entry.path())
            .unwrap_or_else(|e| panic!("W20: {} could not be read: {e}", entry.path().display()));
        let leaked = loud_forms_in(&String::from_utf8_lossy(&bytes));
        assert!(
            leaked.is_empty(),
            "W20: {} carries the secret of a refused save ({leaked:?})",
            entry.path().display()
        );
    }
    let file = read(&kept.path().join("gateway.yaml"));
    assert!(
        loud_forms_in(&file).is_empty(),
        "W20: gateway.yaml carries the secret: {file}"
    );
}

/// Writes each intent it is handed to `path`, one per line: the record an
/// audited save leaves, read back by the row.
struct FileSink(std::path::PathBuf);

impl IntentSink for FileSink {
    fn append(&mut self, intent: &Intent) -> Result<IntentId, String> {
        use std::io::Write as _;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.0)
            .map_err(|e| e.to_string())?;
        writeln!(file, "{intent:?}").map_err(|e| e.to_string())?;
        Ok(IntentId("recorded".to_owned()))
    }
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

/// What loading `text` as gateway.yaml says.
fn load_refusal(text: &str) -> String {
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("gateway.yaml");
    write_owner_only(&path, text).expect("write config");
    crate::config::Config::load(Some(&path))
        .expect_err("a reference to a reserved name is refused")
        .to_string()
}

/// Every form a reserved reference can take in YAML is refused with its
/// name and line: an anchored scalar an alias repeats, a flow mapping, a
/// quoted key, and a scalar spread over lines.
#[test]
fn every_yaml_form_of_a_reserved_reference_is_refused_with_its_line() {
    let backend = "backends:\n  a:\n    http_url: \"http://127.0.0.1:9/mcp\"\n";
    let cases = [
        (
            "an alias",
            format!(
                "{backend}    headers:\n      X-One: &tok \"env:MCPGW_PENDING_SLOT_1\"\n      X-Two: *tok\n"
            ),
            "MCPGW_PENDING_SLOT_1",
            5,
        ),
        (
            "a flow mapping",
            format!("{backend}    headers: {{X-A: \"${{MCPGW_PENDING_SLOT_2}}\"}}\n"),
            "MCPGW_PENDING_SLOT_2",
            4,
        ),
        (
            "a quoted key",
            format!("{backend}    headers:\n      \"${{MCPGW_PENDING_SLOT_4}}\": v\n"),
            "MCPGW_PENDING_SLOT_4",
            5,
        ),
        (
            "a multi-line scalar",
            format!(
                "{backend}    headers:\n      X-B: \"first\n        ${{MCPGW_PENDING_SLOT_5}} second\"\n"
            ),
            "MCPGW_PENDING_SLOT_5",
            5,
        ),
    ];
    for (form, text, name, line) in cases {
        let refused = load_refusal(&text);
        assert!(
            refused.contains(name) && refused.contains(&format!("line {line}")),
            "{form}: the refusal names {name} and line {line}: {refused}"
        );
    }
}

/// An env file that assigns a reserved name is refused, naming it, the env
/// file and the assignment's line, as the YAML forms name theirs.
#[test]
fn an_env_file_assigning_a_reserved_name_is_refused() {
    let dir = tempfile::tempdir().expect("dir");
    let env = dir.path().join("gateway.env");
    write_owner_only(&env, "# a comment\nOTHER=1\nMCPGW_PENDING_SLOT_6=x\n")
        .expect("write env file");
    let refused = load_refusal(&format!(
        "env_files:\n  - {}\nbackends:\n  a:\n    http_url: \"http://127.0.0.1:9/mcp\"\n",
        env.display()
    ));
    assert!(
        refused.contains("MCPGW_PENDING_SLOT_6") && refused.contains("rename"),
        "the refusal names the reserved assignment: {refused}"
    );
    assert!(
        refused.contains(&env.display().to_string()) && refused.contains("line 3"),
        "the refusal names the env file and the assignment's line: {refused}"
    );
}

/// A plain scalar that only mentions the prefix, with neither `env:` nor
/// `${`, is no reference and loads.
#[test]
fn a_plain_scalar_mentioning_the_reserved_prefix_loads() {
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("gateway.yaml");
    write_owner_only(
        &path,
        "backends:\n  a:\n    http_url: \"http://127.0.0.1:9/mcp\"\n    headers:\n      X-Note: \"MCPGW_PENDING_SLOT_7 is reserved\"\n",
    )
    .expect("write config");
    crate::config::Config::load(Some(&path)).expect("a mention without a reference loads");
}

/// The shared-credential refusal names the two fields and nothing of the
/// credential: neither the submitted bearer nor its digest.
#[tokio::test]
async fn the_shared_credential_refusal_names_fields_not_the_credential() {
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("gateway.yaml");
    write_owner_only(&path, with_key("")).expect("write config");
    let refused = replace_detached(
        context(&path),
        save(
            dir.path(),
            Counting::new(dir.path()),
            &["auth", "bearer_token"],
            &with_key("  bearer_token: {slot}\n"),
            CRED,
        ),
        WAIT,
    )
    .await
    .expect_err("one secret would match two credentials");

    let ReplaceError::Refused(message) = refused else {
        panic!("premise: the shared-credential refusal: {refused:?}");
    };
    assert_eq!(
        message,
        "Configuration validation error: auth.bearer_token and auth.api_keys['ci'].key_sha256 \
         are the same credential, so one secret would match both; replace one of them"
    );
    let bearer = std::str::from_utf8(CRED).expect("utf-8");
    let digest = crate::hashing::sha256_hex(CRED);
    assert!(
        !message.contains(bearer) && !message.contains(&digest),
        "the refusal carries the credential or its digest: {message}"
    );
}

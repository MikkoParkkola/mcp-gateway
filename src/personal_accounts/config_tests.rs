// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use std::cell::RefCell;

use super::*;

/// 32 bytes of `0x51`, base64 — the only shape `accounts.keys` accepts.
///
/// 44 characters, which is what 32 bytes encodes to. An earlier draft used the
/// 40-character string, decoding to 29 bytes, and the byte-for-byte assertions
/// below could then be satisfied by a mapper that ignored the overlay and
/// stuffed `[0x51; 32]` in directly. The literals are asserted against their own
/// decodings at the top of the positive test, before anything can panic.
const KEY_B64: &str = "UVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVE=";
/// A different 32 bytes, every byte `0x52`, referenced by `RETIRED_VAR`.
const RETIRED_KEY_B64: &str = "UlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlI=";
/// What each reference must decode to, byte for byte.
const CURRENT_KEY: [u8; 32] = [0x51; 32];
const RETIRED_KEY: [u8; 32] = [0x52; 32];

/// The approved storage bound, not an invented ceiling.
///
/// `storage.rs::validate_config` refuses a configuration whose
/// `max_authority_bytes.checked_add(16).and_then(|size| size.checked_mul(4))`
/// overflows, and the approved configuration table (design doc row 432) says
/// `accounts.limits` must "reject zero/overflow". So the largest accepted value
/// is the one that still survives that arithmetic: `(usize::MAX / 4) - 16`.
/// Nothing of this size is ever allocated — it is a bound, checked as a number.
const MAX_AUTHORITY_BYTES: usize = (usize::MAX / 4) - 16;
/// Valid base64, fewer than 32 decoded bytes: the axis a length check catches
/// and a decode check does not. Its exact length is asserted with the others.
const SHORT_KEY_B64: &str = "UVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUQ==";
const KEY_VAR: &str = "MCP_ACCOUNTS_KEY_CURRENT";
const RETIRED_VAR: &str = "MCP_ACCOUNTS_KEY_RETIRED";

#[track_caller]
fn refuse_scaffold<T>(
    result: Result<T, AccountsConfigError>,
    what: &str,
) -> Result<T, AccountsConfigError> {
    match result {
        Err(AccountsConfigError::RuntimeNotImplemented) => {
            panic!("{what}: RuntimeNotImplemented is the scaffold, not a domain outcome")
        }
        other => other,
    }
}

#[track_caller]
fn domain_err<T>(result: Result<T, AccountsConfigError>, what: &str) -> AccountsConfigError {
    refuse_scaffold(result, what).err().expect(what)
}

/// Counts every lookup, so a test can assert WHICH variables were read and how
/// often — a resolver that reads the environment directly reads nothing here
/// and fails the count.
struct CountingOverlay {
    values: Vec<(String, String)>,
    looked_up: RefCell<Vec<String>>,
}

impl CountingOverlay {
    fn new(values: &[(&str, &str)]) -> Self {
        Self {
            values: values
                .iter()
                .map(|(k, v)| ((*k).into(), (*v).into()))
                .collect(),
            looked_up: RefCell::new(Vec::new()),
        }
    }

    fn lookups(&self) -> Vec<String> {
        self.looked_up.borrow().clone()
    }
}

impl SecretOverlay for CountingOverlay {
    fn resolve(&self, name: &str) -> Option<String> {
        self.looked_up.borrow_mut().push(name.to_string());
        self.values
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
    }
}

fn root() -> tempfile::TempDir {
    tempfile::TempDir::new().expect("accounts config fixture root")
}

fn valid(root: &std::path::Path) -> AccountsConfig {
    AccountsConfig {
        schema_version: "accounts.v1".into(),
        enabled: true,
        deployment: "single_process".into(),
        instance_id: "gateway-instance".into(),
        store_dir: root.join("records"),
        authority_dir: root.join("authority"),
        current_key_id: "current".into(),
        keys: BTreeMap::from([
            ("current".into(), format!("env:{KEY_VAR}")),
            ("retired".into(), format!("env:{RETIRED_VAR}")),
        ]),
        descriptors: Default::default(),
        limits: AccountsLimits {
            store_entries: 10_000,
            authority_bytes: 16_777_216,
        },
    }
}

fn overlay() -> CountingOverlay {
    CountingOverlay::new(&[(KEY_VAR, KEY_B64), (RETIRED_VAR, RETIRED_KEY_B64)])
}

#[test]
fn a_valid_block_resolves_to_store_config_and_reads_exactly_its_key_refs() {
    // FIRST, before anything can panic: the fixtures are what they claim.
    // `refuse_scaffold` panics on the scaffold, so an assertion placed after it
    // never runs — a typo in a literal would then hide behind the refusal and
    // only surface once the runtime went green.
    use base64::Engine as _;
    let decoded = |label: &str, encoded: &str| {
        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap_or_else(|error| panic!("{label} must be valid base64: {error}"))
    };
    assert_eq!(
        decoded("KEY_B64", KEY_B64),
        CURRENT_KEY.to_vec(),
        "the current fixture must decode to exactly the 32 bytes it is compared against"
    );
    assert_eq!(
        decoded("RETIRED_KEY_B64", RETIRED_KEY_B64),
        RETIRED_KEY.to_vec(),
        "the retired fixture must decode to exactly the 32 bytes it is compared against"
    );
    assert_ne!(
        CURRENT_KEY, RETIRED_KEY,
        "the two references must be distinguishable"
    );
    assert_ne!(
        decoded("SHORT_KEY_B64", SHORT_KEY_B64).len(),
        32,
        "the short fixture must actually be the wrong length"
    );

    let tmp = root();
    let config = valid(tmp.path());
    let env = overlay();

    let resolved = refuse_scaffold(resolve(Some(&config), &env), "valid accounts block")
        .expect("a complete valid block resolves")
        .expect("accounts present means custody is configured");

    assert_eq!(resolved.store.instance_id, "gateway-instance");
    assert_eq!(resolved.store.store_dir, config.store_dir);
    assert_eq!(resolved.store.authority_dir, config.authority_dir);
    assert_eq!(resolved.store.current_key_id, "current");
    assert_eq!(
        resolved.store.max_entries, 10_000,
        "limits.store_entries maps onto the existing StoreConfig bound"
    );
    assert_eq!(resolved.store.max_authority_bytes, 16_777_216);

    // Both key ids survive: an old entry stays readable so a rotated record
    // still opens.
    assert_eq!(
        resolved.store.keys.keys().collect::<Vec<_>>(),
        vec!["current", "retired"]
    );
    // THE BINDING, not just the length: each key id must hold exactly the bytes
    // its own `env:` reference decoded to. Reading both variables and then
    // installing any 32 bytes — or the same bytes twice — fails here.
    assert_eq!(
        resolved.store.keys.get("current").map(Vec::as_slice),
        Some(CURRENT_KEY.as_slice()),
        "the current key must be exactly what MCP_ACCOUNTS_KEY_CURRENT decoded to"
    );
    assert_eq!(
        resolved.store.keys.get("retired").map(Vec::as_slice),
        Some(RETIRED_KEY.as_slice()),
        "the retired key must be exactly what MCP_ACCOUNTS_KEY_RETIRED decoded to"
    );
    assert_eq!(
        resolved.store.keys.get("current").map(Vec::as_slice),
        Some(decoded("KEY_B64", KEY_B64).as_slice()),
        "the installed current key must be the decoding of its own env: reference"
    );
    assert_eq!(
        resolved.store.keys.get("retired").map(Vec::as_slice),
        Some(decoded("RETIRED_KEY_B64", RETIRED_KEY_B64).as_slice()),
        "the installed retired key must be the decoding of its own env: reference"
    );

    // Exactly the two declared references, once each, and nothing else.
    let mut lookups = env.lookups();
    lookups.sort();
    assert_eq!(lookups, vec![KEY_VAR.to_string(), RETIRED_VAR.to_string()]);
    assert_eq!(resolved.secret_refs_read.len(), 2);
}

#[test]
fn omitted_accounts_enables_no_custody_and_reads_nothing() {
    let env = overlay();
    let resolved = refuse_scaffold(resolve(None, &env), "omitted accounts block")
        .expect("an omitted block is valid configuration, not an error");
    assert!(
        resolved.is_none(),
        "omitted accounts must preserve existing behaviour and enable no managed custody"
    );
    assert!(
        env.lookups().is_empty(),
        "nothing may be read when nothing is configured"
    );
}

/// One axis at a time. Each case moves exactly one field of an otherwise valid
/// block, so a refusal names the rule that fired instead of the first one a
/// combined-invalid fixture happens to hit.
#[test]
fn each_unsafe_axis_is_refused_on_its_own() {
    let tmp = root();
    let base = valid(tmp.path());
    let nested = base.store_dir.join("authority");
    let relative = std::path::PathBuf::from("relative/records");

    let cases: Vec<(&str, AccountsConfig, AccountsConfigError)> = vec![
        (
            "schema_version",
            AccountsConfig {
                schema_version: "accounts.v2".into(),
                ..base.clone()
            },
            AccountsConfigError::SchemaVersion,
        ),
        (
            "deployment",
            AccountsConfig {
                deployment: "multi_process".into(),
                ..base.clone()
            },
            AccountsConfigError::Deployment,
        ),
        (
            "enabled",
            AccountsConfig {
                enabled: false,
                ..base.clone()
            },
            AccountsConfigError::NotEnabled,
        ),
        (
            "instance_id",
            AccountsConfig {
                instance_id: String::new(),
                ..base.clone()
            },
            AccountsConfigError::InstanceId,
        ),
        (
            "relative store_dir",
            AccountsConfig {
                store_dir: relative,
                ..base.clone()
            },
            AccountsConfigError::Directory { field: "store_dir" },
        ),
        (
            "nested authority_dir",
            AccountsConfig {
                authority_dir: nested,
                ..base.clone()
            },
            AccountsConfigError::DirectoriesNotDisjoint,
        ),
        (
            "identical directories",
            AccountsConfig {
                authority_dir: base.store_dir.clone(),
                ..base.clone()
            },
            AccountsConfigError::DirectoriesNotDisjoint,
        ),
        (
            "current_key_id absent from keys",
            AccountsConfig {
                current_key_id: "rotated".into(),
                ..base.clone()
            },
            AccountsConfigError::CurrentKeyMissing,
        ),
        (
            "inline literal key",
            AccountsConfig {
                keys: BTreeMap::from([("current".into(), KEY_B64.into())]),
                current_key_id: "current".into(),
                ..base.clone()
            },
            AccountsConfigError::KeyNotAReference {
                key_id: "current".into(),
            },
        ),
        (
            "zero store_entries",
            AccountsConfig {
                limits: AccountsLimits {
                    store_entries: 0,
                    ..base.limits
                },
                ..base.clone()
            },
            AccountsConfigError::Limit {
                field: "store_entries",
            },
        ),
        (
            "zero authority_bytes",
            AccountsConfig {
                limits: AccountsLimits {
                    authority_bytes: 0,
                    ..base.limits
                },
                ..base.clone()
            },
            AccountsConfigError::Limit {
                field: "authority_bytes",
            },
        ),
        (
            "authority_bytes one past the approved bound",
            AccountsConfig {
                limits: AccountsLimits {
                    authority_bytes: MAX_AUTHORITY_BYTES + 1,
                    ..base.limits
                },
                ..base.clone()
            },
            AccountsConfigError::Limit {
                field: "authority_bytes",
            },
        ),
    ];

    for (label, config, expected) in cases {
        let env = overlay();
        assert_eq!(
            domain_err(resolve(Some(&config), &env), label),
            expected,
            "{label} must be refused on its own axis"
        );
    }

    // The control: the unmodified block still resolves, so "refuses everything"
    // cannot pass the cases above.
    let env = overlay();
    assert!(
        refuse_scaffold(resolve(Some(&base), &env), "control").is_ok(),
        "the unmodified valid block must still resolve"
    );

    // The OTHER side of the bound. Rejecting one past it is only meaningful if
    // the bound itself is accepted -- otherwise a mapper that refuses anything
    // large would pass the overflow case for the wrong reason. Nothing of this
    // size is allocated; it is carried as a number and mapped onto the existing
    // `StoreConfig` field.
    let env = overlay();
    let at_bound = refuse_scaffold(
        resolve(
            Some(&AccountsConfig {
                limits: AccountsLimits {
                    authority_bytes: MAX_AUTHORITY_BYTES,
                    ..base.limits
                },
                ..base.clone()
            }),
            &env,
        ),
        "authority_bytes exactly at the approved bound",
    )
    .expect("the largest value storage::validate_config accepts must resolve")
    .expect("accounts present");
    assert_eq!(
        at_bound.store.max_authority_bytes, MAX_AUTHORITY_BYTES,
        "the bound is forwarded unchanged, not clamped to an invented default"
    );
}

/// Key material axes need their own case: the reference resolves, and what it
/// resolves TO is what is wrong.
#[test]
fn key_material_is_validated_after_the_reference_resolves() {
    let tmp = root();
    let base = valid(tmp.path());

    let unresolved = CountingOverlay::new(&[(RETIRED_VAR, KEY_B64)]);
    assert_eq!(
        domain_err(resolve(Some(&base), &unresolved), "unresolved reference"),
        AccountsConfigError::KeyReferenceUnresolved {
            key_id: "current".into(),
            variable: KEY_VAR.into(),
        },
        "an unresolvable reference is reported, never silently emptied"
    );

    for (label, value) in [
        ("wrong length", SHORT_KEY_B64),
        ("not base64", "not-base64-$$$"),
        ("empty", ""),
    ] {
        let env = CountingOverlay::new(&[(KEY_VAR, value), (RETIRED_VAR, KEY_B64)]);
        assert_eq!(
            domain_err(resolve(Some(&base), &env), label),
            AccountsConfigError::KeyMaterial {
                key_id: "current".into()
            },
            "{label} key material must be refused"
        );
    }
}

/// The leak test. A resolved 32-byte key must not appear in any rendering of
/// anything on this path — not raw, not base64, not hex.
#[test]
fn no_rendering_on_the_resolution_path_reveals_key_material() {
    let tmp = root();
    let base = valid(tmp.path());
    let env = overlay();

    let resolved = refuse_scaffold(resolve(Some(&base), &env), "redaction fixture")
        .expect("valid block")
        .expect("accounts present");

    let key_bytes = resolved
        .store
        .keys
        .get("current")
        .expect("current key present")
        .clone();
    let rendered = format!("{resolved:?}");
    let hex_key = key_bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let raw_key = String::from_utf8_lossy(&key_bytes).to_string();

    for (label, needle) in [
        ("base64", KEY_B64),
        ("hex", hex_key.as_str()),
        ("raw", raw_key.as_str()),
    ] {
        assert!(
            !rendered.contains(needle),
            "{label} key material appeared in a Debug rendering: {rendered}"
        );
    }
    assert!(
        rendered.contains("current"),
        "key IDs stay visible for diagnosis"
    );

    // Every refusal message is rendered too: an error that echoes the resolved
    // value would put it in the log line that reports the failure.
    let bad = CountingOverlay::new(&[(KEY_VAR, SHORT_KEY_B64), (RETIRED_VAR, KEY_B64)]);
    let error = domain_err(resolve(Some(&base), &bad), "short key");
    let message = format!("{error} {error:?}");
    assert!(
        !message.contains(SHORT_KEY_B64),
        "an error must not echo key material"
    );
    assert!(
        message.contains("current"),
        "an error names the key id it refused"
    );
}

#[test]
fn a_later_inline_literal_is_refused_without_reading_the_earlier_env_ref() {
    let tmp = root();
    let base = valid(tmp.path());

    let control = overlay();
    refuse_scaffold(resolve(Some(&base), &control), "two-reference control")
        .expect("valid two-reference fixture must resolve");
    let mut control_lookups = control.lookups();
    control_lookups.sort();
    assert_eq!(
        control_lookups,
        vec![KEY_VAR.to_string(), RETIRED_VAR.to_string()],
        "the two-reference control must account for both env reads"
    );

    let env = overlay();
    let keys = BTreeMap::from([
        ("current".into(), format!("env:{KEY_VAR}")),
        ("retired".into(), KEY_B64.into()),
    ]);
    assert_eq!(
        keys.keys().collect::<Vec<_>>(),
        vec!["current", "retired"],
        "BTree order must visit the valid env reference before the inline literal"
    );
    let config = AccountsConfig { keys, ..base };
    assert_eq!(
        domain_err(
            resolve(Some(&config), &env),
            "retired inline after current env"
        ),
        AccountsConfigError::KeyNotAReference {
            key_id: "retired".into(),
        },
    );
    assert!(
        env.lookups().is_empty(),
        "structure must be validated before any overlay read"
    );
}

#[test]
fn an_absolute_directory_with_a_parent_component_is_refused_without_reading_secrets() {
    {
        let tmp = root();
        let mut config = valid(tmp.path());
        config.store_dir = config.store_dir.join("..");
        assert!(
            config.store_dir.is_absolute(),
            "the store_dir fixture must stay absolute so the refusal is the ParentDir axis"
        );
        let env = overlay();
        assert_eq!(
            domain_err(resolve(Some(&config), &env), "store_dir ParentDir"),
            AccountsConfigError::Directory { field: "store_dir" },
        );
        assert!(
            env.lookups().is_empty(),
            "store_dir ParentDir must be refused before any overlay read"
        );
    }
    {
        let tmp = root();
        let mut config = valid(tmp.path());
        config.authority_dir = config.authority_dir.join("..");
        assert!(
            config.authority_dir.is_absolute(),
            "the authority_dir fixture must stay absolute so the refusal is the ParentDir axis"
        );
        let env = overlay();
        assert_eq!(
            domain_err(resolve(Some(&config), &env), "authority_dir ParentDir"),
            AccountsConfigError::Directory {
                field: "authority_dir",
            },
        );
        assert!(
            env.lookups().is_empty(),
            "authority_dir ParentDir must be refused before any overlay read"
        );
    }
}

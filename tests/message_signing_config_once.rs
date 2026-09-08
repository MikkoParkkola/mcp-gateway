// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! SIGNING.2: evaluated key bytes are opaque across subsequent validation.

use mcp_gateway::config::{Config, EnvOverlay};
use serde_json::json;

struct Fixture {
    _directory: tempfile::TempDir,
    path: std::path::PathBuf,
    overlay: EnvOverlay,
    outer_current: String,
    outer_previous: String,
    current: String,
    previous: String,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let suffix: String = directory
            .path()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .map(|c| c.to_ascii_uppercase())
            .collect();
        let outer_current = format!("MIK7406_ONCE_CURRENT_{suffix}");
        let outer_previous = format!("MIK7406_ONCE_PREVIOUS_{suffix}");
        let inner = format!("MIK7406_OPAQUE_INNER_REFERENCE_{suffix}");
        for name in [&outer_current, &outer_previous, &inner] {
            assert!(std::env::var_os(name).is_none());
        }
        let current = format!("env:{inner}");
        let previous = format!("${{{inner}}}");
        assert!(current.len() >= 32 && previous.len() >= 32);
        let env_path = directory.path().join("keys.env");
        // Single quotes preserve reference-like bytes through dotenv parsing.
        std::fs::write(&env_path, format!(
            "{outer_current}='{current}'\n{outer_previous}='{previous}'\n{inner}=unexpected-second-expansion\n"
        )).unwrap();
        let overlay = EnvOverlay::from_paths_checked(&[env_path.clone()]).unwrap();
        assert_eq!(
            overlay.resolve(&outer_current).as_deref(),
            Some(current.as_str())
        );
        assert_eq!(
            overlay.resolve(&outer_previous).as_deref(),
            Some(previous.as_str())
        );
        let path = directory.path().join("gateway.yaml");
        std::fs::write(
            &path,
            serde_yaml::to_string(&json!({
                "env_files":[env_path], "security":{"message_signing":{
                    "enabled":true,"shared_secret":format!("env:{outer_current}"),
                    "previous_secret":format!("${{{outer_previous}}}"), "key_id":"opaque-keys"
                }}
            }))
            .unwrap(),
        )
        .unwrap();
        Self {
            _directory: directory,
            path,
            overlay,
            outer_current,
            outer_previous,
            current,
            previous,
        }
    }

    fn evaluated(&self) -> Config {
        let evaluated = Config::load_evaluated(Some(&self.path)).unwrap();
        let signing = &evaluated.config.security.message_signing;
        assert_eq!(
            signing.shared_secret, self.current,
            "first resolution must use exact current key bytes"
        );
        assert_eq!(
            signing.previous_secret, self.previous,
            "first resolution must use exact previous key bytes"
        );
        evaluated.config
    }
}

#[test]
fn signing_config_resolved_reference_like_keys_remain_opaque() {
    let fixture = Fixture::new();
    let config = fixture.evaluated();
    config
        .validate_with_env(&fixture.overlay)
        .expect("validation must not expand effective keys again");
    config
        .validate()
        .expect("effective keys do not require their original environment");
    let cloned = config.clone();
    cloned
        .validate()
        .expect("cloning preserves effective key identity");
    let serialized = serde_json::to_value(&cloned.security.message_signing).unwrap();
    let mut fields: Vec<_> = serialized
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    fields.sort_unstable();
    assert_eq!(
        fields,
        [
            "enabled",
            "key_id",
            "previous_secret",
            "replay_window",
            "require_nonce",
            "shared_secret"
        ]
    );
    assert_eq!(serialized["shared_secret"], fixture.current);
    assert_eq!(serialized["previous_secret"], fixture.previous);
}

#[test]
fn signing_config_mutated_key_invalidates_only_its_resolution_identity() {
    let fixture = Fixture::new();
    for field in ["shared_secret", "previous_secret"] {
        let mut config = fixture.evaluated();
        let missing = format!("env:MIK7406_MISSING_{}", fixture.outer_current);
        assert!(std::env::var_os(missing.trim_start_matches("env:")).is_none());
        let signing = &mut config.security.message_signing;
        if field == "shared_secret" {
            signing.shared_secret.clone_from(&missing);
        } else {
            signing.previous_secret.clone_from(&missing);
        }
        let error = config
            .validate_with_env(&fixture.overlay)
            .expect_err("changed reference must be re-evaluated");
        for output in [error.to_string(), format!("{error:?}")] {
            assert!(output.contains(field));
            for secret in [&missing, &fixture.current, &fixture.previous] {
                assert!(!output.contains(secret));
            }
        }
        let signing = &mut config.security.message_signing;
        if field == "shared_secret" {
            signing.shared_secret = format!("env:{}", fixture.outer_current);
        } else {
            signing.previous_secret = format!("${{{}}}", fixture.outer_previous);
        }
        config
            .validate_with_env(&fixture.overlay)
            .expect("changed key resolves once; other effective key remains opaque");
    }
}

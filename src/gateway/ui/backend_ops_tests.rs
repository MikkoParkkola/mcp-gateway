// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Tests for the backend CRUD operations shared by the CLI and the UI.

mod tests {
    use super::super::*;

    fn empty_config() -> Config {
        Config::default()
    }

    fn stdio_transport(cmd: &str) -> TransportConfig {
        TransportConfig::Stdio {
            command: cmd.to_string(),
            cwd: None,
            protocol_version: None,
        }
    }

    fn http_transport(url: &str) -> TransportConfig {
        TransportConfig::Http {
            http_url: url.to_string(),
            streamable_http: false,
            protocol_version: None,
        }
    }

    // ── add_backend ───────────────────────────────────────────────────────────

    #[test]
    fn add_backend_inserts_entry() {
        let mut cfg = empty_config();
        add_backend(
            &mut cfg,
            "my-server",
            stdio_transport("node server.js"),
            "My server".to_string(),
            HashMap::new(),
        )
        .unwrap();

        let b = cfg.backends.get("my-server").unwrap();
        assert_eq!(b.description, "My server");
        assert!(b.enabled);
        match &b.transport {
            TransportConfig::Stdio { command, .. } => assert_eq!(command, "node server.js"),
            other => panic!("expected Stdio, got {other:?}"),
        }
    }

    #[test]
    fn add_backend_duplicate_returns_error() {
        let mut cfg = empty_config();
        add_backend(
            &mut cfg,
            "dup",
            stdio_transport("cmd"),
            String::new(),
            HashMap::new(),
        )
        .unwrap();

        let err = add_backend(
            &mut cfg,
            "dup",
            stdio_transport("cmd"),
            String::new(),
            HashMap::new(),
        )
        .unwrap_err();
        assert!(err.contains("already exists"));
    }

    #[test]
    fn add_backend_stores_env_vars() {
        let mut cfg = empty_config();
        let env = HashMap::from([("API_KEY".to_string(), "secret".to_string())]);
        add_backend(&mut cfg, "svc", stdio_transport("cmd"), String::new(), env).unwrap();

        assert_eq!(
            cfg.backends["svc"].env.get("API_KEY").map(String::as_str),
            Some("secret")
        );
    }

    // ── remove_backend ────────────────────────────────────────────────────────

    #[test]
    fn remove_backend_deletes_existing() {
        let mut cfg = empty_config();
        add_backend(
            &mut cfg,
            "to-remove",
            stdio_transport("cmd"),
            String::new(),
            HashMap::new(),
        )
        .unwrap();

        remove_backend(&mut cfg, "to-remove").unwrap();
        assert!(!cfg.backends.contains_key("to-remove"));
    }

    #[test]
    fn remove_backend_missing_returns_error() {
        let mut cfg = empty_config();
        let err = remove_backend(&mut cfg, "ghost").unwrap_err();
        assert!(err.contains("not found"));
    }

    // ── update_backend ────────────────────────────────────────────────────────

    #[test]
    fn update_backend_changes_description() {
        let mut cfg = empty_config();
        add_backend(
            &mut cfg,
            "svc",
            stdio_transport("cmd"),
            "old desc".to_string(),
            HashMap::new(),
        )
        .unwrap();

        update_backend(
            &mut cfg,
            "svc",
            BackendUpdate {
                description: Some("new desc".to_string()),
                ..Default::default()
            },
        )
        .unwrap();

        assert_eq!(cfg.backends["svc"].description, "new desc");
    }

    #[test]
    fn update_backend_partial_leaves_other_fields_intact() {
        let mut cfg = empty_config();
        let env = HashMap::from([("K".to_string(), "V".to_string())]);
        add_backend(
            &mut cfg,
            "svc",
            stdio_transport("original-cmd"),
            "desc".to_string(),
            env,
        )
        .unwrap();

        update_backend(
            &mut cfg,
            "svc",
            BackendUpdate {
                enabled: Some(false),
                ..Default::default()
            },
        )
        .unwrap();

        let b = &cfg.backends["svc"];
        assert!(!b.enabled);
        assert_eq!(b.description, "desc"); // unchanged
        assert_eq!(b.env.get("K").map(String::as_str), Some("V")); // unchanged
    }

    #[test]
    fn update_backend_missing_returns_error() {
        let mut cfg = empty_config();
        let err = update_backend(&mut cfg, "ghost", BackendUpdate::default()).unwrap_err();
        assert!(err.contains("not found"));
    }

    #[test]
    fn update_backend_replaces_transport() {
        let mut cfg = empty_config();
        add_backend(
            &mut cfg,
            "svc",
            stdio_transport("old"),
            String::new(),
            HashMap::new(),
        )
        .unwrap();

        update_backend(
            &mut cfg,
            "svc",
            BackendUpdate {
                transport: Some(http_transport("http://localhost:9000")),
                ..Default::default()
            },
        )
        .unwrap();

        match &cfg.backends["svc"].transport {
            TransportConfig::Http { http_url, .. } => {
                assert_eq!(http_url, "http://localhost:9000");
            }
            other => panic!("expected Http after update, got {other:?}"),
        }
    }

    // ── list_backends ─────────────────────────────────────────────────────────

    #[test]
    fn list_backends_returns_sorted_names() {
        let mut cfg = empty_config();
        add_backend(
            &mut cfg,
            "zebra",
            stdio_transport("z"),
            String::new(),
            HashMap::new(),
        )
        .unwrap();
        add_backend(
            &mut cfg,
            "alpha",
            stdio_transport("a"),
            String::new(),
            HashMap::new(),
        )
        .unwrap();

        let list = list_backends(&cfg);
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].name, "alpha");
        assert_eq!(list[1].name, "zebra");
    }

    #[test]
    fn list_backends_empty_config_returns_empty_vec() {
        let cfg = empty_config();
        assert!(list_backends(&cfg).is_empty());
    }

    #[test]
    fn list_backends_http_transport_sets_url_field() {
        let mut cfg = empty_config();
        add_backend(
            &mut cfg,
            "remote",
            http_transport("https://api.example.com/mcp"),
            String::new(),
            HashMap::new(),
        )
        .unwrap();

        let info = &list_backends(&cfg)[0];
        assert_eq!(info.transport, "http");
        // Origin only. The path is dropped because a webhook-style URL keeps its
        // whole secret there (MIK-7221).
        assert_eq!(info.url.as_deref(), Some("https://api.example.com"));
        assert!(info.command.is_none());
    }

    #[test]
    fn list_backends_stdio_transport_sets_command_field() {
        let mut cfg = empty_config();
        add_backend(
            &mut cfg,
            "local",
            stdio_transport("npx my-server"),
            String::new(),
            HashMap::new(),
        )
        .unwrap();

        let info = &list_backends(&cfg)[0];
        assert_eq!(info.transport, "stdio");
        // The executable is reported; the arguments are counted, never shown.
        // This assertion used to read `Some("npx my-server")` — the whole command
        // string, which is where an `--api-key` would have been (MIK-7221).
        let command = info.command.as_ref().expect("stdio backend has a command");
        assert_eq!(command.executable, "npx");
        assert_eq!(command.argument_count, 1);
        assert!(info.url.is_none());
    }

    // ── get_backend ───────────────────────────────────────────────────────────

    #[test]
    fn get_backend_returns_info_for_known_name() {
        let mut cfg = empty_config();
        add_backend(
            &mut cfg,
            "known",
            stdio_transport("cmd"),
            "description".to_string(),
            HashMap::new(),
        )
        .unwrap();

        let info = get_backend(&cfg, "known").unwrap();
        assert_eq!(info.name, "known");
        assert_eq!(info.description, "description");
    }

    #[test]
    fn get_backend_missing_returns_error() {
        let cfg = empty_config();
        let err = get_backend(&cfg, "missing").unwrap_err();
        assert!(err.contains("not found"));
    }

    // ── resolve_transport ─────────────────────────────────────────────────────

    #[test]
    fn resolve_transport_explicit_command_takes_priority() {
        let (transport, _) = resolve_transport("tavily", Some("my-cmd"), None, None).unwrap();
        match transport {
            TransportConfig::Stdio { command, .. } => assert_eq!(command, "my-cmd"),
            other => panic!("expected Stdio, got {other:?}"),
        }
    }

    #[test]
    fn resolve_transport_explicit_url() {
        let (transport, _) =
            resolve_transport("custom", None, Some("http://localhost:9000"), None).unwrap();
        match transport {
            TransportConfig::Http { http_url, .. } => assert_eq!(http_url, "http://localhost:9000"),
            other => panic!("expected Http, got {other:?}"),
        }
    }

    #[test]
    fn resolve_transport_registry_lookup_for_known_name() {
        let (transport, description) = resolve_transport("tavily", None, None, None).unwrap();
        match transport {
            TransportConfig::Stdio { command, .. } => {
                assert!(command.contains("tavily"));
            }
            other => panic!("expected Stdio for tavily, got {other:?}"),
        }
        assert!(!description.is_empty());
    }

    #[test]
    fn resolve_transport_unknown_name_without_flags_returns_error() {
        let result = resolve_transport("totally-unknown-server-xyz", None, None, None);
        assert!(result.is_err());
    }

    #[test]
    fn resolve_transport_desc_override_applies_for_registry_entry() {
        let (_, description) =
            resolve_transport("tavily", None, None, Some("my custom desc")).unwrap();
        assert_eq!(description, "my custom desc");
    }

    // ── parse_env_vars ────────────────────────────────────────────────────────

    #[test]
    fn parse_env_vars_valid_pairs_returns_map() {
        let vars = vec!["KEY=value".to_string(), "FOO=bar".to_string()];
        let map = parse_env_vars(&vars).unwrap();
        assert_eq!(map["KEY"], "value");
        assert_eq!(map["FOO"], "bar");
    }

    #[test]
    fn parse_env_vars_value_contains_equals_keeps_full_value() {
        let vars = vec!["URL=http://host:80/path?a=b".to_string()];
        let map = parse_env_vars(&vars).unwrap();
        assert_eq!(map["URL"], "http://host:80/path?a=b");
    }

    #[test]
    fn parse_env_vars_missing_equals_returns_error() {
        let vars = vec!["NOEQUALS".to_string()];
        assert!(parse_env_vars(&vars).is_err());
    }

    #[test]
    fn parse_env_vars_empty_slice_returns_empty_map() {
        let map = parse_env_vars(&[]).unwrap();
        assert!(map.is_empty());
    }

    // ── backend_to_info (via list/get) ────────────────────────────────────────

    #[test]
    fn backend_info_serializes_to_json() {
        let mut cfg = empty_config();
        let env = HashMap::from([("TOKEN".to_string(), "abc".to_string())]);
        add_backend(
            &mut cfg,
            "svc",
            http_transport("https://svc.example.com"),
            "A service".to_string(),
            env,
        )
        .unwrap();

        let info = get_backend(&cfg, "svc").unwrap();
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"name\":\"svc\""));
        assert!(json.contains("\"transport\":\"http\""));
        assert!(json.contains("\"enabled\":true"));
        // The name is reported, the value never is. This assertion used to read
        // `json.contains("\"TOKEN\":\"abc\"")` — it asserted the leak, and passed
        // for as long as the leak existed (MIK-7221).
        assert!(json.contains("\"TOKEN\""), "the variable NAME is reported");
        assert!(
            !json.contains("abc"),
            "the VALUE must never be serialised: {json}"
        );
        // command should not appear for http transport
        assert!(!json.contains("\"command\""));
    }
}

#[cfg(test)]
mod stop_when_idle_ui_tests {
    use super::super::*;

    fn stdio_backend() -> BackendConfig {
        BackendConfig {
            transport: TransportConfig::Stdio {
                command: "echo hi".to_string(),
                cwd: None,
                protocol_version: None,
            },
            ..BackendConfig::default()
        }
    }

    fn http_backend() -> BackendConfig {
        BackendConfig {
            transport: TransportConfig::Http {
                http_url: "http://127.0.0.1:39400/mcp".to_string(),
                streamable_http: false,
                protocol_version: None,
            },
            ..BackendConfig::default()
        }
    }

    fn config_with(name: &str, backend: BackendConfig) -> Config {
        let mut c = Config::default();
        c.backends.insert(name.to_string(), backend);
        c
    }

    // GW.IDLE.10 - settable from the panel on a backend the gateway starts.
    #[test]
    fn panel_can_set_and_clear_stop_when_idle_on_an_owned_backend() {
        let mut config = config_with("owned", stdio_backend());

        update_backend(
            &mut config,
            "owned",
            BackendUpdate {
                stop_when_idle_for: Some(Some(Duration::from_secs(300))),
                ..Default::default()
            },
        )
        .expect("an owned backend may opt in");
        assert_eq!(
            config.backends["owned"].stop_when_idle_for,
            Some(Duration::from_secs(300))
        );

        // And it must be switchable back off, or the panel is a one-way door.
        update_backend(
            &mut config,
            "owned",
            BackendUpdate {
                stop_when_idle_for: Some(None),
                ..Default::default()
            },
        )
        .expect("clearing must be possible");
        assert_eq!(config.backends["owned"].stop_when_idle_for, None);
    }

    // The panel must refuse, not silently drop. Silently dropping is exactly how
    // `idle_timeout` came to sit on 24 backends doing nothing.
    #[test]
    fn panel_refuses_stop_when_idle_on_a_backend_the_gateway_does_not_start() {
        let mut config = config_with("external", http_backend());

        let err = update_backend(
            &mut config,
            "external",
            BackendUpdate {
                stop_when_idle_for: Some(Some(Duration::from_secs(300))),
                ..Default::default()
            },
        )
        .expect_err("the gateway cannot stop a process it did not start");

        assert!(err.contains("external"), "must name the backend: {err}");
        assert_eq!(
            config.backends["external"].stop_when_idle_for, None,
            "a refused update must not partially apply"
        );
    }

    // An omitted field must leave the existing setting alone.
    #[test]
    fn an_unrelated_panel_edit_does_not_disturb_the_setting() {
        let mut config = config_with("owned", stdio_backend());
        config.backends.get_mut("owned").unwrap().stop_when_idle_for =
            Some(Duration::from_secs(600));

        update_backend(
            &mut config,
            "owned",
            BackendUpdate {
                description: Some("renamed".to_string()),
                ..Default::default()
            },
        )
        .expect("update");

        assert_eq!(
            config.backends["owned"].stop_when_idle_for,
            Some(Duration::from_secs(600)),
            "editing the description must not silently clear an unrelated setting"
        );
    }

    // The panel needs to know whether to offer the control at all.
    #[test]
    fn backend_info_reports_whether_the_control_is_offerable() {
        let owned = config_with("owned", stdio_backend());
        let external = config_with("external", http_backend());

        assert!(
            get_backend(&owned, "owned")
                .expect("info")
                .can_stop_when_idle,
            "a gateway-started backend can be stopped"
        );
        assert!(
            !get_backend(&external, "external")
                .expect("info")
                .can_stop_when_idle,
            "the panel must hide the control for a backend the gateway did not start"
        );
    }
}

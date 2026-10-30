// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8512 red tests: the pure parts (decision, parser, allowlist, URL,
//! proxy route, document read, sanitizer, hint). The network rows are in
//! `npm_pin_wire_tests.rs`.

use std::collections::{BTreeSet, HashMap};

use mcp_gateway::config::{BackendConfig, TransportConfig};

use super::*;

fn pin(name: &str, version: &str) -> Pin {
    Pin {
        name: name.to_string(),
        version: version.to_string(),
    }
}

fn stdio(command: &str, env: &[(&str, &str)]) -> BackendConfig {
    BackendConfig {
        transport: TransportConfig::Stdio {
            command: command.to_string(),
            cwd: None,
            protocol_version: None,
        },
        env: env
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect::<HashMap<_, _>>(),
        ..BackendConfig::default()
    }
}

// ── decide: on by default (operator ruling 2026-10-22) ─────────────────────

#[test]
fn the_lookup_is_on_unless_switched_off_or_hardened() {
    assert_eq!(decide(false, false), Lookup::On);
    assert_eq!(decide(true, false), Lookup::OffByFlag);
    assert_eq!(decide(false, true), Lookup::OffByPosture);
    // The flag wins the reason when both apply: it is what the user typed.
    assert_eq!(decide(true, true), Lookup::OffByFlag);
}

#[test]
fn the_hardened_posture_turns_the_lookup_off() {
    let mut config = mcp_gateway::config::Config::default();
    assert_eq!(lookup_of(&config, false), Lookup::On);
    config.security.posture = mcp_gateway::security::SecurityPosture::Hardened;
    assert_eq!(lookup_of(&config, false), Lookup::OffByPosture);
    assert_eq!(lookup_of(&config, true), Lookup::OffByFlag);
}

// ── npx_pin: the accepted forms, table-driven ──────────────────────────────

#[test]
fn npx_pin_accepts_only_the_listed_forms() {
    let memory = "@modelcontextprotocol/server-memory";
    let accepted: &[(&str, &str, &str)] = &[
        (
            "npx -y @modelcontextprotocol/server-memory@2026.8.31",
            memory,
            "2026.8.31",
        ),
        (
            "npx --yes @modelcontextprotocol/server-memory@1.0.0",
            memory,
            "1.0.0",
        ),
        (
            "npx @modelcontextprotocol/server-memory@1.0.0",
            memory,
            "1.0.0",
        ),
        ("npx -y -y tavily-mcp@0.2.22", "tavily-mcp", "0.2.22"),
        (
            "/usr/local/bin/npx -y tavily-mcp@0.2.22",
            "tavily-mcp",
            "0.2.22",
        ),
        ("npx.cmd -y tavily-mcp@0.2.22", "tavily-mcp", "0.2.22"),
        (
            "npx -y @playwright/mcp@0.0.83 --headless --isolated",
            "@playwright/mcp",
            "0.0.83",
        ),
        (
            "npx -y tavily-mcp@1.2.3-beta.1",
            "tavily-mcp",
            "1.2.3-beta.1",
        ),
    ];
    for (command, name, version) in accepted {
        assert_eq!(npx_pin(command), Some(pin(name, version)), "{command}");
    }
    // A path form the host's own splitter keeps: unquoted backslashes only
    // survive the Windows splitter, so each host gets its own row.
    #[cfg(windows)]
    let path_form = r"C:\node\npx.cmd -y tavily-mcp@0.2.22";
    #[cfg(not(windows))]
    let path_form = "'/opt/node bin/npx' -y tavily-mcp@0.2.22";
    assert_eq!(
        npx_pin(path_form),
        Some(pin("tavily-mcp", "0.2.22")),
        "{path_form}"
    );
    let refused: &[&str] = &[
        "npx -y tavily-mcp",                     // no version
        "npx -y tavily-mcp@latest",              // a tag
        "npx -y tavily-mcp@^1.2.3",              // a range
        "npx -y tavily-mcp@1.2",                 // not exact
        "npx -y tavily-mcp@1.2.3+build",         // build metadata
        "npx -p tavily-mcp@1.2.3 tavily",        // -p
        "npx --package tavily-mcp@1.2.3 tavily", // --package
        "npx --registry https://evil.example tavily-mcp@1.2.3",
        "npx --call 'x' tavily-mcp@1.2.3",
        "npx -c 'x' tavily-mcp@1.2.3",
        "npm exec tavily-mcp@1.2.3",
        "pnpm dlx tavily-mcp@1.2.3",
        "node npx tavily-mcp@1.2.3",
        "mynpx -y tavily-mcp@1.2.3",
        "",
    ];
    for command in refused {
        assert_eq!(npx_pin(command), None, "{command}");
    }
    let long = format!("npx -y tavily-mcp@1.2.3-{}", "a".repeat(64));
    assert_eq!(npx_pin(&long), None, "a version over 64 characters");
}

// ── allowlist: derived from the registry, pinned ───────────────────────────

#[test]
fn the_allowlist_is_exactly_the_registry_npx_packages() {
    let expected: BTreeSet<String> = [
        "tavily-mcp",
        "@brave/brave-search-mcp-server",
        "exa-mcp-server",
        "@perplexity-ai/mcp-server",
        "@modelcontextprotocol/server-filesystem",
        "@benborla29/mcp-server-mysql",
        "@modelcontextprotocol/server-memory",
        "slack-mcp-server",
        "@modelcontextprotocol/server-sequential-thinking",
        "@playwright/mcp",
        "airtable-mcp-server",
        "@pinecone-database/mcp",
        "chrome-devtools-mcp",
        "mongodb-mcp-server",
        "@supabase/mcp-server-supabase",
        "@hubspot/mcp-server",
    ]
    .into_iter()
    .map(String::from)
    .collect();
    assert_eq!(allowlist(), expected);
    assert_eq!(current_version(MEMORY_PACKAGE).as_deref(), Some("2.0.0"));
    assert_eq!(current_version("@company/internal-tool"), None);
}

// ── package_url: the production URL, pinned with no network ───────────────

#[test]
fn the_production_url_is_npm_with_an_encoded_scope() {
    let base = Url::parse(REGISTRY_BASE).expect("the registry base parses");
    assert_eq!(
        package_url(&base, MEMORY_PACKAGE).as_str(),
        "https://registry.npmjs.org/@modelcontextprotocol%2Fserver-memory"
    );
    assert_eq!(
        package_url(&base, "tavily-mcp").as_str(),
        "https://registry.npmjs.org/tavily-mcp"
    );
    let production = ClientCfg::production();
    assert_eq!(production.base.as_str(), "https://registry.npmjs.org/");
    // The bundled roots, every one, and nothing else.
    let mut bundled = rustls::RootCertStore::empty();
    bundled.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    assert!(!bundled.is_empty());
    assert_eq!(production.roots.roots, bundled.roots);
}

#[test]
fn the_snapshot_reads_only_the_proxy_variables_through_its_lookup() {
    let read = std::cell::RefCell::new(Vec::new());
    let env = ProxyEnv::from_lookup(|name| {
        read.borrow_mut().push(name.to_string());
        match name {
            "HTTPS_PROXY" => Some("http://p.example:3128".into()),
            "REQUEST_METHOD" => Some("GET".into()),
            _ => None,
        }
    });
    let mut names = read.into_inner();
    names.sort();
    names.dedup();
    assert_eq!(
        names,
        [
            "ALL_PROXY",
            "HTTPS_PROXY",
            "HTTP_PROXY",
            "NO_PROXY",
            "all_proxy",
            "http_proxy",
            "https_proxy",
            "no_proxy"
        ]
    );
    assert_eq!(route(&env), via("http://p.example:3128"));
}

#[cfg(unix)]
fn not_utf8() -> std::ffi::OsString {
    use std::os::unix::ffi::OsStringExt;
    std::ffi::OsString::from_vec(vec![b'h', 0xff, b'x'])
}

#[cfg(windows)]
fn not_utf8() -> std::ffi::OsString {
    use std::os::windows::ffi::OsStringExt;
    std::ffi::OsString::from_wide(&[0x68, 0xD800, 0x78])
}

#[test]
fn an_unreadable_proxy_variable_skips_the_lookup() {
    for bad in ["HTTPS_PROXY", "all_proxy", "NO_PROXY", "http_proxy"] {
        let env = ProxyEnv::from_lookup(|name| {
            if name == bad {
                Some(not_utf8())
            } else if name == "HTTPS_PROXY" {
                Some("http://p.example:3128".into())
            } else {
                None
            }
        });
        assert_eq!(route(&env), Route::Skip, "{bad} unreadable");
        let env = ProxyEnv::from_lookup(|name| {
            if name == "HTTPS_PROXY" && bad != "HTTPS_PROXY" {
                Some("http://p.example:3128".into())
            } else {
                None
            }
        });
        assert_ne!(route(&env), Route::Skip, "{bad} unset is not Skip");
    }
}

// ── route: the proxy is chosen here, fail-closed (r4, r4.1) ────────────────

fn route_of(pairs: &[(&str, &str)]) -> Route {
    route(&ProxyEnv::from_pairs(pairs))
}

fn via(url: &str) -> Route {
    Route::Proxy {
        url: Url::parse(url).expect("a test proxy URL parses"),
        no_proxy: None,
    }
}

#[test]
fn no_proxy_variables_mean_direct() {
    assert_eq!(route_of(&[]), Route::Direct);
    // HTTP_PROXY is for http:// targets; the registry is https.
    assert_eq!(
        route_of(&[("HTTP_PROXY", "http://p.example:3128")]),
        Route::Direct
    );
    // An empty value is unset.
    assert_eq!(route_of(&[("HTTPS_PROXY", "")]), Route::Direct);
    // Nothing outside the proxy variables is read: REQUEST_METHOD (hyper-util's
    // CGI guard) changes nothing here.
    assert_eq!(route_of(&[("REQUEST_METHOD", "GET")]), Route::Direct);
}

#[test]
fn https_proxy_then_all_proxy_lowercase_first() {
    assert_eq!(
        route_of(&[("HTTPS_PROXY", "http://p.example:3128")]),
        via("http://p.example:3128")
    );
    assert_eq!(
        route_of(&[("https_proxy", "https://p.example:443")]),
        via("https://p.example:443")
    );
    assert_eq!(
        route_of(&[("ALL_PROXY", "http://a.example:3128")]),
        via("http://a.example:3128")
    );
    assert_eq!(
        route_of(&[
            ("ALL_PROXY", "http://a.example:1"),
            ("HTTPS_PROXY", "http://h.example:2")
        ]),
        via("http://h.example:2"),
        "HTTPS_PROXY before ALL_PROXY"
    );
    assert_eq!(
        route_of(&[
            ("HTTPS_PROXY", "http://upper.example:1"),
            ("https_proxy", "http://lower.example:2")
        ]),
        via("http://lower.example:2"),
        "lowercase before uppercase"
    );
    // A valid proxy is used even with REQUEST_METHOD set (gpt r3).
    assert_eq!(
        route_of(&[
            ("REQUEST_METHOD", "GET"),
            ("HTTPS_PROXY", "http://p.example:3128")
        ]),
        via("http://p.example:3128")
    );
}

#[test]
fn a_proxy_this_check_will_not_use_skips_never_direct() {
    let skipped: &[&[(&str, &str)]] = &[
        &[("ALL_PROXY", "socks5://s.example:1080")],
        &[("HTTPS_PROXY", "socks5h://s.example:1080")],
        &[("HTTPS_PROXY", "http://user:secret@p.example:3128")],
        &[("HTTPS_PROXY", "http://user@p.example:3128")],
        &[("HTTPS_PROXY", "not a url")],
        &[("HTTPS_PROXY", "http://")],
        // url::Url accepts it, http::Uri does not: hyper-util would drop it (r4.1).
        &[("HTTPS_PROXY", "http://proxy{typo}:8080")],
        // Either case invalid is enough, even when the other is valid.
        &[
            ("https_proxy", "http://lower.example:2"),
            ("HTTPS_PROXY", "socks5://u.example:1"),
        ],
        &[
            ("https_proxy", "socks5://l.example:1"),
            ("HTTPS_PROXY", "http://upper.example:2"),
        ],
        // An unusable HTTPS_PROXY is not rescued by a valid ALL_PROXY.
        &[
            ("HTTPS_PROXY", "socks5://s.example:1"),
            ("ALL_PROXY", "http://a.example:2"),
        ],
    ];
    for pairs in skipped {
        assert_eq!(route_of(pairs), Route::Skip, "{pairs:?}");
    }
}

#[test]
fn no_proxy_travels_with_the_proxy() {
    assert_eq!(
        route_of(&[
            ("HTTPS_PROXY", "http://p.example:3128"),
            ("NO_PROXY", "registry.npmjs.org")
        ]),
        Route::Proxy {
            url: Url::parse("http://p.example:3128").expect("parses"),
            no_proxy: Some("registry.npmjs.org".to_string()),
        }
    );
    assert_eq!(
        route_of(&[
            ("HTTPS_PROXY", "http://p.example:3128"),
            ("no_proxy", "a.example"),
            ("NO_PROXY", "b.example")
        ]),
        Route::Proxy {
            url: Url::parse("http://p.example:3128").expect("parses"),
            no_proxy: Some("a.example".to_string()),
        },
        "lowercase before uppercase"
    );
}

#[test]
fn a_skip_route_builds_no_client() {
    let cfg = ClientCfg {
        base: Url::parse(REGISTRY_BASE).expect("parses"),
        roots: rustls::RootCertStore::empty(),
        proxy: ProxyEnv::from_pairs(&[("HTTPS_PROXY", "socks5://s.example:1080")]),
        bounds_override: None,
    };
    assert!(client(&cfg).is_none());
}

// ── deprecation: reading the abbreviated document ──────────────────────────

/// The shape of npm's abbreviated document, trimmed to what is read.
fn doc(versions: &[(&str, Option<&str>)]) -> Vec<u8> {
    let versions: serde_json::Map<String, serde_json::Value> = versions
        .iter()
        .map(|(v, deprecated)| {
            let mut entry = serde_json::json!({ "name": MEMORY_PACKAGE, "version": v });
            if let Some(text) = deprecated {
                entry["deprecated"] = serde_json::Value::String((*text).to_string());
            }
            ((*v).to_string(), entry)
        })
        .collect();
    serde_json::to_vec(&serde_json::json!({ "name": MEMORY_PACKAGE, "versions": versions }))
        .expect("the fixture serializes")
}

#[test]
fn deprecation_reads_only_a_non_empty_string_for_the_pinned_version() {
    let body = doc(&[
        (
            "2026.8.31",
            Some("Date-based versions are no longer published"),
        ),
        ("1.0.0", None),
        ("0.9.0", Some("")),
        ("0.8.0", Some("   ")),
    ]);
    assert_eq!(
        deprecation(&body, "2026.8.31").as_deref(),
        Some("Date-based versions are no longer published")
    );
    assert_eq!(deprecation(&body, "1.0.0"), None);
    assert_eq!(
        deprecation(&body, "0.9.0"),
        None,
        "an empty string is not deprecated"
    );
    assert_eq!(deprecation(&body, "0.8.0"), None, "blank after trimming");
    assert_eq!(
        deprecation(&body, "3.0.0"),
        None,
        "a version npm does not list"
    );
    assert_eq!(deprecation(b"not json", "1.0.0"), None);
    assert_eq!(
        deprecation(br#"{"versions":{"1.0.0":{"deprecated":true}}}"#, "1.0.0"),
        None
    );
    assert_eq!(deprecation(br#"{"versions":[]}"#, "1.0.0"), None);
}

// ── npm_text: third-party text made safe for a terminal ────────────────────

#[test]
fn npm_text_strips_escapes_controls_and_format_characters() {
    assert_eq!(npm_text("plain text"), "plain text");
    assert_eq!(npm_text("\u{1b}[31mred\u{1b}[0m text"), "red text");
    assert_eq!(
        npm_text("\u{1b}]8;;https://evil.example\u{7}link\u{1b}]8;;\u{7}"),
        "link"
    );
    assert_eq!(npm_text("a\u{0}b\u{7}c\u{8}d"), "abcd");
    assert_eq!(
        npm_text("line one\nline two\r\n\tthree"),
        "line one line two three"
    );
    // Bidi override and other Unicode format characters (Cf).
    assert_eq!(npm_text("safe\u{202e}txt.exe"), "safetxt.exe");
    assert_eq!(npm_text("zero\u{200b}width\u{feff}"), "zerowidth");
    assert_eq!(npm_text("  padded  "), "padded");
}

#[test]
fn npm_text_cuts_on_a_char_boundary() {
    let long = "é".repeat(MESSAGE_CAP + 50);
    let cut = npm_text(&long);
    assert_eq!(cut.chars().count(), MESSAGE_CAP);
    assert!(cut.chars().all(|c| c == 'é'));
}

// ── hint: edit the pin; for server-memory keep the graph first ─────────────

#[test]
fn the_memory_hint_copies_the_graph_before_the_pin_changes() {
    let old = pin(MEMORY_PACKAGE, "2026.8.31");
    let backend = stdio("npx -y @modelcontextprotocol/server-memory@2026.8.31", &[]);
    let text = hint("memory", &old, &backend);
    assert!(text.contains("MEMORY_FILE_PATH"), "{text}");
    assert!(text.contains("memory.jsonl"), "{text}");
    assert!(text.contains("pkg-cache"), "{text}");
    assert!(text.to_lowercase().contains("copy"), "{text}");
    assert!(
        text.contains("2.0.0"),
        "names the registry's current pin: {text}"
    );
    let copy_at = text.to_lowercase().find("copy").expect("checked above");
    let pin_at = text.find("2.0.0").expect("checked above");
    assert!(copy_at < pin_at, "copy first, then change the pin: {text}");
}

#[test]
fn an_absolute_memory_file_path_gets_the_plain_hint() {
    let old = pin(MEMORY_PACKAGE, "2026.8.31");
    let absolute = if cfg!(windows) {
        r"C:\data\memory.jsonl"
    } else {
        "/data/memory.jsonl"
    };
    let backend = stdio(
        "npx -y @modelcontextprotocol/server-memory@2026.8.31",
        &[("MEMORY_FILE_PATH", absolute)],
    );
    let text = hint("memory", &old, &backend);
    assert!(!text.contains("pkg-cache"), "{text}");
    assert!(text.contains("backends.memory.command"), "{text}");
    assert!(
        text.contains("@modelcontextprotocol/server-memory@2.0.0"),
        "{text}"
    );

    // A relative path does not keep the graph across versions.
    let relative = stdio(
        "npx -y @modelcontextprotocol/server-memory@2026.8.31",
        &[("MEMORY_FILE_PATH", "memory.jsonl")],
    );
    assert!(hint("memory", &old, &relative).contains("pkg-cache"));
}

#[test]
fn other_packages_get_the_edit_the_pin_hint() {
    let old = pin("@modelcontextprotocol/server-filesystem", "2026.8.31");
    let backend = stdio(
        "npx -y @modelcontextprotocol/server-filesystem@2026.8.31 /tmp",
        &[],
    );
    let text = hint("files", &old, &backend);
    assert!(text.contains("backends.files.command"), "{text}");
    assert!(
        text.contains("@modelcontextprotocol/server-filesystem@2.0.0"),
        "{text}"
    );
    assert!(!text.contains("MEMORY_FILE_PATH"), "{text}");
    assert!(
        !text.contains("mcp-gateway add"),
        "add refuses an existing name: {text}"
    );
}

#[test]
fn the_memory_hint_names_the_cache_the_backend_uses() {
    let command = "npx -y @modelcontextprotocol/server-memory@2026.8.31";
    let old = pin(MEMORY_PACKAGE, "2026.8.31");
    let backend = stdio(command, &[]);
    let dir =
        mcp_gateway::transport::isolated_package_manager_env("memory", command, HashMap::new())
            .get("npm_config_cache")
            .expect("npx is assigned an npm cache")
            .clone();
    let text = hint("memory", &old, &backend);
    let under = std::path::Path::new(&dir)
        .join("_npx")
        .display()
        .to_string();
    assert!(text.contains(&under), "{text}");
    // The old text named "pkg-cache/memory directory"; the real directory is
    // pkg-cache/memory-<hash>, so the space after the name tells them apart.
    assert!(!text.contains("pkg-cache/memory directory"), "{text}");
}

#[test]
fn an_operator_npm_cache_is_named_in_the_memory_hint() {
    let command = "npx -y @modelcontextprotocol/server-memory@2026.8.31";
    let cache = if cfg!(windows) {
        r"C:\srv\npm"
    } else {
        "/srv/npm"
    };
    let old = pin(MEMORY_PACKAGE, "2026.8.31");
    let backend = stdio(command, &[("npm_config_cache", cache)]);
    let text = hint("memory", &old, &backend);
    let under = std::path::Path::new(cache)
        .join("_npx")
        .display()
        .to_string();
    assert!(text.contains(&under), "{text}");
}

#[path = "npm_pin_wire_tests.rs"]
mod wire;

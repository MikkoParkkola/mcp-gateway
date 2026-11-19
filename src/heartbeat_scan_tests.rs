// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Heartbeat source scans (test plan D10-D12, DOC1): where `start` is
//! called and with what, that every gateway test helper and every launch of
//! the gateway image in our scripts and workflows opts out, and that the
//! privacy page states the facts the code fixes.

/// Every `.rs` file under `dir`, as (path relative to the crate, text).
fn rust_files(dir: &std::path::Path) -> Vec<(String, String)> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut out = Vec::new();
    let mut todo = vec![dir.to_path_buf()];
    while let Some(d) = todo.pop() {
        for entry in std::fs::read_dir(&d).expect("readable dir").flatten() {
            let p = entry.path();
            if p.is_dir() {
                todo.push(p);
            } else if p.extension().is_some_and(|e| e == "rs") {
                let rel = p
                    .strip_prefix(root)
                    .expect("under the crate")
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push((rel, std::fs::read_to_string(&p).expect("readable")));
            }
        }
    }
    out.sort();
    out
}

/// The production files that call `heartbeat::start(`.
fn start_callers(files: &[(String, String)]) -> Vec<String> {
    files
        .iter()
        .filter(|(_, text)| {
            crate::test_source_text::production_text(text).contains("heartbeat::start(")
        })
        .map(|(path, _)| path.clone())
        .collect()
}

/// D10. `heartbeat::start` is called from exactly the two server starts and
/// nowhere else (no CLI command); a planted CLI caller fails by name.
#[test]
fn start_is_called_only_from_the_two_servers() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let files = rust_files(&root.join("src"));
    assert_eq!(
        start_callers(&files),
        [
            "src/gateway/server/run.rs",
            "src/gateway/server/stdio_loop.rs"
        ],
    );
    // Each call passes the server's resolved posture (tp-r1: call wiring, not a
    // mention): the argument text names `security.posture`.
    for (path, text) in files
        .iter()
        .filter(|(p, _)| p.ends_with("run.rs") || p.ends_with("stdio_loop.rs"))
    {
        let production = crate::test_source_text::production_text(text);
        let at = production.find("heartbeat::start(").expect("the call");
        let args = &production[at..at + production[at..].find(')').expect("the call's end")];
        assert!(
            args.contains("security.posture"),
            "{path} does not pass the resolved posture: {args}"
        );
    }
    let mut planted = files;
    planted.push((
        "src/commands/planted.rs".to_owned(),
        "fn planted() { crate::heartbeat::start(p, d, s); }".to_owned(),
    ));
    assert!(start_callers(&planted).contains(&"src/commands/planted.rs".to_owned()));
}

/// The functions in `text` whose body builds a gateway command but never
/// sets `DO_NOT_TRACK` (a lexical split at each `fn `: a nested fn ends the
/// outer chunk early, which can only flag more, never less).
fn helpers_without_dnt(text: &str) -> Vec<String> {
    // Comments are not settings (tp-r2): drop each line's `//` tail first.
    let code: String = text
        .lines()
        .map(|l| l.split("//").next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n");
    let starts: Vec<usize> = code
        .match_indices("fn ")
        .map(|(i, _)| i)
        .filter(|&i| i == 0 || code[..i].ends_with(char::is_whitespace))
        .collect();
    let mut out = Vec::new();
    for (k, &s) in starts.iter().enumerate() {
        let chunk = &code[s..starts.get(k + 1).copied().unwrap_or(code.len())];
        let name: String = chunk[3..]
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        let Some(built) = chunk.find("CARGO_BIN_EXE_mcp-gateway") else {
            continue;
        };
        // The setting must come after the command is built, on its chain.
        let set = chunk[built..].contains(r#".env("DO_NOT_TRACK", "1")"#);
        if !set {
            out.push(name);
        }
    }
    out
}

/// D11. Each test helper that builds a gateway command sets
/// `DO_NOT_TRACK=1` on it; a planted helper without it fails by name.
#[test]
fn each_gateway_helper_sets_dnt() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut missing = Vec::new();
    for (path, text) in rust_files(&root.join("tests/common")) {
        for name in helpers_without_dnt(&text) {
            missing.push(format!("{path}::{name}"));
        }
    }
    assert!(
        missing.is_empty(),
        "gateway helpers without DO_NOT_TRACK: {missing:?}"
    );
    let planted = r#"fn planted() -> Command { Command::new(env!("CARGO_BIN_EXE_mcp-gateway")) }"#;
    assert_eq!(helpers_without_dnt(planted), ["planted"]);
    // A mention is not a setting (tp-r1): a comment or a removal still fails.
    let mentioned = r#"fn mentioned() -> Command { // DO_NOT_TRACK
        let mut c = Command::new(env!("CARGO_BIN_EXE_mcp-gateway")); c.env_remove("DO_NOT_TRACK"); c }"#;
    assert_eq!(helpers_without_dnt(mentioned), ["mentioned"]);
    let unrelated = r#"fn unrelated() -> Command {
        let mut other = Command::new("true"); other.env("DO_NOT_TRACK", "1");
        Command::new(env!("CARGO_BIN_EXE_mcp-gateway")) }"#;
    assert_eq!(helpers_without_dnt(unrelated), ["unrelated"]);
}

/// The launch commands that start a container or pod.
const LAUNCHERS: [&str; 8] = [
    "docker run",
    "podman run",
    "docker compose up",
    "docker compose run",
    "kubectl run",
    "kubectl apply",
    "helm install",
    "helm upgrade",
];

/// Whether a launch line passes `DO_NOT_TRACK=1` through an env flag (`-e`,
/// `--env`, or a Helm `--set`/`--set-string` value), not just mentions it.
fn launch_sets_dnt(launch: &str) -> bool {
    let words: Vec<&str> = launch.split_whitespace().collect();
    let helm_value = |v: &str| v.ends_with(".DO_NOT_TRACK=1") || v == "DO_NOT_TRACK=1";
    words.windows(2).any(|w| match w[0] {
        "-e" | "--env" => w[1] == "DO_NOT_TRACK=1",
        "--set" | "--set-string" => helm_value(w[1]),
        _ => false,
    }) || words.iter().any(|w| {
        *w == "--env=DO_NOT_TRACK=1"
            || ["--set=", "--set-string="]
                .iter()
                .any(|f| w.strip_prefix(f).is_some_and(|v| helm_value(v)))
    })
}

/// The launches in `text` (continued lines joined) that start the gateway
/// image or chart without `DO_NOT_TRACK=1` on that launch.
fn launches_without_dnt(text: &str) -> Vec<String> {
    let joined = text.replace("\\\r\n", " ").replace("\\\n", " ");
    joined
        .lines()
        .filter(|l| LAUNCHERS.iter().any(|c| l.contains(c)))
        .filter(|l| l.contains("mcp-gateway"))
        .filter(|l| !launch_sets_dnt(l))
        .map(|l| l.trim().to_owned())
        .collect()
}

/// A compose file that runs the gateway image without `DO_NOT_TRACK` set to
/// `1` in an `environment:` entry.
fn compose_without_dnt(text: &str) -> bool {
    // Per service (tp-r2): a block starts at a two-space key under `services:`.
    let mut blocks: Vec<Vec<&str>> = Vec::new();
    let mut in_services = false;
    for line in text.lines() {
        if line.starts_with("services:") {
            in_services = true;
            continue;
        }
        if in_services && !line.starts_with(' ') && !line.trim().is_empty() {
            in_services = false;
        }
        if !in_services {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        if indent == 2 && line.trim_end().ends_with(':') {
            blocks.push(Vec::new());
        } else if let Some(block) = blocks.last_mut() {
            block.push(line.trim());
        }
    }
    blocks.iter().any(|block| {
        let gateway = block
            .iter()
            .any(|l| l.starts_with("image:") && l.contains("mcp-gateway"));
        let set = block.iter().any(|l| {
            let l = l.trim_start_matches("- ");
            l == "DO_NOT_TRACK=1" || l == "DO_NOT_TRACK: \"1\"" || l == "DO_NOT_TRACK: '1'"
        });
        gateway && !set
    })
}

/// Our own launch surfaces: shell scripts and Makefiles under `scripts/` and
/// `tests/`, the workflows, the root Makefile, and compose files under
/// `scripts/` and `tests/`. `deploy/` is the product's own deployment
/// material, used by users, and must not set the variable, so it is not read.
fn launch_sources() -> Vec<(String, String)> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut out = Vec::new();
    if let Ok(text) = std::fs::read_to_string(root.join("Makefile")) {
        out.push(("Makefile".to_owned(), text));
    }
    let mut todo = vec![
        root.join("scripts"),
        root.join("tests"),
        root.join(".github").join("workflows"),
    ];
    while let Some(d) = todo.pop() {
        for entry in std::fs::read_dir(&d).into_iter().flatten().flatten() {
            let p = entry.path();
            let name = p
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            if p.is_dir() {
                todo.push(p);
            } else if name == "Makefile"
                || p.extension()
                    .is_some_and(|e| e == "sh" || e == "yml" || e == "yaml")
            {
                if let Ok(text) = std::fs::read_to_string(&p) {
                    out.push((
                        p.strip_prefix(root)
                            .expect("under the crate")
                            .to_string_lossy()
                            .into_owned(),
                        text,
                    ));
                }
            }
        }
    }
    out
}

/// D12. Every launch of the gateway image or chart in our scripts and
/// workflows passes `DO_NOT_TRACK=1` on that launch itself; one planted
/// launch per form, without it, fails.
#[test]
fn every_image_launch_sets_dnt() {
    let mut missing = Vec::new();
    for (path, text) in launch_sources() {
        for launch in launches_without_dnt(&text) {
            missing.push(format!("{path}: {launch}"));
        }
        let name = std::path::Path::new(&path)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if (name.starts_with("docker-compose") || name.starts_with("compose"))
            && compose_without_dnt(&text)
        {
            missing.push(format!(
                "{path}: a compose service runs the gateway image without DO_NOT_TRACK=1"
            ));
        }
    }
    assert!(
        missing.is_empty(),
        "launches without DO_NOT_TRACK=1: {missing:?}"
    );
    for launcher in LAUNCHERS {
        let planted = format!("{launcher} \\\n  ghcr.io/mikkoparkkola/mcp-gateway:test\n");
        assert_eq!(
            launches_without_dnt(&planted).len(),
            1,
            "planted {launcher} was not caught"
        );
        let kept =
            format!("{launcher} -e DO_NOT_TRACK=1 \\\n  ghcr.io/mikkoparkkola/mcp-gateway:test\n");
        assert!(
            launches_without_dnt(&kept).is_empty(),
            "{launcher} with the variable was refused"
        );
        let mentioned = format!(
            "{launcher} ghcr.io/mikkoparkkola/mcp-gateway:test # DO_NOT_TRACK=1 set elsewhere\n"
        );
        assert_eq!(
            launches_without_dnt(&mentioned).len(),
            1,
            "a mention passed for {launcher}"
        );
    }
    let compose = "services:\n  gw:\n    image: ghcr.io/mikkoparkkola/mcp-gateway:test\n";
    assert!(
        compose_without_dnt(compose),
        "a planted compose service was not caught"
    );
    let compose_kept = format!("{compose}    environment:\n      - DO_NOT_TRACK=1\n");
    assert!(
        !compose_without_dnt(&compose_kept),
        "a compose service with the variable was refused"
    );
    let two = "services:\n  other:\n    image: busybox\n    environment:\n      - DO_NOT_TRACK=1\n  gw:\n    image: ghcr.io/mikkoparkkola/mcp-gateway:test\n";
    assert!(
        compose_without_dnt(two),
        "another service's setting covered the gateway service"
    );
}

/// DOC1. docs/PRIVACY.md states the facts the code fixes, written out here as
/// literals: the five field names, the receiver URL, the stored place and
/// time, the three-month retention, every opt-out and proxy name; and the old
/// "sends nothing" promise is gone.
#[test]
fn privacy_text_states_the_facts() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(root.join("docs/PRIVACY.md")).expect("PRIVACY.md");
    for fact in [
        "`project`",
        "`event`",
        "`install_id`",
        "mcp-gateway version",
        "operating system and processor architecture",
        "the time the heartbeat arrived",
        "https://telemetry.revaluator.ai/v1/heartbeat",
        "city name and a country code",
        "three months",
        "DO_NOT_TRACK=1",
        "NO_TELEMETRY=1",
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "ALL_PROXY",
        "security.posture: hardened",
    ] {
        assert!(text.contains(fact), "PRIVACY.md does not state {fact:?}");
    }
    assert!(
        !text.contains("sends nothing to its author"),
        "PRIVACY.md still promises that nothing is sent"
    );
}

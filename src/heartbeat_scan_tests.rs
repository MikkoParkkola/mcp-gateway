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
            // Code only: a string or comment naming the call is not a call (the
            // scan's own matcher holds the text).
            let code = crate::test_source_text::production_text(text);
            crate::test_source_text::sanitize(&code).contains("heartbeat::start(")
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
    // Controls first, so a red run proves them: a planted CLI caller is found,
    // and a string or comment naming the call is not a call.
    let mut planted = files.clone();
    planted.push((
        "src/commands/planted.rs".to_owned(),
        "fn planted() { crate::heartbeat::start(p, d, s); }".to_owned(),
    ));
    planted.push((
        "src/commands/named.rs".to_owned(),
        "// heartbeat::start(\nfn named() { let _ = \"heartbeat::start(\"; }".to_owned(),
    ));
    let found = start_callers(&planted);
    assert!(
        found.contains(&"src/commands/planted.rs".to_owned()),
        "{found:?}"
    );
    assert!(
        !found.contains(&"src/commands/named.rs".to_owned()),
        "{found:?}"
    );
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

/// Scripts whose gateway image arrives as their first argument (docker.yml
/// passes the image it built), and the variable that holds it there.
const ARG_IMAGE: [(&str, &str); 2] = [
    ("scripts/ci/smoke-image.sh", "IMAGE"),
    ("scripts/ci/smoke-full-image.sh", "IMAGE"),
];

/// Whether `s` names the gateway image (`mcp-gateway:` or `mcp-gateway@`) or
/// its chart; a container or secret name such as `mcp-gateway-auth` does not.
fn names_image(s: &str) -> bool {
    s.contains("mcp-gateway:")
        || s.contains("mcp-gateway@")
        || s.contains("deploy/helm/mcp-gateway")
}

/// The shell variables in `text` (of the file at `path`) that hold the
/// gateway image or chart: assigned a value naming it, or the file's
/// argument image ([`ARG_IMAGE`]).
fn image_vars(path: &str, text: &str) -> Vec<String> {
    let mut vars: Vec<String> = ARG_IMAGE
        .iter()
        .filter(|(file, _)| *file == path)
        .map(|(_, var)| (*var).to_owned())
        .collect();
    for line in text.lines() {
        let t = line.trim_start();
        let t = ["export ", "local ", "readonly "]
            .iter()
            .find_map(|k| t.strip_prefix(k))
            .unwrap_or(t);
        if let Some((name, value)) = t.split_once('=')
            && !name.is_empty()
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            && names_image(value)
        {
            vars.push(name.to_owned());
        }
    }
    vars
}

/// Whether `line` expands the shell variable `var` (`$var` or `${var}`).
fn expands(line: &str, var: &str) -> bool {
    line.contains(&format!("${{{var}}}"))
        || line.match_indices(&format!("${var}")).any(|(i, m)| {
            !line[i + m.len()..].starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_')
        })
}

/// `line` with a launcher program called through its variable (`"$HELM"`,
/// `${KUBECTL}`) written as the program itself, so [`LAUNCHERS`] match it.
fn programs_named(line: &str) -> String {
    let mut out = line.to_owned();
    for tool in ["docker", "podman", "kubectl", "helm"] {
        let var = tool.to_ascii_uppercase();
        for form in [
            format!("\"${{{var}}}\""),
            format!("\"${var}\""),
            format!("${{{var}}}"),
        ] {
            out = out.replace(&form, tool);
        }
        // A bare `$HELM`, not `$HELM_HOME`.
        let bare = format!("${var}");
        loop {
            // Found in its own statement, so the search's borrow ends before the edit.
            let Some(i) = out.match_indices(&bare).map(|(i, _)| i).find(|&i| {
                !out[i + bare.len()..].starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_')
            }) else {
                break;
            };
            out.replace_range(i..i + bare.len(), tool);
        }
    }
    out
}

/// The launches in `text`, the file at `path` (continued lines joined,
/// comments dropped), that start the gateway image or chart.
fn gateway_launches(path: &str, text: &str) -> Vec<String> {
    let vars = image_vars(path, text);
    let joined = text.replace("\\\r\n", " ").replace("\\\n", " ");
    joined
        .lines()
        // A `#` at the start or after whitespace starts a shell or YAML comment (tp-r3).
        .filter(|l| !l.trim_start().starts_with('#'))
        .map(|l| l.find(" #").map_or(l, |i| &l[..i]))
        .map(programs_named)
        .filter(|l| LAUNCHERS.iter().any(|c| l.contains(c)))
        .filter(|l| !l.contains("docker compose up") && !l.contains("docker compose run"))
        .filter(|l| names_image(l) || vars.iter().any(|v| expands(l, v)))
        .map(|l| l.trim().to_owned())
        .collect()
}

/// [`gateway_launches`] without `DO_NOT_TRACK=1` on the launch itself.
fn launches_without_dnt(path: &str, text: &str) -> Vec<String> {
    gateway_launches(path, text)
        .into_iter()
        .filter(|l| !launch_sets_dnt(l))
        .collect()
}

/// A compose file that runs the gateway image without `DO_NOT_TRACK` set to
/// `1` in an `environment:` entry.
fn compose_without_dnt(text: &str) -> bool {
    // Per service, at whatever indent the file uses; only `environment:`
    // entries count (not labels); trailing comments dropped (tp-r3).
    let mut services: Vec<(bool, bool)> = Vec::new();
    let (mut in_services, mut service_indent, mut in_env) = (false, None, false);
    for raw in text.lines() {
        let line = raw.find(" #").map_or(raw, |i| &raw[..i]).trim_end();
        if line.trim().is_empty() {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        let t = line.trim();
        if indent == 0 {
            in_services = t == "services:";
            continue;
        }
        if !in_services {
            continue;
        }
        let si = *service_indent.get_or_insert(indent);
        if indent == si {
            services.push((false, false));
            in_env = false;
            continue;
        }
        let Some(service) = services.last_mut() else {
            continue;
        };
        if t.starts_with("image:") && t.contains("mcp-gateway") {
            service.0 = true;
        }
        if t.starts_with("environment:") {
            in_env = true;
            if t.contains("DO_NOT_TRACK=1")
                || t.contains("DO_NOT_TRACK: 1")
                || t.contains("DO_NOT_TRACK: \"1\"")
            {
                service.1 = true;
            }
            continue;
        }
        if in_env && indent > si {
            let e = t.trim_start_matches("- ");
            if [
                "DO_NOT_TRACK=1",
                "DO_NOT_TRACK: 1",
                "DO_NOT_TRACK: \"1\"",
                "DO_NOT_TRACK: '1'",
            ]
            .contains(&e)
            {
                service.1 = true;
            }
        }
        if !t.starts_with('-') && t.ends_with(':') && !t.starts_with("environment:") {
            in_env = false;
        }
    }
    services.iter().any(|(gateway, set)| *gateway && !set)
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
                    // Forward slashes on every OS, so the file tables
                    // (ARG_IMAGE, KNOWN_LAUNCHES) match on Windows too.
                    out.push((
                        p.strip_prefix(root)
                            .expect("under the crate")
                            .to_string_lossy()
                            .replace('\\', "/"),
                        text,
                    ));
                }
            }
        }
    }
    out
}

/// Every gateway launch in our scripts today, by file: the D12 floor.
const KNOWN_LAUNCHES: [(&str, usize); 5] = [
    ("scripts/ci/smoke-full-image.sh", 9),
    ("scripts/ci/smoke-image.sh", 3),
    ("scripts/dev/docker-smoke.sh", 2),
    ("scripts/dev/helm-kind-lifecycle.sh", 2),
    ("scripts/dev/helm-kind-real-image.sh", 2),
];

/// D12. Every launch of the gateway image or chart in our scripts and
/// workflows passes `DO_NOT_TRACK=1` on that launch itself; one planted
/// launch per form, without it, fails.
#[test]
fn every_image_launch_sets_dnt() {
    // The floor (A3/A4): the finder sees each known gateway launch, by file,
    // before anything is judged; a finder blind to an image form sees fewer.
    let mut seen = std::collections::BTreeMap::new();
    for (path, text) in launch_sources() {
        let n = gateway_launches(&path, &text).len();
        if n > 0 {
            seen.insert(path, n);
        }
    }
    let known: std::collections::BTreeMap<String, usize> = KNOWN_LAUNCHES
        .iter()
        .map(|(f, n)| ((*f).to_owned(), *n))
        .collect();
    assert_eq!(seen, known, "the gateway launches found, by file");
    let mut missing = Vec::new();
    for (path, text) in launch_sources() {
        for launch in launches_without_dnt(&path, &text) {
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
    for launcher in LAUNCHERS {
        // Compose launches take service names; their environment is checked
        // per service in the compose file (compose_without_dnt below).
        if launcher.starts_with("docker compose") {
            continue;
        }
        let commented =
            format!("{launcher} ghcr.io/mikkoparkkola/mcp-gateway:test # -e DO_NOT_TRACK=1\n");
        assert_eq!(
            launches_without_dnt("planted.sh", &commented).len(),
            1,
            "an opt-out in a comment passed for {launcher}"
        );
        let planted = format!("{launcher} \\\n  ghcr.io/mikkoparkkola/mcp-gateway:test\n");
        assert_eq!(
            launches_without_dnt("planted.sh", &planted).len(),
            1,
            "planted {launcher} was not caught"
        );
        let kept =
            format!("{launcher} -e DO_NOT_TRACK=1 \\\n  ghcr.io/mikkoparkkola/mcp-gateway:test\n");
        assert!(
            launches_without_dnt("planted.sh", &kept).is_empty(),
            "{launcher} with the variable was refused"
        );
        let mentioned = format!(
            "{launcher} ghcr.io/mikkoparkkola/mcp-gateway:test # DO_NOT_TRACK=1 set elsewhere\n"
        );
        assert_eq!(
            launches_without_dnt("planted.sh", &mentioned).len(),
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
    // Images and programs through variables, as our scripts write them (red read).
    let via_var =
        "CHART=\"$ROOT/deploy/helm/mcp-gateway\"\n\"$HELM\" upgrade --install gw \"$CHART\"\n";
    assert_eq!(
        launches_without_dnt("planted.sh", via_var).len(),
        1,
        "a chart launch through variables was not caught"
    );
    let via_arg = "IMAGE=\"${1:?image}\"\ndocker run -d --name x \"${IMAGE}\"\n";
    assert_eq!(
        launches_without_dnt("scripts/ci/smoke-image.sh", via_arg).len(),
        1,
        "an argument image was not caught"
    );
    assert!(
        launches_without_dnt("other.sh", via_arg).is_empty(),
        "an image variable outside ARG_IMAGE counted"
    );
    let named = "kubectl create secret generic mcp-gateway-auth -o yaml | kubectl apply -f -\n";
    assert!(
        gateway_launches("planted.sh", named).is_empty(),
        "a secret named mcp-gateway-* counted as a launch"
    );
    // The judgement last, so a red run proves every control above first.
    assert!(
        missing.is_empty(),
        "launches without DO_NOT_TRACK=1: {missing:?}"
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

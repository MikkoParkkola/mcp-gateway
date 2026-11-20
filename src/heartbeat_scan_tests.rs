// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Heartbeat source scans (test plan D10-D12, DOC1): where `start` is
//! called and with what, that every gateway test helper and every launch of
//! the gateway image in our scripts and workflows opts out, and that the
//! README's privacy section states the facts the code fixes. The 3.5 line's
//! form: plain text scans (no `syn` on this line), and D12 skips only in the
//! unpacked published crate, which ships `tests/` but not `scripts/` or the
//! workflows.

/// The unpacked published crate: `cargo package` writes `Cargo.toml.orig`
/// into it, and it has no `.git` (a checkout always does).
fn is_packaged_crate() -> bool {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    root.join("Cargo.toml.orig").exists() && !root.join(".git").exists()
}

/// `text` with `//` comments and the contents of string literals removed, so a
/// comment or a string naming a call is not a call. Text-level (the 3.5 line
/// has no `syn`); a test file is never scanned, see [`start_callers`].
fn code_only(text: &str) -> String {
    let mut out = String::new();
    for line in text.lines() {
        let mut in_str = false;
        let mut escaped = false;
        let mut chars = line.chars().peekable();
        while let Some(c) = chars.next() {
            if in_str {
                if escaped {
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else if c == '"' {
                    in_str = false;
                    out.push(c);
                }
            } else if c == '"' {
                in_str = true;
                out.push(c);
            } else if c == '/' && chars.peek() == Some(&'/') {
                break;
            } else {
                out.push(c);
            }
        }
        out.push('\n');
    }
    out
}

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
        // Production files only: a test file's calls are rows.
        .filter(|(path, _)| !path.ends_with("_tests.rs") && !path.ends_with("/tests.rs"))
        // Code only: a string or comment naming the call is not a call (the
        // scan's own matcher holds the text).
        .filter(|(_, text)| code_only(text).contains("heartbeat::start("))
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
    // On the 3.5 line both server starts live in one file.
    assert_eq!(start_callers(&files), ["src/gateway/server/mod.rs"]);
    // Two calls, one in `run` and one in `run_stdio_on`, each on the root
    // `heartbeat::root()` gives (never the real home in a test build).
    let server = &files
        .iter()
        .find(|(p, _)| p == "src/gateway/server/mod.rs")
        .expect("the server file")
        .1;
    let code = code_only(server);
    let calls: Vec<usize> = code
        .match_indices("heartbeat::start(")
        .map(|(i, _)| i)
        .collect();
    let run = code.find("pub async fn run(").expect("run");
    let stdio = code.find("fn run_stdio_on").expect("run_stdio_on");
    assert_eq!(calls.len(), 2, "{calls:?}");
    assert!(
        run < calls[0] && calls[0] < stdio,
        "the HTTP call is not in run"
    );
    assert!(stdio < calls[1], "the stdio call is not in run_stdio_on");
    for at in calls {
        let statement = &code[code[..at].rfind(';').unwrap_or(0)..at];
        assert!(
            statement.contains("heartbeat::root()"),
            "a start call does not take heartbeat::root(): {statement}"
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
    // A quoted word is the same word to the shell (`-e "DO_NOT_TRACK=1"`).
    let words: Vec<&str> = launch
        .split_whitespace()
        .map(|w| w.trim_matches(|c| c == '"' || c == '\''))
        .collect();
    let helm_value = |v: &str| v.ends_with(".DO_NOT_TRACK=1") || v == "DO_NOT_TRACK=1";
    // The chart's container environment is a list (`extraEnv`): its name and
    // its string value set at the same index.
    let helm_list = (0..8).any(|i| {
        let set =
            |flag: &str, value: String| words.windows(2).any(|w| w[0] == flag && w[1] == value);
        set("--set", format!("extraEnv[{i}].name=DO_NOT_TRACK"))
            && set("--set-string", format!("extraEnv[{i}].value=1"))
    });
    helm_list
        || words.windows(2).any(|w| match w[0] {
            "-e" | "--env" => w[1] == "DO_NOT_TRACK=1",
            "--set" | "--set-string" => helm_value(w[1]),
            _ => false,
        })
        || words.iter().any(|w| {
            *w == "--env=DO_NOT_TRACK=1"
                || ["--set=", "--set-string="]
                    .iter()
                    .any(|f| w.strip_prefix(f).is_some_and(helm_value))
        })
}

/// Whether `s` names the gateway image (`mcp-gateway:` or `mcp-gateway@`) or
/// its chart; a container or secret name such as `mcp-gateway-auth` does not.
fn names_image(s: &str) -> bool {
    s.contains("mcp-gateway:")
        || s.contains("mcp-gateway@")
        || s.contains("deploy/helm/mcp-gateway")
}

/// The shell variables in `text` (of the file at `path`) that hold the
/// Scripts whose gateway image arrives as their first argument (ci.yml
/// passes the image it built), and the variable that holds it there.
const ARG_IMAGE: [(&str, &str); 2] = [
    ("scripts/ci/smoke-image.sh", "IMAGE"),
    ("scripts/ci/smoke-full-image.sh", "IMAGE"),
];

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

/// Where `bare` (`$HELM`) first stands alone in `line`, not as the start of
/// a longer name (`$HELM_HOME`). Returns no borrow, so the caller can edit.
fn bare_at(line: &str, bare: &str) -> Option<usize> {
    line.match_indices(bare).map(|(i, _)| i).find(|&i| {
        !line[i + bare.len()..].starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_')
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
        while let Some(i) = bare_at(&out, &bare) {
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
    // Reached only in a checkout (D12 skips in a packaged crate).
    let makefile = "Makefile";
    if let Ok(text) = std::fs::read_to_string(root.join(makefile)) {
        out.push((makefile.to_owned(), text));
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
            } else if (name == makefile
                || p.extension()
                    .is_some_and(|e| e == "sh" || e == "yml" || e == "yaml"))
                && let Ok(text) = std::fs::read_to_string(&p)
            {
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
    out
}

/// Every gateway launch in our scripts today, by file: the D12 floor.
const KNOWN_LAUNCHES: [(&str, usize); 5] = [
    (".github/workflows/docker.yml", 1),
    (PAUSE_SCRIPT, 2),
    ("scripts/ci/smoke-image.sh", 3),
    ("scripts/ci/smoke-full-image.sh", 6),
    ("scripts/dev/docker-smoke.sh", 1),
];

/// The one launch file exempt from the opt-out: it installs the chart with the
/// image set to `registry.k8s.io/pause`, so no gateway process runs.
const PAUSE_SCRIPT: &str = "scripts/dev/helm-kind-lifecycle.sh";

/// The exemption holds only while the script runs exactly the pause image:
/// the registry and repository are those literals, set in the arguments both
/// launches pass; no other image key or values file reaches a launch; and the
/// chart's one container takes its image from those keys (deployment.yaml's
/// image line, the `mcp-gateway.image` helper).
fn pause_script_runs_only_pause(script: &str, deployment: &str, helpers: &str) -> bool {
    let launches: Vec<&str> = script
        .lines()
        .filter(|l| l.contains("\"$HELM\" upgrade"))
        .collect();
    let common = script
        .split_once("common_args=(")
        .and_then(|(_, rest)| rest.split_once("\n)"))
        .map_or("", |(block, _)| block);
    let values_file =
        |s: &str| s.contains(" -f ") || s.contains("--values") || s.contains("--set-file");
    // Each variable assigned once, as a whole line: a commented copy beside
    // a later reassignment does not count (grok A2/A3 improvement).
    let assigned_once = |name: &str, line: &str| {
        let lines: Vec<&str> = script
            .lines()
            .map(str::trim)
            .filter(|l| !l.starts_with('#') && l.contains(name))
            .collect();
        lines == [line]
    };
    assigned_once("IMG_REG=", "IMG_REG=\"registry.k8s.io\"")
        && assigned_once("IMG_REPO=", "IMG_REPO=\"pause\"")
        && common.contains("--set image.registry=\"$IMG_REG\"")
        && common.contains("--set image.repository=\"$IMG_REPO\"")
        && !values_file(common)
        && launches.len() == 2
        && launches.iter().all(|l| {
            l.contains("\"${common_args[@]}\"")
                && !values_file(l)
                && l.matches("image.").count() == 1
                && l.contains("--set image.tag=")
        })
        // The two keys in the common args plus one tag per launch.
        && script.matches("image.").count() == 4
        && deployment.matches("image:").count() == 1
        && deployment.contains("image: {{ include \"mcp-gateway.image\" . | quote }}")
        && helpers.contains("{{- $reg := .Values.image.registry -}}")
        && helpers.contains("{{- $repo := .Values.image.repository -}}")
        && helpers.contains("printf \"%s/%s@%s\" $reg $repo")
        && helpers.contains("printf \"%s/%s:%s\" $reg $repo")
}

/// D12's planted compose services, chart and image variables, the chart's
/// list form and a quoted value, each both ways.
fn assert_planted_compose_and_variable_forms() {
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
        launches_without_dnt(ARG_IMAGE[0].0, via_arg).len(),
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
    // The chart's list form and a quoted flag value (implementation): kept
    // when name and value share an index, caught otherwise.
    let chart = "helm upgrade --install gw ./deploy/helm/mcp-gateway";
    for (args, caught) in [
        (
            "--set 'extraEnv[0].name=DO_NOT_TRACK' --set-string 'extraEnv[0].value=1'",
            false,
        ),
        (
            "--set 'extraEnv[0].name=DO_NOT_TRACK' --set-string 'extraEnv[1].value=1'",
            true,
        ),
        ("--set 'extraEnv[0].name=DO_NOT_TRACK'", true),
    ] {
        let launch = format!("{chart} {args}\n");
        assert_eq!(
            launches_without_dnt("planted.sh", &launch).len(),
            usize::from(caught),
            "{args}"
        );
    }
    let quoted = "docker run -e \"DO_NOT_TRACK=1\" ghcr.io/mikkoparkkola/mcp-gateway:test\n";
    assert!(
        launches_without_dnt("planted.sh", quoted).is_empty(),
        "a quoted setting was refused"
    );
}

/// D12's planted launches, both ways: each launcher with an opt-out in a
/// comment, a continued line, a kept setting and a mere mention; then the
/// compose and variable forms.
fn assert_planted_launch_forms() {
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
    assert_planted_compose_and_variable_forms();
}

/// D12. Every launch of the gateway image or chart in our scripts and
/// workflows passes `DO_NOT_TRACK=1` on that launch itself; one planted
/// launch per form, without it, fails.
#[test]
fn every_image_launch_sets_dnt() {
    // The planted launch forms read no repository file, so they run in the
    // packaged crate too.
    assert_planted_launch_forms();
    // Checkout-only, as PACKED.2: the unpacked crate ships `tests/` but not
    // `scripts/` or the workflows, so its walk would see a partial tree.
    if is_packaged_crate() {
        eprintln!("skipped: the launch scripts and workflows are not in the packaged crate");
        return;
    }
    // The floor (A3/A4): the finder sees each known gateway launch, by file,
    // before anything is judged; a finder blind to an image form sees fewer.
    // One read of the launch files, so the floor and the judgement see the
    // same text.
    let sources = launch_sources();
    let mut seen = std::collections::BTreeMap::new();
    for (path, text) in &sources {
        let n = gateway_launches(path, text).len();
        if n > 0 {
            seen.insert(path.clone(), n);
        }
    }
    let known: std::collections::BTreeMap<String, usize> = KNOWN_LAUNCHES
        .iter()
        .map(|(f, n)| ((*f).to_owned(), *n))
        .collect();
    assert_eq!(seen, known, "the gateway launches found, by file");
    let mut missing = Vec::new();
    for (path, text) in &sources {
        if path == PAUSE_SCRIPT {
            let chart = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("deploy/helm/mcp-gateway/templates");
            let read =
                |f: &str| std::fs::read_to_string(chart.join(f)).expect("the chart template");
            let (deployment, helpers) = (read("deployment.yaml"), read("_helpers.tpl"));
            // Controls: each binding, broken, ends the exemption.
            for (script, deployment, helpers) in [
                (
                    text.replace("IMG_REPO=\"pause\"", "IMG_REPO=\"mcp-gateway\""),
                    deployment.clone(),
                    helpers.clone(),
                ),
                (
                    text.replacen(" \"${common_args[@]}\"", "", 1),
                    deployment.clone(),
                    helpers.clone(),
                ),
                (
                    text.replacen("--set image.tag=", "-f v.yaml --set image.tag=", 1),
                    deployment.clone(),
                    helpers.clone(),
                ),
                (
                    text.replacen(
                        "--set image.tag=",
                        "--set-string image.repository=gw --set image.tag=",
                        1,
                    ),
                    deployment.clone(),
                    helpers.clone(),
                ),
                (
                    text.clone(),
                    deployment.replace("include \"mcp-gateway.image\" .", "\"gw\""),
                    helpers.clone(),
                ),
                (
                    text.clone(),
                    deployment.clone(),
                    helpers.replace(".Values.image.repository", ".Values.gateway.image"),
                ),
                (
                    text.replacen(
                        "IMG_REPO=\"pause\"",
                        "IMG_REPO=\"pause\"\nIMG_REPO=\"mcp-gateway\"",
                        1,
                    ),
                    deployment.clone(),
                    helpers.clone(),
                ),
            ] {
                assert!(
                    !pause_script_runs_only_pause(&script, &deployment, &helpers),
                    "a broken pause binding still exempted {PAUSE_SCRIPT}"
                );
            }
            assert!(
                pause_script_runs_only_pause(text, &deployment, &helpers),
                "{PAUSE_SCRIPT} no longer runs only registry.k8s.io/pause: its launches need DO_NOT_TRACK=1"
            );
            // Only the two pause upgrades are exempt: any other launch in
            // this file still needs the opt-out (grok A2/A3 improvement).
            let unexempt = |t: &str| -> Vec<String> {
                launches_without_dnt(path, t)
                    .into_iter()
                    .filter(|l| {
                        !(l.starts_with("helm upgrade") && l.contains("\"${common_args[@]}\""))
                    })
                    .collect()
            };
            let planted = format!("{text}\ndocker run ghcr.io/mikkoparkkola/mcp-gateway:x\n");
            assert_eq!(
                unexempt(&planted).len(),
                1,
                "a planted launch rode the exemption"
            );
            for launch in unexempt(text) {
                missing.push(format!("{path}: {launch}"));
            }
            continue;
        }
        for launch in launches_without_dnt(path, text) {
            missing.push(format!("{path}: {launch}"));
        }
        let name = std::path::Path::new(path)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if (name.starts_with("docker-compose") || name.starts_with("compose"))
            && compose_without_dnt(text)
        {
            missing.push(format!(
                "{path}: a compose service runs the gateway image without DO_NOT_TRACK=1"
            ));
        }
    }
    // The judgement last, so a red run proves every control above first.
    assert!(
        missing.is_empty(),
        "launches without DO_NOT_TRACK=1: {missing:?}"
    );
}

/// The command each use of the gateway binary in `text` builds: from the use
/// to the first call that runs it.
fn binary_commands(text: &str) -> Vec<&str> {
    text.match_indices("CARGO_BIN_EXE_mcp-gateway")
        .map(|(at, _)| {
            let rest = &text[at..];
            let runs = [".output()", ".spawn()", ".status()"];
            let end = runs.iter().filter_map(|r| rest.find(r)).min();
            &rest[..end.unwrap_or(rest.len())]
        })
        .collect()
}

/// Spawns under tests/ today, by file: D11's floor, so a finder that missed
/// a spawn form shows here first.
const BINARY_SPAWNS: [(&str, usize); 4] = [
    ("tests/stdio_tests.rs", 1),
    ("tests/tool_list_tests.rs", 1),
    ("tests/http_stop_reaches_teardown.rs", 1),
    ("tests/cli_secret_redaction.rs", 2),
];

/// D11. Every test command that runs the gateway binary sets
/// `DO_NOT_TRACK=1` itself (no shared helper on the 3.5 line, so a new spawn
/// file fails here by name). Planted both ways first.
#[test]
fn every_binary_spawn_sets_dnt() {
    let opted = |cmd: &&str| cmd.contains(".env(\"DO_NOT_TRACK\", \"1\")");
    let without = "Command::new(env!(\"CARGO_BIN_EXE_mcp-gateway\")).arg(\"a\").output()";
    let with = "Command::new(env!(\"CARGO_BIN_EXE_mcp-gateway\"))\n.env(\"DO_NOT_TRACK\", \"1\")\n.spawn()";
    assert!(
        !binary_commands(without).iter().any(opted),
        "planted: missed"
    );
    assert!(binary_commands(with).iter().all(opted), "planted: refused");
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut seen = std::collections::BTreeMap::new();
    let mut bare = Vec::new();
    for (path, text) in rust_files(&root.join("tests")) {
        let commands = binary_commands(&text);
        if commands.is_empty() {
            continue;
        }
        seen.insert(path.clone(), commands.len());
        bare.extend(commands.iter().filter(|c| !opted(*c)).map(|_| path.clone()));
    }
    let floor: std::collections::BTreeMap<String, usize> = BINARY_SPAWNS
        .iter()
        .map(|(f, n)| ((*f).to_owned(), *n))
        .collect();
    assert_eq!(seen, floor, "the gateway-binary spawns found, by file");
    assert!(bare.is_empty(), "spawns without DO_NOT_TRACK=1: {bare:?}");
}

/// DOC1. README.md's "Privacy" section (the 3.5 line has no PRIVACY.md)
/// states, as literals here: where it goes and how long it is kept, the
/// switches and environments that stop it, the Windows and chart cases, the
/// five fields and what the receiver adds; and it names no posture, which the
/// 3.5 line does not have.
#[test]
fn privacy_text_states_the_facts() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let readme = std::fs::read_to_string(root.join("README.md")).expect("README.md");
    let at = readme.find("\n## Privacy\n").expect("a Privacy section");
    let rest = &readme[at + 1..];
    let section = &rest[..rest[3..].find("\n## ").map_or(rest.len(), |end| end + 3)];
    let stated = [
        "https://telemetry.revaluator.ai/v1/heartbeat",
        "kept for three months",
        "`NO_TELEMETRY=1`",
        "`DO_NOT_TRACK=1`",
        "`GITHUB_ACTIONS`",
        "`ALL_PROXY`",
        "`HTTP_PROXY`",
        "`HTTPS_PROXY`",
        "on Windows, where the 3.5 line sends no heartbeat",
        "root filesystem is read-only",
        "`install_id`",
        "`runtime`",
        "`version`",
        "`event`",
        "`project`",
        "processor architecture",
        "a city name and a country",
        "time the heartbeat arrived",
    ];
    for fact in stated {
        assert!(section.contains(fact), "Privacy does not state {fact:?}");
    }
    assert!(
        !section.contains("posture") && !section.contains("hardened"),
        "Privacy names a posture the 3.5 line does not have"
    );
}

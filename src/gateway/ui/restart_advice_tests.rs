// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Advice rows A1-A10: which restart keys an answer carries, how the start
//! command is quoted and when it is left out, and that the guidance has one
//! source shared with the restart GET. Rows compare against the module's own
//! constants rather than restating the guidance.

use std::path::Path;

use serde_json::{Value, json};

use super::super::Reason;
use super::{Platform, StartCommand, UNIX_GUIDANCE, WINDOWS_GUIDANCE, advice, refusal_sentence};

const EXE: &str = "/opt/gw/bin/mcp-gateway";
const CONFIG: &str = "/etc/gw/gateway.yaml";

fn start(exe: &str, config: &str) -> Option<StartCommand> {
    StartCommand::new(Path::new(exe), Path::new(config))
}

fn keys(map: Option<serde_json::Map<String, Value>>) -> Value {
    map.map_or(Value::Null, Value::Object)
}

#[test]
fn a1_nothing_pending_adds_no_key() {
    let cmd = start(EXE, CONFIG);
    for platform in [Platform::Unix, Platform::Windows] {
        assert_eq!(
            keys(advice(false, None, platform, cmd.as_ref())),
            Value::Null
        );
        assert_eq!(
            keys(advice(false, Some("bad bind"), platform, cmd.as_ref())),
            Value::Null
        );
    }
}

// Unix only: the command absolutizes its config path, and a POSIX path is not absolute on Windows.
#[cfg(unix)]
#[test]
fn a2_unix_pending_gives_the_line_and_the_quoted_command() {
    let cmd = start(EXE, CONFIG).expect("plain paths give a command");
    assert_eq!(
        keys(advice(true, None, Platform::Unix, Some(&cmd))),
        json!({
            "restart_advice": UNIX_GUIDANCE,
            "start_command": format!("'{EXE}' serve --config '{CONFIG}'"),
        })
    );
}

#[test]
fn a3_without_a_command_the_line_stands_alone() {
    assert_eq!(
        keys(advice(true, None, Platform::Unix, None)),
        json!({ "restart_advice": UNIX_GUIDANCE })
    );
}

#[test]
fn a4_windows_never_carries_a_command() {
    let cmd = start(EXE, CONFIG);
    assert_eq!(
        keys(advice(true, None, Platform::Windows, cmd.as_ref())),
        json!({ "restart_advice": WINDOWS_GUIDANCE })
    );
}

#[test]
fn a5_a_refusal_is_the_only_key_on_both_platforms() {
    let cmd = start(EXE, CONFIG);
    let why = "server.bind is a public address without TLS";
    for platform in [Platform::Unix, Platform::Windows] {
        assert_eq!(
            keys(advice(true, Some(why), platform, cmd.as_ref())),
            json!({ "start_refusal": refusal_sentence(why) })
        );
    }
    let sentence = refusal_sentence(why);
    assert!(sentence.contains(why), "{sentence}");
    assert!(sentence.contains("config file"), "{sentence}");
    assert!(!sentence.contains("gateway.yaml"), "{sentence}");
    // A reason that ends in its own full stop: one stop where reason and fix meet.
    let stopped = refusal_sentence("the port is taken.");
    assert!(stopped.contains("the port is taken. Fix"), "{stopped}");
    assert!(!stopped.contains(".."), "{stopped}");
}

/// Paths with a quote, a space and a substitution, in exe and config alike.
#[cfg(unix)]
const ODD_EXE: &str = "/opt/my 'gw'/$(id) bin/mcp-gateway";
#[cfg(unix)]
const ODD_CONFIG: &str = "/srv/it's here/$(id).yaml";

#[cfg(unix)]
#[test]
fn a6_quotes_keep_every_path_one_word_with_nothing_expanded() {
    let cmd = start(ODD_EXE, ODD_CONFIG).expect("quotes and spaces are quotable");
    assert_eq!(
        cmd.as_str(),
        r"'/opt/my '\''gw'\''/$(id) bin/mcp-gateway' serve --config '/srv/it'\''s here/$(id).yaml'"
    );
}

#[cfg(unix)]
#[test]
fn a6b_a_relative_config_path_is_given_absolute() {
    let cmd = start(EXE, "conf/gateway.yaml").expect("a relative path gives a command");
    let whole = std::path::absolute("conf/gateway.yaml").expect("the working directory is known");
    assert!(
        cmd.as_str()
            .ends_with(&format!(" serve --config '{}'", whole.display())),
        "{}",
        cmd.as_str()
    );
}

#[cfg(unix)]
#[test]
fn a6_a_posix_shell_reads_the_command_back_as_the_same_words() {
    let cmd = start(ODD_EXE, ODD_CONFIG).expect("quotes and spaces are quotable");
    let out = std::process::Command::new("sh")
        .arg("-c")
        // The shell parses the command into its words, then prints each.
        .arg(format!("set -- {}; printf '%s\\0' \"$@\"", cmd.as_str()))
        .output()
        .expect("sh runs");
    let words: Vec<String> = out
        .stdout
        .split(|b| *b == 0)
        .filter(|w| !w.is_empty())
        .map(|w| String::from_utf8_lossy(w).into_owned())
        .collect();
    assert_eq!(words, [ODD_EXE, "serve", "--config", ODD_CONFIG]);
}

const SENTINEL: &str = "argv-sentinel-9453";
/// The name A7's child is invoked by on Unix (its argv[0]).
const ARG0_SENTINEL: &str = "arg0-sentinel-9453";
const MARK: &str = "A7-ADVICE:";
/// The config path the parent hands the child, marked with the parent's pid.
const A7_CONFIG_ENV: &str = "GW_A7_MARKED_CONFIG";

/// Run by A7 as a child process whose argv holds the sentinel.
#[test]
#[ignore = "run by a7 as a child process"]
fn a7_child_prints_the_production_advice() {
    let config = std::env::var(A7_CONFIG_ENV).unwrap_or_else(|_| CONFIG.to_owned());
    let advice = super::super::restart_advice(true, None, Some(Path::new(&config)));
    println!("{MARK}{}", keys(advice));
}

#[test]
fn a7_the_command_holds_no_argument_of_the_process() {
    let full = module_path!()
        .split_once("::")
        .map_or(module_path!(), |(_, rest)| rest);
    let helper = format!("{full}::a7_child_prints_the_production_advice");
    let marked = format!("/etc/gw/a7-run-{}/gateway.yaml", std::process::id());
    let mut child = crate::test_home::test_binary();
    // The command names the running file, never the name the process was
    // invoked by, so the child's argv[0] is a sentinel as well.
    #[cfg(unix)]
    std::os::unix::process::CommandExt::arg0(&mut child, ARG0_SENTINEL);
    let out = child
        .env(A7_CONFIG_ENV, &marked)
        .args([
            helper.as_str(),
            SENTINEL,
            "--exact",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .output()
        .expect("the child runs");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let printed = stdout
        .lines()
        .find_map(|l| l.split_once(MARK).map(|(_, body)| body.to_owned()))
        .unwrap_or_else(|| panic!("the child printed no advice: {stdout}"));
    assert!(out.status.success(), "the child failed: {stdout}");
    let answer: Value = serde_json::from_str(&printed).expect("the child printed JSON");
    assert!(answer.get("restart_advice").is_some(), "{printed}");
    if cfg!(unix) {
        // The oracle is the command this run produced: it names the marked
        // path, so a helper that never ran cannot pass by printing nothing.
        let command = answer["start_command"]
            .as_str()
            .unwrap_or_else(|| panic!("no start command: {printed}"));
        assert!(command.contains(&marked), "{command}");
        assert!(!command.contains(SENTINEL), "{command}");
        assert!(!command.contains(ARG0_SENTINEL), "{command}");
    } else {
        assert!(!printed.contains(SENTINEL), "{printed}");
    }
    assert!(
        !include_str!("restart_advice.rs").contains("env::args"),
        "the advice reads the process arguments"
    );
}

#[test]
fn a8_the_restart_get_answers_the_same_guidance() {
    assert_eq!(Reason::RestartNotAvailable.recovery(), UNIX_GUIDANCE);
    assert_eq!(Reason::WindowsManualRestart.recovery(), WINDOWS_GUIDANCE);
}

#[test]
fn a8b_each_guidance_sentence_is_written_once_in_src() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let texts: Vec<(std::path::PathBuf, String)> = walkdir::WalkDir::new(&root)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file() && e.path().extension().is_some_and(|x| x == "rs"))
        .map(|e| {
            let text = std::fs::read_to_string(e.path()).expect("readable source");
            (e.into_path(), text)
        })
        .collect();
    for line in [UNIX_GUIDANCE, WINDOWS_GUIDANCE] {
        assert!(!line.is_empty(), "a guidance constant is empty");
        let hits: Vec<_> = texts
            .iter()
            .flat_map(|(path, text)| std::iter::repeat_n(path, text.matches(line).count()))
            .collect();
        assert_eq!(hits.len(), 1, "{line:?} written at {hits:?}");
    }
}

#[test]
fn the_unix_line_says_to_stop_first_and_names_the_supervisors() {
    for word in ["stop", "start command", "systemctl", "docker", "brew"] {
        assert!(
            UNIX_GUIDANCE.contains(word),
            "the Unix guidance lacks {word:?}"
        );
    }
}

#[test]
fn a9_a_control_character_in_either_path_leaves_the_command_out() {
    for (exe, config) in [
        (EXE, "/etc/gw/two\nlines.yaml"),
        ("/opt/gw\n/mcp-gateway", CONFIG),
        (EXE, "/etc/gw/tab\there.yaml"),
        (EXE, "/etc/gw/carriage\rreturn.yaml"),
        ("/opt/gw\r/mcp-gateway", CONFIG),
        (EXE, "/etc/gw/bell\u{7}.yaml"),
    ] {
        assert!(start(exe, config).is_none(), "{exe:?} {config:?}");
    }
}

#[cfg(unix)]
#[test]
fn a10_a_path_that_is_not_utf8_leaves_the_command_out() {
    use std::os::unix::ffi::OsStrExt as _;
    let config = Path::new(std::ffi::OsStr::from_bytes(b"/etc/gw/\xff.yaml"));
    assert!(StartCommand::new(Path::new(EXE), config).is_none());
}

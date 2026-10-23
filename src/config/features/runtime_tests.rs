// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8666 (DUPC-9.PR9.3): the `runtime.availability` config shape is pinned
//! byte for byte, so swapping the Rust type behind it cannot change a file.

use std::fmt::Write as _;

use super::RuntimeConfig;

const PINNED: &str = "local_process: true\ndocker: false\npodman: false\nsystemd: false\nlaunchd: false\nkubernetes: false\n";

fn parse(yaml: &str) -> RuntimeConfig {
    crate::yaml::from_str(yaml).expect("fixture parses")
}

#[test]
fn availability_defaults_and_partial_keys_keep_local_process_on() {
    let empty = parse("availability: {}");
    assert!(empty.availability.local_process && !empty.availability.docker);
    let docker = parse("availability: {docker: true}");
    assert!(docker.availability.local_process && docker.availability.docker);
    assert!(
        !parse("availability: {local_process: false}")
            .availability
            .local_process
    );
    assert_eq!(
        parse("{}").availability,
        RuntimeConfig::default().availability
    );
}

#[test]
fn availability_serializes_and_round_trips_byte_identically() {
    let default = crate::yaml::to_string(&RuntimeConfig::default().availability).expect("ser");
    assert_eq!(default, PINNED);
    let nested = PINNED.lines().fold(String::new(), |mut out, line| {
        let _ = writeln!(out, "  {line}");
        out
    });
    let reparsed = parse(&format!("availability:\n{nested}"));
    assert_eq!(
        crate::yaml::to_string(&reparsed.availability).expect("ser"),
        PINNED
    );
}

#[test]
fn each_provider_turns_on_alone_and_local_process_stays_on() {
    const KEYS: [&str; 5] = ["docker", "podman", "systemd", "launchd", "kubernetes"];
    for key in KEYS {
        let a = parse(&format!("availability: {{{key}: true}}")).availability;
        let on = [a.docker, a.podman, a.systemd, a.launchd, a.kubernetes];
        let want = KEYS.map(|k| k == key);
        assert_eq!(on, want, "{key} alone");
        assert!(a.local_process, "{key}: local_process stays on");
    }
}

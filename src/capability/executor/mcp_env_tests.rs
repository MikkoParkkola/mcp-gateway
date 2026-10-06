// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7953: names the gateway sets for the child itself (`is_reserved`) are no
//! redaction secrets, yet a changed declared value still restarts the child.

use serde_json::json;

use super::{call, caller, capability_yaml, executor_holding, parse_capability};

/// HOME in `env` is reserved and never taken from the list, so its value stays
/// in the result; the declared name the child receives is scrubbed.
#[tokio::test]
async fn a_reserved_env_name_is_not_scrubbed_from_the_result() {
    let home = "/home-7953-operator";
    let secret = "tok-7953-mcp-declared";
    // The helper writes one env-file line; HOME rides on a second.
    let (_dir, executor) = executor_holding(&format!("{secret}\nHOME={home}"));
    let cap = parse_capability(&capability_yaml().replace(
        "transport: stdio",
        "transport: stdio\n      env: [HOME, CAP_EXEC_TEST_TOKEN]",
    ))
    .expect("probe parses");
    let out = call(
        &executor,
        &cap,
        json!({"operation": "say", "text": home}),
        &caller("a"),
    )
    .await
    .unwrap();
    assert_eq!(out["arguments"]["message"], home, "{out}");
    assert_eq!(
        out["test_values"]["CAP_EXEC_TEST_TOKEN"], "[redacted]",
        "{out}"
    );
    assert!(!out.to_string().contains(secret), "{out}");
}

/// PATH in `env` is left out of the redaction list, yet the child receives it,
/// so a reload that changes it still starts a new child.
#[tokio::test]
async fn a_reload_changing_a_declared_path_restarts_the_child() {
    let cap = parse_capability(&capability_yaml().replace(
        "transport: stdio",
        "transport: stdio\n      env: [PATH, CAP_EXEC_TEST_TOKEN]",
    ))
    .expect("probe parses");
    // The helper writes one env-file line; PATH rides on a second.
    let (_a, executor) = executor_holding("tok-7953\nPATH=/path-7953-a");
    let say = json!({"operation": "say", "text": "x"});
    let first = call(&executor, &cap, say.clone(), &caller("a"))
        .await
        .unwrap();
    let (_b, reloaded) = executor_holding("tok-7953\nPATH=/path-7953-b");
    executor.env.set(reloaded.env.get());
    let second = call(&executor, &cap, say, &caller("a")).await.unwrap();
    assert_ne!(first["pid"], second["pid"], "a new PATH starts a new child");
}

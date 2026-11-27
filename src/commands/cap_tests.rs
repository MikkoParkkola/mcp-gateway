// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::cap_pin;
use mcp_gateway::capability::{compute_capability_hash, parse_capability_file};
use std::io::Write;
use std::process::ExitCode;
use tempfile::TempDir;

const PINNABLE_YAML: &str = "\
name: pin_cli_cap
description: CLI pin test
providers:
  primary:
    service: rest
    config:
      base_url: https://example.com
      path: /cli
";

/// Extract the exit-code discriminant for comparison in tests.
fn is_success(code: ExitCode) -> bool {
    // ExitCode doesn't expose its raw value publicly; compare via Debug.
    format!("{code:?}") == format!("{:?}", ExitCode::SUCCESS)
}

/// LD6: `cap validate` refuses a misspelt key with the loader's message
/// (the same `parse_capability_file` error `validate` prints) and fails.
#[tokio::test]
async fn ld6_cap_validate_refuses_a_misspelt_key() {
    let dir = TempDir::new().expect("dir");
    let path = dir.path().join("typo.yaml");
    std::fs::write(
            &path,
            "name: typo\ndescription: d\nproviders:\n  primary:\n    service: rest\n    rate_lmit:\n      interval_ms: 1000\n    config:\n      base_url: https://typo.test\n      path: /x\n",
        )
        .expect("write");
    let message = parse_capability_file(&path)
        .await
        .expect_err("refused")
        .to_string();
    assert_eq!(
        message,
        format!(
            "Configuration error: {}: key `rate_lmit` is not a capability provider field. Did you mean: rate_limit?",
            path.display()
        )
    );
    assert!(
        !is_success(super::cap_validate(path, super::Render::Text).await),
        "cap validate fails"
    );
}

#[tokio::test]
async fn cap_pin_writes_valid_hash_and_roundtrips_through_loader() {
    // GIVEN: a fresh, unpinned capability YAML on disk
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("pin_me.yaml");
    {
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(PINNABLE_YAML.as_bytes()).unwrap();
    }
    let expected_hash = compute_capability_hash(PINNABLE_YAML);

    // WHEN: running `mcp-gateway cap pin <file>`
    let code = cap_pin(path.clone()).await;

    // THEN: command succeeds
    assert!(is_success(code), "cap_pin should exit successfully");

    // AND: the file now begins with a sha256 line carrying the right hash
    let written = std::fs::read_to_string(&path).unwrap();
    assert!(written.starts_with(&format!("sha256: {expected_hash}\n")));

    // AND: the loader accepts the rewritten file (pin verification passes)
    let cap = parse_capability_file(&path).await.unwrap();
    assert_eq!(cap.name, "pin_cli_cap");
    assert_eq!(cap.sha256.as_deref(), Some(expected_hash.as_str()));
}

/// `cap pin` never writes a file the loader then refuses. A pin line that
/// already hides a second `sha256:` after a YAML line break would
/// otherwise be rewritten into a file with two pins (#1212).
#[tokio::test]
async fn cap_pin_never_writes_a_file_the_loader_refuses() {
    for brk in ['\r', '\u{85}', '\u{2028}', '\u{2029}'] {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("malformed.yaml");
        let original = format!("sha256: old{brk}sha256: older\n{PINNABLE_YAML}");
        std::fs::write(&path, &original).unwrap();

        let code = cap_pin(path.clone()).await;

        if is_success(code) {
            parse_capability_file(&path)
                .await
                .unwrap_or_else(|e| panic!("break {brk:?}: cap pin wrote a refused file: {e}"));
        } else {
            assert_eq!(
                std::fs::read_to_string(&path).unwrap(),
                original,
                "break {brk:?}: a refused pin changed the file"
            );
        }
    }
}

/// J11, the failures before the call (MIK-9764.JSONF.1): an unreadable capability file, arguments that are not
/// JSON and arguments the input schema refuses each leave stdout empty in both forms and name the failure on stderr,
/// the same in both forms. Arguments that are not JSON are a wrong invocation, exit 2; the other two exit 1.
#[tokio::test]
async fn cap_test_failures_before_the_call_print_nothing_on_stdout() {
    use crate::cli::output::Render;
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("city_cap.yaml");
    std::fs::write(
            &file,
            "name: city_cap\ndescription: City\nschema:\n  input:\n    type: object\n    properties:\n      \
             city:\n        type: string\n    required: [city]\nproviders:\n  primary:\n    service: rest\n    \
             config:\n      base_url: https://city.test\n      path: /now\n      method: GET\n",
        )
        .unwrap();
    let missing = dir.path().join("missing.yaml");
    let executor = mcp_gateway::capability::CapabilityExecutor::new();
    // (file, arguments, the start of the stderr, a word it must name, the exit)
    let cases = [
        (
            &missing,
            r#"{"city": "Oulu"}"#,
            "error: Failed to parse capability: ",
            "missing.yaml",
            1,
        ),
        // Arguments that are not JSON are a wrong invocation.
        (&file, "{", "error: Invalid JSON arguments: ", "EOF", 2),
        // The schema refusal: `city` is required and missing.
        (&file, "{}", "error: ", "city", 1),
    ];
    for (path, args, start, names, exit) in cases {
        for render in [Render::Text, Render::Json] {
            let mut banner = String::new();
            let printed = super::cap_test_with(&executor, path, args, render, &mut |b| {
                banner.push_str(b);
            })
            .await;
            assert_eq!(
                banner, "",
                "no banner before a refused call: {args} {render:?}"
            );
            assert_eq!(
                (printed.stdout.as_str(), printed.exit),
                ("", exit),
                "{args} {render:?}"
            );
            assert!(
                printed.stderr.starts_with(start) && printed.stderr.contains(names),
                "{args} {render:?}: {}",
                printed.stderr
            );
        }
    }
}

/// J11, order: in text the banner goes out before the call. The backend answers 200 only once the banner has
/// reached the test (it waits up to 10 s, then answers 500), so a banner held back until the call returns gets
/// the 500 and this row fails.
#[tokio::test]
async fn cap_test_text_banner_goes_out_before_the_call() {
    use crate::cli::output::Render;
    use std::io::Read as _;
    let (seen_tx, seen_rx) = std::sync::mpsc::channel::<()>();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        let mut request = vec![0_u8; 65536];
        let _ = stream.read(&mut request);
        let (status, body) = match seen_rx.recv_timeout(std::time::Duration::from_secs(10)) {
            Ok(()) => ("200 OK", r#"{"ok":true}"#),
            Err(_) => ("500 Banner Late", r#"{"ok":false}"#),
        };
        let head = format!(
            "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            body.len()
        );
        let _ = stream.write_all(head.as_bytes());
        let _ = stream.write_all(body.as_bytes());
    });
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("order_cap.yaml");
    std::fs::write(
            &file,
            format!(
                "name: order_cap\ndescription: Order\nschema:\n  input:\n    type: object\nproviders:\n  primary:\n    \
                 service: rest\n    config:\n      base_url: http://127.0.0.1:{port}\n      path: /now\n      \
                 method: GET\n"
            ),
        )
        .unwrap();
    let executor = mcp_gateway::capability::CapabilityExecutor::new().with_test_loopback_egress();
    let mut banner = String::new();
    let printed = super::cap_test_with(&executor, &file, "{}", Render::Text, &mut |b| {
        banner.push_str(b);
        let _ = seen_tx.send(());
    })
    .await;
    assert_eq!(banner, "Testing capability: order_cap\nArguments: {}\n\n");
    assert_eq!(
        (printed.exit, printed.stdout.as_str()),
        (0, "✅ Success:\n\n{\n  \"ok\": true\n}\n"),
        "{}",
        printed.stderr
    );
}

/// J11 (MIK-9764.JSONF.1): a successful `cap test` through an executor that may reach loopback (the `cfg(test)`
/// seam): under `--json` one document with the capability, the arguments and the result (with no response
/// transform the result is the body); in text the banner, the arguments and the pretty result, as today.
#[tokio::test]
async fn cap_test_prints_one_document_on_success() {
    use crate::cli::output::{Printed, Render};
    use std::io::Read as _;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let body = br#"{"temp":21,"unit":"C"}"#;
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let mut request = vec![0_u8; 65536];
            let _ = stream.read(&mut request);
            let head = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(body);
        }
    });
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("now_cap.yaml");
    std::fs::write(
            &file,
            format!(
                "name: now_cap\ndescription: Now\nschema:\n  input:\n    type: object\n    properties:\n      \
                 city:\n        type: string\nproviders:\n  primary:\n    service: rest\n    config:\n      \
                 base_url: http://127.0.0.1:{port}\n      path: /now\n      method: GET\n"
            ),
        )
        .unwrap();
    let executor = mcp_gateway::capability::CapabilityExecutor::new().with_test_loopback_egress();
    let args = r#"{"city": "Oulu"}"#;

    let mut banner = String::new();
    let json = super::cap_test_with(&executor, &file, args, Render::Json, &mut |b| {
        banner.push_str(b);
    })
    .await;
    assert_eq!(banner, "", "--json sends nothing out before the call");
    assert_eq!(
            json,
            Printed {
                stdout: "{\"schema_version\":1,\"capability\":\"now_cap\",\"arguments\":{\"city\":\"Oulu\"},\
                         \"result\":{\"temp\":21,\"unit\":\"C\"}}\n"
                    .to_owned(),
                stderr: String::new(),
                exit: 0,
            }
        );
    let text = super::cap_test_with(&executor, &file, args, Render::Text, &mut |b| {
        banner.push_str(b);
    })
    .await;
    assert_eq!(
        banner, "Testing capability: now_cap\nArguments: {\n  \"city\": \"Oulu\"\n}\n\n",
        "text sends the banner out before the call"
    );
    assert_eq!(
        text,
        Printed {
            stdout: "✅ Success:\n\n{\n  \"temp\": 21,\n  \"unit\": \"C\"\n}\n".to_owned(),
            stderr: String::new(),
            exit: 0,
        }
    );
}

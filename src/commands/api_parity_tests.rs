// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The CLI form of every web UI change, `mcp-gateway api METHOD PATH`, parses
//! as the api command and sends exactly that method and path, once: the
//! table in `gateway::ui::cli_parity_tests` is checked against the command
//! that would send it, not only against clap.

use std::sync::Mutex;

use clap::Parser;
use mcp_gateway::cli::{Cli, Command};
use reqwest::StatusCode;
use reqwest::header::HeaderMap;

use super::api::{ApiExit, ApiRequest, run_api_with};
use super::dashboard_link::{AdminCallError, AdminResponse, LinkTls, TOKEN_ENV};
use crate::gateway::ui::cli_parity_tests::{CliForm, UI_CHANGES, filled};

#[tokio::test]
async fn each_ui_change_cli_form_sends_that_method_and_path() {
    let mut checked = 0;
    for change in UI_CHANGES.iter().filter(|c| c.cli == CliForm::Api) {
        let path = filled(change.path);
        let form = format!("mcp-gateway api {} {path}", change.method);
        let cli = Cli::try_parse_from(["mcp-gateway", "api", change.method, path.as_str()])
            .unwrap_or_else(|e| panic!("{form}: does not parse: {e}"));
        let Some(Command::Api(args)) = cli.command else {
            panic!("{form}: parses as another command");
        };
        let sent = Mutex::new(Vec::new());
        let outcome = run_api_with(
            &args,
            "http://127.0.0.1:9",
            &LinkTls::default(),
            |name| (name == TOKEN_ENV).then(|| "parity-credential".to_owned()),
            || Err("no stdin in this row".to_owned()),
            |request: ApiRequest| {
                let seen = (request.method.to_string(), request.url.path().to_owned());
                sent.lock().expect("sent").push(seen);
                async {
                    Ok::<_, AdminCallError>(AdminResponse {
                        status: StatusCode::NO_CONTENT,
                        headers: HeaderMap::new(),
                        body: Vec::new(),
                    })
                }
            },
        )
        .await;
        let sent = sent.into_inner().expect("sent");
        assert_eq!(
            sent,
            [(change.method.to_owned(), path)],
            "{form}: must send that method and path once"
        );
        assert_eq!(
            outcome.exit,
            ApiExit::Ok,
            "{form}: a 204 answer must exit 0"
        );
        checked += 1;
    }
    assert!(
        checked >= 20,
        "premise: the table's forms were sent, saw {checked}"
    );
}

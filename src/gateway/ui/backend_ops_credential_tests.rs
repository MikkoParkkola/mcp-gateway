// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What a saved command or URL may not carry as text (`credential_refusals`).

/// A `credential_refusals` answer as `code:field` strings.
fn refused(cmd: Option<&str>, url: Option<&str>) -> Vec<String> {
    super::credential_refusals(cmd, url)
        .into_iter()
        .map(|(code, field)| format!("{code}:{field}"))
        .collect()
}

fn url(u: &str) -> Vec<String> {
    refused(None, Some(u))
}

fn cmd(c: &str) -> Vec<String> {
    refused(Some(c), None)
}

const BAD_URL: &[&str] = &["secret_in_url:url"];
const BAD_CMD: &[&str] = &["secret_in_command:command"];
const NONE: &[&str] = &[];

/// R1 (D-CLI r2): what a saved command or URL may not carry as text. A
/// credential-named query, userinfo, command flag, `NAME=value` or
/// `Name: value` argument with a literal (or literal-bearing) value is
/// refused by field; templates, references, ordinary queries and positional
/// words pass; a URL is not checked when a command is given. (URLs with
/// userinfo are built from parts.)
/// (This table: a saved URL's userinfo and query.)
#[test]
fn r1_credential_refusals_table() {
    assert_eq!(
        url(&["https://svc:", "pw-0123456789", "@h.example/mcp"].concat()),
        BAD_URL,
        "userinfo"
    );
    assert_eq!(
        url("https://h.example/mcp?api_key=k1"),
        BAD_URL,
        "short credential query"
    );
    assert_eq!(
        url("https://h.example/mcp?token=${T:-dflt-0123}"),
        BAD_URL,
        "literal default"
    );
    assert_eq!(
        url("https://h.example/mcp?transport=sse&region=eu"),
        NONE,
        "ordinary query"
    );
    assert_eq!(
        url("wss://h.example/ws?access_token=abc12345"),
        BAD_URL,
        "websocket"
    );
    assert_eq!(
        url(&["https://", "user-0123456789", ":@h.example/mcp"].concat()),
        BAD_URL,
        "username with an empty password"
    );
    assert_eq!(
        url(&["https://svc:", "${SVC_TOKEN}", "@h.example/mcp"].concat()),
        NONE,
        "userinfo template"
    );
    assert_eq!(
        url(&["https://", "${SVC_USER}", "@h.example/mcp"].concat()),
        NONE,
        "userinfo template without a password"
    );
    // Delta G5b: spellings the URL parser accepts without exactly `://`.
    for spelling in ["https:/", "https:///", "https:", "https:\\\\"] {
        assert_eq!(
            url(&[spelling, "svc:", "pw-0123456789", "@h.example/mcp"].concat()),
            BAD_URL,
            "userinfo after {spelling}"
        );
    }
    // Delta G5c: a later `://` or a fragment cannot lend a placeholder.
    for tail in ["/mcp://${T}@x", "/mcp#https://svc:${T}@x"] {
        assert_eq!(
            url(&["https:svc:", "pw-0123456789", "@h.example", tail].concat()),
            BAD_URL,
            "placeholder lent by {tail}"
        );
    }
    // One reading (the parser's): a placeholder passes in any spelling it
    // accepts; anything else in the userinfo, encoded or not, is refused.
    assert_eq!(
        url("https:svc:${SVC_TOKEN}@h.example/mcp"),
        NONE,
        "placeholder outside the canonical spelling"
    );
    assert_eq!(
        url(&["https://", "svc:", "$%7BA%7D-x", "@h.example/mcp"].concat()),
        BAD_URL,
        "text beside an encoded placeholder"
    );
    assert_eq!(
        url(&["https://", "svc:", "%24%7BSVC_TOKEN%7D", "@h.example/mcp"].concat()),
        BAD_URL,
        "a placeholder with its dollar escaped stays refused"
    );
    assert_eq!(
        url(&["https://", "svc:", "${SVC:-pw-0123}", "@h.example/mcp"].concat()),
        BAD_URL,
        "a placeholder with a default is text"
    );
    assert_eq!(
        url(&[" https://", "svc:", "pw-0123456789", "@h.example/mcp"].concat()),
        BAD_URL,
        "leading space the parser trims"
    );
}

/// R1b (D-CLI r2): the same rule for a saved command, and the URL is not
/// checked when a command is given.
#[test]
fn r1b_command_credential_refusals_table() {
    assert_eq!(url("https://h.example/mcp"), NONE, "plain");

    assert_eq!(cmd("npx tool --api-key=k1"), BAD_CMD, "flag=value");
    assert_eq!(
        cmd("npx tool --token tok-0123456789"),
        BAD_CMD,
        "flag value"
    );
    assert_eq!(
        cmd("env GITHUB_TOKEN=ghp-0123 npx tool"),
        BAD_CMD,
        "name=value"
    );
    assert_eq!(
        cmd("npx tool --authorization \"Bearer tok-0123456789\""),
        BAD_CMD,
        "quoted value"
    );
    assert_eq!(cmd("npx tool \"--api-key=k1\""), BAD_CMD, "quoted flag");
    assert_eq!(
        cmd("curl -H \"Authorization: Bearer tok-0123\""),
        BAD_CMD,
        "header-shaped"
    );
    assert_eq!(
        cmd("curl -H \"Authorization:Bearer tok-0123\""),
        BAD_CMD,
        "header-shaped, no space after the colon"
    );
    assert_eq!(
        cmd("npx tool --url=https://h/?api_key=k1"),
        BAD_CMD,
        "url in an argument"
    );
    assert_eq!(cmd("npx tool --token ${MY_TOKEN}"), NONE, "template");
    assert_eq!(cmd("npx tool --token env:MY_TOKEN"), NONE, "reference");
    assert_eq!(
        cmd("npx -y @scope/server --port 8080 data.json"),
        NONE,
        "ordinary"
    );
    assert_eq!(
        cmd("npx tool --token-limit 5"),
        NONE,
        "not a credential name"
    );
    // Code review r2 (G5): forms the first cut let through or refused wrongly.
    assert_eq!(
        cmd("npx tool https://h.example/mcp?transport=sse&api_key=k1"),
        BAD_CMD,
        "URL argument with the credential after an ordinary query"
    );
    assert_eq!(
        cmd("npx tool --token -abc123"),
        BAD_CMD,
        "value with a leading dash"
    );
    assert_eq!(
        cmd("npx tool --token --verbose"),
        NONE,
        "a long flag after the name"
    );
    assert_eq!(
        refused(
            Some("npx tool"),
            Some(&["https://svc:", "pw-0123456789", "@h/mcp"].concat())
        ),
        NONE,
        "the URL is not saved when a command is given"
    );
}

/// Pins why mutant M14 is equivalent: the URL parser turns an empty password
/// (`user:@`) into no password, so the userinfo check's empty-password guard
/// never sees one. If a url crate release changes this, the row fails and
/// the guard starts to matter.
#[test]
fn an_empty_url_password_parses_as_no_password() {
    for scheme in ["http", "https"] {
        let raw = [scheme, "://", "user", ":", "@h.example/"].concat();
        let url = url::Url::parse(&raw).expect("parses");
        assert_eq!(url.password(), None, "{raw}");
        assert_eq!(url.username(), "user", "{raw}");
    }
}

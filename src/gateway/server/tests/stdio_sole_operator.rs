// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! [`sole_operator_asserted`](super::super::account_bindings::sole_operator_asserted)
//! observed through the install and the registry, not the predicate in
//! isolation.
//!
//! Both tests call `install_account_strategies` with an explicit
//! [`ServeMode`] and then `AccountStrategyRegistry::resolve` against a real,
//! empty custody — a descriptor that is declared but never connected. Custody
//! is real rather than scripted because the fact under test is WHICH refusal
//! text a caller reaches, and `PropagationError::AccountNotConnected`'s own
//! text ("no connected account (fail-closed)") is production's, not this
//! fixture's.
//!
//! T1 (stdio): auth is off and `single_user` is not declared, and the caller
//! presents nothing but the stdio transport itself. A stdio gateway is
//! spawned BY its one operator (`CallerProvenance::LocalTransport`), so it
//! must be served as the sole operator regardless of `auth.enabled`.
//!
//! T2 (http): auth is on with two API keys, never a sole-operator shape. The
//! caller is refused before any mint.
use std::collections::BTreeMap;
use std::sync::Arc;

use crate::backend::BackendRegistry;
use crate::config::{ApiKeyConfig, AuthConfig, Config, api_key_digest_spec};
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::oauth::GatewayKeyPair;
use crate::gateway::server::account_bindings::{ServeMode, install_account_strategies};
use crate::identity_propagation::{CallerProof, CallerProvenance};
use crate::personal_accounts::config::{
    AccountDescriptor, AccountsConfig, AccountsLimits, DescriptorMode,
};
use crate::personal_accounts::{
    AccountCustody, AccountKey, CredentialLease, CredentialReleaseObserver, CustodyHandle,
    GrantRecord, PersonalAccountStore, ProviderRefreshError, RefreshProvider, ReleasedCredentials,
    StoreConfig, TokenRefresh,
};

const DESCRIPTOR_ID: &str = "acct";
const PROVIDER: &str = "wire-fixture";
const STORE_KEY: [u8; 32] = [0x42; 32];

/// With no grant seeded, custody must refuse before it would ever ask a
/// provider to refresh one — so this provider is never called.
struct UnreachableProvider;

impl RefreshProvider for UnreachableProvider {
    fn refresh(
        &self,
        _account: &AccountKey,
        _current: &GrantRecord,
    ) -> impl std::future::Future<Output = Result<TokenRefresh, ProviderRefreshError>> + Send {
        // Never reached: with no grant seeded, custody refuses before asking.
        std::future::ready(Err(ProviderRefreshError::Unavailable))
    }
}

/// Nothing in this fixture mints, so nothing ever releases.
struct UnreachableObserver;

impl CredentialReleaseObserver for UnreachableObserver {
    fn on_release(
        &self,
        _account: &AccountKey,
        _lease: &CredentialLease,
        _credentials: &ReleasedCredentials,
    ) {
        unreachable!("no mint succeeds in this fixture; nothing ever releases")
    }
}

/// Real custody over a freshly initialized, empty store: `DESCRIPTOR_ID` is
/// declared by the fixture configuration but never connected, so a resolve
/// against it reaches production's own absence refusal.
fn empty_custody(root: &std::path::Path) -> Arc<dyn AccountCustody> {
    let root = root.canonicalize().expect("fixture tempdir exists");
    let config = StoreConfig {
        instance_id: "stdio-sole-operator-tests".to_string(),
        store_dir: root.join("records"),
        authority_dir: root.join("authority"),
        current_key_id: "current".to_string(),
        keys: BTreeMap::from([("current".to_string(), STORE_KEY.to_vec())]),
        max_entries: 16,
        max_authority_bytes: 65_536,
    };
    let store = PersonalAccountStore::initialize(config.clone()).expect("store initializes");
    drop(store);
    let handle = CustodyHandle::start(config, UnreachableProvider, UnreachableObserver, 1)
        .expect("custody starts over the empty store");
    Arc::new(handle) as Arc<dyn AccountCustody>
}

/// One structurally complete `personal_managed` descriptor. Synthetic
/// `.invalid` hosts; nothing here is opened over the network.
fn descriptor() -> AccountDescriptor {
    AccountDescriptor {
        mode: DescriptorMode::PersonalManaged,
        provider: PROVIDER.to_string(),
        resource: Some("https://wire.example.invalid/".to_string()),
        issuer: Some("https://accounts.wire-fixture.invalid".to_string()),
        authorization_endpoint: Some("https://accounts.wire-fixture.invalid/authorize".to_string()),
        token_endpoint: Some("https://accounts.wire-fixture.invalid/token".to_string()),
        revocation_endpoint: None,
        client_id: Some("synthetic-client".to_string()),
        client_secret_ref: Some("env:FIXTURE_STDIO_SOLE_OPERATOR_SECRET".to_string()),
        redirect_uri: Some("https://gateway.example.invalid/oauth/callback".to_string()),
        scopes: Some(vec!["https://wire.example.invalid/read".to_string()]),
        send_resource_parameter: Some(false),
        external_strategy: None,
        authorize_extra: None,
    }
}

fn accounts_config() -> AccountsConfig {
    AccountsConfig {
        schema_version: "accounts.v1".to_string(),
        enabled: true,
        deployment: "single_process".to_string(),
        instance_id: "stdio-sole-operator-tests".to_string(),
        store_dir: std::path::PathBuf::from("/synthetic/fixture/accounts/records"),
        authority_dir: std::path::PathBuf::from("/synthetic/fixture/accounts/authority"),
        current_key_id: "current".to_string(),
        keys: BTreeMap::from([(
            "current".to_string(),
            "env:FIXTURE_ACCOUNT_STORE_KEY".to_string(),
        )]),
        descriptors: Some(BTreeMap::from([(DESCRIPTOR_ID.to_string(), descriptor())])),
        limits: AccountsLimits::default(),
        adapters: Vec::new(),
        hosted: None,
    }
}

/// A named, digest-backed API key — never a plaintext one.
fn api_key(name: &str, secret: &[u8]) -> ApiKeyConfig {
    ApiKeyConfig {
        key: None,
        key_sha256: Some(api_key_digest_spec(secret)),
        expires_at: None,
        name: name.to_string(),
        rate_limit: 0,
        backends: Vec::new(),
        allowed_tools: None,
        denied_tools: None,
        admin: false,
        kind: crate::config::ApiKeyKind::Shared,
    }
}

/// The production sequence: real install, then a real resolve against the
/// one declared, never-connected descriptor. Returns the refusal text.
async fn resolve_under(mode: ServeMode, auth: AuthConfig, caller: CallerProof<'_>) -> String {
    let root = tempfile::TempDir::new().expect("fixture tempdir");
    let custody = empty_custody(root.path());
    let config = Config {
        auth,
        accounts: Some(accounts_config()),
        ..Config::default()
    };
    let meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
    let gateway_key = Arc::new(GatewayKeyPair::generate().expect("keygen"));
    install_account_strategies(&config, Some(&custody), &gateway_key, &meta, mode)
        .expect("install must accept this fixture configuration");
    let auth_key = format!("oauth:{PROVIDER}");
    match meta
        .account_strategies()
        .resolve(DESCRIPTOR_ID, &auth_key, caller)
        .await
    {
        Ok(_) => panic!("no grant is seeded; resolve must refuse"),
        Err(error) => error.to_string(),
    }
}

#[tokio::test]
async fn stdio_caller_with_auth_off_is_the_sole_operator() {
    let auth = AuthConfig {
        enabled: false,
        bearer_token: None,
        api_keys: Vec::new(),
        public_paths: vec!["/health".to_string()],
        client_circuit_breaker: None,
        single_user: false,
        dashboard_session: crate::config::DashboardSessionConfig::default(),
    };
    // The transport's own provenance: only the stdio module can supply the
    // mark (MIK-7272.OWNER.3).
    let caller = CallerProof::new(
        None,
        CallerProvenance::local_transport(super::super::StdioNonce::process()),
    );
    let error = resolve_under(ServeMode::Stdio, auth, caller).await;
    assert!(
        error.contains("no connected account (fail-closed)"),
        "stdio with auth off must be served as the sole operator, \
         reaching custody's own absence refusal rather than a missing-identity one; got: {error}"
    );
    assert!(
        !error.contains("carries no verified end-user identity"),
        "a stdio caller structurally cannot present a verified identity and must never be \
         asked for one; got: {error}"
    );
}

#[tokio::test]
async fn http_multiple_api_keys_never_asserts_sole_operator() {
    let auth = AuthConfig {
        enabled: true,
        bearer_token: None,
        api_keys: vec![
            api_key("keyA", b"scoped-key-a"),
            api_key("keyB", b"scoped-key-b"),
        ],
        public_paths: vec!["/health".to_string()],
        client_circuit_breaker: None,
        single_user: true,
        dashboard_session: crate::config::DashboardSessionConfig::default(),
    };
    let caller = CallerProof::new(None, CallerProvenance::classify(Some("validated-api-key")));
    let error = resolve_under(ServeMode::Http, auth, caller).await;
    assert!(
        error.contains("carries no verified end-user identity"),
        "over HTTP, two configured API keys must never share stored OAuth grants under one \
         sole-operator principal; got: {error}"
    );
    assert!(
        !error.contains("no connected account (fail-closed)"),
        "a multi-key gateway must refuse before ever attempting a mint; got: {error}"
    );
}

// ── T5/T6: the serve call sites, end to end ─────────────────────────────────
//
// T1/T2 above pass the mode by hand; these reach the installer only through
// `run_stdio_on` and `Gateway::run`, so a wrong mode at either call site
// fails here. Custody is production's `start_custody` over an initialized
// store with an EMPTY descriptor map: nothing is fetched, while the
// descriptor stays declared in `accounts`, so the installer still installs a
// managed strategy for it.

/// The account-bound capability both cases invoke.
const E2E_TOOL: &str = "drive_read";
const E2E_KEY_VAR: &str = "FIXTURE_E2E_STORE_KEY";
const E2E_SECRET_VAR: &str = "FIXTURE_E2E_CLIENT_SECRET";
/// Long enough for a loaded CI runner to boot and scan one capability file.
const E2E_ARRIVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// A tempdir holding the config, its env file, the capability and the store.
struct E2eFixture {
    _temp: tempfile::TempDir,
    root: std::path::PathBuf,
}

impl E2eFixture {
    fn new() -> Self {
        let temp = tempfile::TempDir::new().expect("fixture tempdir");
        let root = temp.path().canonicalize().expect("fixture root resolves");
        let key = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, STORE_KEY);
        crate::gateway::test_helpers::write_owner_only(
            root.join("accounts.env"),
            format!("{E2E_KEY_VAR}={key}\n{E2E_SECRET_VAR}=synthetic-secret\n"),
        )
        .expect("write the fixture env file");
        std::fs::create_dir(root.join("caps")).expect("capability dir");
        std::fs::write(
            root.join("caps").join(format!("{E2E_TOOL}.yaml")),
            format!(
                "name: {E2E_TOOL}\ndescription: Read one folder through a personal account\n\
                 auth:\n  required: true\n  type: bearer\n  key: oauth:{PROVIDER}\n  \
                 account: {DESCRIPTOR_ID}\nproviders:\n  primary:\n    service: rest\n    \
                 config:\n      base_url: http://127.0.0.1:9\n      path: /read\n      method: GET\n"
            ),
        )
        .expect("write the capability");
        Self { _temp: temp, root }
    }

    /// The gateway config: `auth_yaml` is the only part the cases differ in.
    fn config_yaml(&self, port: u16, auth_yaml: &str) -> String {
        // Joined per path, never with "/": a Windows root is a verbatim
        // `\\?\` path, where a forward slash is not a separator.
        let path = |name: &str| self.root.join(name).display().to_string();
        let (env_file, tasks, caps) = (path("accounts.env"), path("tasks"), path("caps"));
        let (records, authority) = (path("records"), path("authority"));
        format!(
            "env_files:\n  - {env_file}\n\
             server:\n  host: 127.0.0.1\n  port: {port}\n\
             {auth_yaml}\
             tasks:\n  store_dir: {tasks}\n\
             capabilities:\n  enabled: true\n  name: capabilities\n  directories:\n    - {caps}\n\
             accounts:\n  schema_version: accounts.v1\n  enabled: true\n  deployment: single_process\n  \
             instance_id: stdio-sole-operator-tests\n  store_dir: {records}\n  \
             authority_dir: {authority}\n  current_key_id: current\n  keys:\n    \
             current: env:{E2E_KEY_VAR}\n  descriptors:\n    {DESCRIPTOR_ID}:\n      \
             mode: personal_managed\n      provider: {PROVIDER}\n      \
             resource: https://wire.example.invalid/\n      \
             issuer: https://accounts.wire-fixture.invalid\n      \
             authorization_endpoint: https://accounts.wire-fixture.invalid/authorize\n      \
             token_endpoint: https://accounts.wire-fixture.invalid/token\n      \
             client_id: synthetic-client\n      client_secret_ref: env:{E2E_SECRET_VAR}\n      \
             redirect_uri: https://gateway.example.invalid/oauth/callback\n      \
             scopes:\n        - https://wire.example.invalid/read\n      \
             send_resource_parameter: false\n"
        )
    }
}

/// A gateway built the way startup builds one (config and env file evaluated
/// together), carrying production custody over an initialized, empty store.
async fn e2e_gateway(fixture: &E2eFixture, port: u16, auth_yaml: &str) -> crate::gateway::Gateway {
    let path = fixture.root.join("gateway.yaml");
    crate::gateway::test_helpers::write_owner_only(&path, fixture.config_yaml(port, auth_yaml))
        .expect("write the fixture config");
    let evaluated = Config::load_evaluated(Some(&path)).expect("the fixture config evaluates");
    let env = Arc::new(crate::config::LiveEnv::new(
        evaluated.overlay,
        evaluated.env_paths,
    ));
    let store = {
        let overlay = env.get();
        crate::personal_accounts::config::resolve(evaluated.config.accounts.as_ref(), &*overlay)
            .expect("the accounts block resolves")
            .expect("the accounts block is enabled")
            .store
    };
    drop(PersonalAccountStore::initialize(store.clone()).expect("store initializes"));
    let custody = crate::personal_accounts::start_custody(store, BTreeMap::new(), Arc::clone(&env))
        .await
        .expect("store-only custody starts without a network fetch");
    crate::gateway::Gateway::new_with_env(evaluated.config, env, Some(path))
        .await
        .expect("the fixture config builds a gateway")
        .with_data_dir(fixture.root.join("data"))
        .with_account_custody(Arc::new(custody))
}

/// The `gateway_invoke` of the account-bound capability, as JSON-RPC id 2.
fn e2e_invoke() -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "gateway_invoke", "arguments": {
            "server": "capabilities", "tool": E2E_TOOL, "arguments": {},
        }},
    })
}

fn e2e_initialize() -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "sole-operator-e2e", "version": "0"},
        },
    })
}

/// Whether `text` holds either refusal a resolve can reach, so a poll stops on
/// the WRONG one too and the assertion, not a timeout, names the failure.
fn e2e_reached_resolve(text: &str) -> bool {
    text.contains("carries no verified end-user identity")
        || text.contains("no connected account (fail-closed)")
}

#[tokio::test]
async fn stdio_run_path_serves_its_operator_the_managed_account() {
    use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _};

    let fixture = E2eFixture::new();
    let auth = "auth:\n  enabled: false\n";
    let gateway = e2e_gateway(&fixture, 0, auth).await;
    let (mut client, input) = tokio::io::duplex(64 * 1024);
    let (output, reader) = tokio::io::duplex(1 << 20);
    let task = tokio::spawn(async move { gateway.run_stdio_on(input, output, None).await });
    let mut lines = tokio::io::BufReader::new(reader).lines();
    let mut answers = Vec::new();
    for frame in [e2e_initialize(), e2e_invoke()] {
        client
            .write_all(format!("{frame}\n").as_bytes())
            .await
            .expect("write to the gateway's stdin");
        let id = frame["id"].as_i64().expect("request id");
        let answer = tokio::time::timeout(E2E_ARRIVAL, async {
            while let Some(line) = lines.next_line().await.expect("read the gateway's stdout") {
                let reply: serde_json::Value =
                    serde_json::from_str(&line).expect("one JSON frame per line");
                if reply["id"].as_i64() == Some(id) && reply.get("method").is_none() {
                    return Some(reply);
                }
            }
            None
        })
        .await
        .unwrap_or_else(|_| panic!("no response to request {id}"));
        let Some(answer) = answer else {
            // Stdout closed: the serve loop ended, and its own error says why.
            panic!("the stdio loop ended early: {:?}", task.await);
        };
        answers.push(answer);
    }
    drop(client);
    drop(tokio::time::timeout(E2E_ARRIVAL, task).await);
    let invoked = answers[1].to_string();
    assert!(
        e2e_reached_resolve(&invoked),
        "the call must reach the account resolve; got: {invoked}"
    );
    assert!(
        !invoked.contains("carries no verified end-user identity"),
        "a stdio gateway is spawned by its one operator and must not ask it for a \
         verified identity (the stdio call site installs ServeMode::Stdio); got: {invoked}"
    );
    assert!(
        invoked.contains("no connected account (fail-closed)"),
        "the operator reaches custody, which has no grant seeded; got: {invoked}"
    );
}

/// One `/mcp` POST as caller A. Returns the session id it was given and the
/// raw body, so a JSON and an SSE answer are read the same way.
async fn e2e_post(
    client: &reqwest::Client,
    port: u16,
    session: Option<&str>,
    frame: &serde_json::Value,
) -> (Option<String>, String) {
    let mut request = client
        .post(format!("http://127.0.0.1:{port}/mcp"))
        .bearer_auth("scoped-key-a")
        .header("accept", "application/json, text/event-stream")
        .json(frame);
    if let Some(session) = session {
        request = request.header("mcp-session-id", session);
    }
    let response = request.send().await.expect("the gateway answers /mcp");
    let session = response
        .headers()
        .get("mcp-session-id")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let status = response.status();
    let body = response.text().await.expect("read the /mcp body");
    (session, format!("HTTP {status}: {body}"))
}

#[tokio::test]
async fn http_run_path_refuses_a_multi_key_caller_the_managed_account() {
    let fixture = E2eFixture::new();
    let auth = format!(
        "auth:\n  enabled: true\n  single_user: true\n  api_keys:\n    \
         - name: keyA\n      key_sha256: \"{}\"\n      backends: [\"*\"]\n    \
         - name: keyB\n      key_sha256: \"{}\"\n      backends: [\"*\"]\n\
         security:\n  transparency_log:\n    enabled: true\n    path: {}\n",
        api_key_digest_spec(b"scoped-key-a"),
        api_key_digest_spec(b"scoped-key-b"),
        // Auth on requires a working audit log (UPGRADING-4.0 item 43).
        fixture.root.join("audit.jsonl").display(),
    );
    // Port 0: the gateway reports the port it bound (MIK-7984).
    let mut gateway = e2e_gateway(&fixture, 0, &auth).await;
    let bound = gateway.bound_port_for_test();
    let server = tokio::spawn(async move { Box::pin(gateway.run()).await });
    let port = tokio::time::timeout(E2E_ARRIVAL, bound)
        .await
        .expect("the HTTP gateway bound a port")
        .expect("the gateway reports the port it bound");
    let client = reqwest::Client::new();
    // Polled: the listener binds and the capability scan runs after spawn, so
    // an early call can miss the tool. Stops on EITHER refusal.
    let mut last = String::from("(no /mcp answer yet)");
    let invoked = tokio::time::timeout(E2E_ARRIVAL, async {
        loop {
            if let Ok(response) = client
                .get(format!("http://127.0.0.1:{port}/livez"))
                .send()
                .await
                && response.status().is_success()
            {
                let (session, _) = e2e_post(&client, port, None, &e2e_initialize()).await;
                let (_, body) = e2e_post(&client, port, session.as_deref(), &e2e_invoke()).await;
                if e2e_reached_resolve(&body) {
                    return body;
                }
                last = body;
            }
            assert!(
                !server.is_finished(),
                "the HTTP gateway stopped while booting"
            );
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("the call never reached the account resolve; last: {last}"));
    server.abort();
    drop(server.await);
    assert!(
        invoked.contains("carries no verified end-user identity"),
        "over HTTP, two configured API keys must never share stored OAuth grants under one \
         sole-operator principal (the HTTP call site installs ServeMode::Http); got: {invoked}"
    );
    assert!(
        !invoked.contains("no connected account (fail-closed)"),
        "a multi-key gateway must refuse before ever attempting a mint; got: {invoked}"
    );
}

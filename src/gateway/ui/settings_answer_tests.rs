// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Each refusal has its own test; the first red row cannot hide the rest.
use super::{test_support::decode, *};
use crate::config_persistence::keyedit::{GiveUp, Segment};
use crate::config_reload::ui_fields::FieldId;
use crate::config_reload::{FileRevision, RefusalClass};
use crate::config_reload::{Patch, PatchStep, PreviewRefused, Shown, UiPreview, UiRefused};
use axum::http::{StatusCode, header::RETRY_AFTER};

const CANARY: &str = "answer-payload-canary";
fn field() -> FieldId {
    FieldId::of("environment").expect("field")
}
fn patch() -> Patch {
    Patch {
        code: GiveUp::Anchor,
        reason: CANARY.into(),
        line: None,
        steps: vec![PatchStep::SetSecret {
            path: vec![
                Segment::Key("auth".into()),
                Segment::Key("bearer_token".into()),
            ],
        }],
    }
}
async fn check(refusal: UiRefused, status: StatusCode, code: &str, retry: bool) {
    let response = answer(refusal);
    assert_eq!(response.status(), status, "shared answer status");
    assert_eq!(response.headers().contains_key(RETRY_AFTER), retry);
    if retry {
        let header = response.headers().get(RETRY_AFTER).expect("Retry-After");
        assert!(
            header
                .to_str()
                .expect("ASCII")
                .parse::<u64>()
                .expect("retry seconds")
                > 0
        );
    }
    let (_, body) = decode(response).await;
    assert_eq!(body["error"], code, "{body}");
    if matches!(
        code,
        "the config write is recovering; retry"
            | "the config is being written; retry"
            | "the secret store did not answer; retry"
            | "the secret store refused the value"
    ) {
        assert_eq!(body, json!({"error": code}));
    }
    assert!(
        !body.to_string().contains(CANARY),
        "free text escaped: {body}"
    );
}
macro_rules! row {
    ($name:ident, $refusal:expr, $status:ident, $code:expr, $retry:expr) => {
        #[doc = concat!("Red oracle: ", stringify!($name), " maps to ", stringify!($status), ", its code and retry contract, without payload text.")]
        #[tokio::test]
        async fn $name() { check($refusal, StatusCode::$status, $code, $retry).await; }
    };
}
row!(
    wrong_kind,
    UiRefused::WrongKind(field()),
    UNPROCESSABLE_ENTITY,
    "wrong_kind",
    false
);
row!(
    bad_value,
    UiRefused::BadValue(field(), CANARY.into()),
    UNPROCESSABLE_ENTITY,
    "bad_value",
    false
);
row!(
    bad_param,
    UiRefused::BadParam(field(), CANARY.into()),
    UNPROCESSABLE_ENTITY,
    "bad_param",
    false
);
row!(
    invalid,
    UiRefused::Invalid(CANARY.into()),
    UNPROCESSABLE_ENTITY,
    "invalid",
    false
);
row!(
    posture,
    UiRefused::ReloadRefused {
        class: RefusalClass::Posture
    },
    CONFLICT,
    "posture_refused",
    false
);
row!(
    reload_invalid,
    UiRefused::ReloadRefused {
        class: RefusalClass::Invalid
    },
    UNPROCESSABLE_ENTITY,
    "invalid",
    false
);
row!(
    shutting_down,
    UiRefused::ReloadRefused {
        class: RefusalClass::ShuttingDown
    },
    SERVICE_UNAVAILABLE,
    "shutting_down",
    true
);
row!(
    internal,
    UiRefused::ReloadRefused {
        class: RefusalClass::Internal
    },
    INTERNAL_SERVER_ERROR,
    "failed",
    false
);
row!(
    unsupported,
    UiRefused::Unsupported(CANARY.into()),
    CONFLICT,
    "unsupported",
    false
);
row!(
    no_audit_log,
    UiRefused::NoAuditLog,
    SERVICE_UNAVAILABLE,
    "audit_log_required",
    false
);
row!(
    unprovable,
    UiRefused::Unprovable(patch()),
    UNPROCESSABLE_ENTITY,
    "not_in_place",
    false
);
row!(
    stale,
    UiRefused::Stale(Box::new(UiPreview {
        revision: FileRevision::of(b"current"),
        shown: Shown::Patch(patch())
    })),
    CONFLICT,
    "stale",
    false
);
row!(
    stale_unpreviewable,
    UiRefused::StaleUnpreviewable(CANARY.into()),
    SERVICE_UNAVAILABLE,
    "stale",
    true
);
row!(
    recovering,
    UiRefused::Preview(PreviewRefused::Recovering),
    SERVICE_UNAVAILABLE,
    "the config write is recovering; retry",
    true
);
row!(
    no_config_file,
    UiRefused::Preview(PreviewRefused::NoConfigFile),
    CONFLICT,
    "no_config_file",
    false
);
row!(
    untrusted,
    UiRefused::Preview(PreviewRefused::Untrusted(CANARY.into())),
    SERVICE_UNAVAILABLE,
    "gateway.yaml could not be loaded",
    false
);
row!(
    unread,
    UiRefused::Preview(PreviewRefused::Unread(CANARY.into())),
    SERVICE_UNAVAILABLE,
    "gateway.yaml could not be loaded",
    false
);
row!(
    busy,
    UiRefused::Busy,
    CONFLICT,
    "the config is being written; retry",
    true
);
row!(
    secret_timeout,
    UiRefused::SecretsRefused { timeout: true },
    SERVICE_UNAVAILABLE,
    "the secret store did not answer; retry",
    true
);
row!(
    secret_refused,
    UiRefused::SecretsRefused { timeout: false },
    UNPROCESSABLE_ENTITY,
    "the secret store refused the value",
    false
);
row!(
    failed,
    UiRefused::Failed(CANARY.into()),
    INTERNAL_SERVER_ERROR,
    "failed",
    false
);

async fn constructor(why: super::super::secret_slots::Unopened, status: StatusCode) {
    let Err(response) = secret_target(Err(why)) else {
        panic!("a failed open produced a target");
    };
    assert_eq!(
        response.headers().contains_key(RETRY_AFTER),
        status == StatusCode::SERVICE_UNAVAILABLE,
    );
    let (got, body) = decode(*response).await;
    if status == StatusCode::SERVICE_UNAVAILABLE {
        assert_eq!(
            body,
            json!({"error": "the secret store did not answer; retry"})
        );
    }
    assert_eq!(got, status, "{body}");
    assert!(!body.to_string().contains(CANARY));
}
/// Red oracle: an unavailable opener is 422.
#[tokio::test]
async fn unopened_unavailable() {
    constructor(
        super::super::secret_slots::Unopened::Unavailable,
        StatusCode::UNPROCESSABLE_ENTITY,
    )
    .await;
}
/// Red oracle: an operational opener failure is 500.
#[tokio::test]
async fn unopened_failed() {
    constructor(
        super::super::secret_slots::Unopened::Failed,
        StatusCode::INTERNAL_SERVER_ERROR,
    )
    .await;
}
/// Red oracle: a timed-out opener is 503.
#[tokio::test]
async fn unopened_timed_out() {
    constructor(
        super::super::secret_slots::Unopened::TimedOut,
        StatusCode::SERVICE_UNAVAILABLE,
    )
    .await;
}
/// Red oracle: a vault error is 500 and never includes its diagnostic payload.
#[tokio::test]
async fn vault_failed() {
    let dir = tempfile::tempdir().expect("dir");
    let store: super::super::secret_slots::Store =
        Arc::new(crate::secret_store::FilesStore::new(dir.path()));
    let Err(response) = secret_target(Ok((
        store,
        Err(crate::secret_store::StoreError::Failed(CANARY.into())),
    ))) else {
        panic!("a failed vault produced a target");
    };
    let (status, body) = decode(*response).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
    assert!(!body.to_string().contains(CANARY));
}

/// A write route with no reload context attempted nothing: 409, same body, no
/// Retry-After. The diff route, which writes nothing, keeps the 503 below.
#[tokio::test]
async fn reload_not_enabled_on_a_write() {
    let (status, body) = decode(write_unavailable()).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(
        body,
        json!({"error": "Config reload is not enabled on this gateway"})
    );
}

#[tokio::test]
async fn reload_not_enabled() {
    let response = unavailable();
    assert!(!response.headers().contains_key(RETRY_AFTER));
    let (status, body) = decode(response).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        body,
        json!({"error": "Config reload is not enabled on this gateway"})
    );
}

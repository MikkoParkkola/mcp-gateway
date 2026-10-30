// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! [`Guard`]: how every web UI API handler admits its caller, from the row
//! [`super::access_table`] holds for the matched route.
//!
//! The extractor never refuses. A handler calls [`Guard::admit`] (or the
//! Activity and control-plane forms) at the line its own check always stood,
//! so a malformed body still answers 415 or 422 before any refusal, and a
//! control-plane store that is down still answers 503 first. A route with no
//! row is refused: a lookup miss never admits.

use std::convert::Infallible;

use axum::Json;
use axum::extract::{FromRequestParts, MatchedPath};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use serde_json::Value;

use super::access_table::{self, AdminShape, CpCheck, Need, Row};
use super::errors::{admin_auth_required, auth_required};
use crate::gateway::auth::AuthenticatedClient;
use crate::key_server::oidc::VerifiedIdentity;
use crate::security::audit::CredentialKind;

/// The caller, and the row of the route it called.
pub(super) struct Guard {
    pub(super) client: Option<AuthenticatedClient>,
    pub(super) identity: Option<VerifiedIdentity>,
    row: Option<&'static Row>,
    #[cfg(test)]
    probe: Option<std::sync::Arc<probe::Probe>>,
}

impl<S: Send + Sync> FromRequestParts<S> for Guard {
    type Rejection = Infallible;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Infallible>> + Send {
        let row = parts
            .extensions
            .get::<MatchedPath>()
            .and_then(|path| access_table::row_for(path.as_str(), &parts.method));
        std::future::ready(Ok(Self {
            client: parts.extensions.get::<AuthenticatedClient>().cloned(),
            identity: parts.extensions.get::<VerifiedIdentity>().cloned(),
            row,
            #[cfg(test)]
            probe: parts
                .extensions
                .get::<std::sync::Arc<probe::Probe>>()
                .cloned(),
        }))
    }
}

/// The verdict for the needs that read the caller alone (admin kinds and
/// open routes): what [`Guard::admit`] enforces and the status report shows.
/// Activity and control-plane needs are refused here; they admit through
/// their own resolvers.
pub(super) fn decide(need: Need, client: Option<&AuthenticatedClient>) -> Result<(), Refused> {
    let admin = super::is_admin(client);
    match need {
        Need::Open => Ok(()),
        Need::Admin(shape) => admin.then_some(()).ok_or(shape.into()),
        Need::AdminSplit => match client {
            None => Err(Refused::Unauthorized),
            Some(c) if !c.admin => Err(Refused::AdminRequired),
            Some(_) => Ok(()),
        },
        Need::AdminKeyLink => client
            .is_some_and(|c| {
                c.admin
                    && (c.credential_kind == CredentialKind::StaticBearer
                        || c.api_key_identity().is_some())
            })
            .then_some(())
            .ok_or(Refused::AdminRequired),
        Need::ActivityReader | Need::ControlPlane(_) => Err(Refused::AdminRequired),
    }
}

/// A handler's early answer: boxed, as a `Response` is large.
pub(super) type Early = Box<Response>;

/// Why a caller was refused, rendered as the route always rendered it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Refused {
    /// `admin_auth_required()`.
    AdminRequired,
    /// `auth_required(403)`.
    Forbidden,
    /// `auth_required(401)`.
    Unauthorized,
    /// The dashboard page's HTML refusal, which its handler renders.
    Html,
}

impl From<AdminShape> for Refused {
    fn from(shape: AdminShape) -> Self {
        match shape {
            AdminShape::AdminRequired => Self::AdminRequired,
            AdminShape::Forbidden => Self::Forbidden,
            #[cfg(feature = "cost-governance")]
            AdminShape::Unauthorized => Self::Unauthorized,
            AdminShape::Html => Self::Html,
        }
    }
}

impl IntoResponse for Refused {
    fn into_response(self) -> Response {
        let (status, body): (StatusCode, Json<Value>) = match self {
            // The dashboard renders its own page; anything else that reaches
            // here refuses as an admin route does.
            Self::AdminRequired | Self::Html => admin_auth_required(),
            Self::Forbidden => auth_required(StatusCode::FORBIDDEN),
            Self::Unauthorized => auth_required(StatusCode::UNAUTHORIZED),
        };
        (status, body).into_response()
    }
}

impl Guard {
    /// A guard for `path` and `method` as the extractor would build it, for
    /// tests that call a handler directly.
    #[cfg(test)]
    pub(super) fn for_route(
        path: &str,
        method: &axum::http::Method,
        client: Option<AuthenticatedClient>,
    ) -> Self {
        Self {
            client,
            identity: None,
            row: access_table::row_for(path, method),
            probe: None,
        }
    }

    /// Admit the caller to an admin route (or an open one), or refuse it with
    /// the route's own refusal. A route with no row, or whose row is admitted
    /// through another form, is refused.
    pub(super) fn admit(&self) -> Result<(), Refused> {
        self.mark_admitted();
        let Some(row) = self.row else {
            return Err(Refused::AdminRequired);
        };
        decide(row.need, self.client.as_ref())
    }

    /// Admit an Activity caller through Activity's own resolver, which gives
    /// the scope the handler then reads with. Refused on any other row.
    pub(super) fn admit_activity<T>(
        &self,
        resolve: impl FnOnce(
            Option<&AuthenticatedClient>,
            Option<&VerifiedIdentity>,
        ) -> Result<T, Early>,
    ) -> Result<T, Early> {
        self.mark_admitted();
        match self.row.map(|r| r.need) {
            Some(Need::ActivityReader) => resolve(self.client.as_ref(), self.identity.as_ref()),
            _ => Err(Box::new(Refused::AdminRequired.into_response())),
        }
    }

    /// Admit a control-plane caller: `resolve` derives the actor, as the
    /// handler always did, and is told what the row checks, so the action a
    /// handler authorizes comes from the table. Refused on any other row.
    pub(super) fn admit_control_plane<T>(
        &self,
        resolve: impl FnOnce(
            Option<&AuthenticatedClient>,
            Option<&VerifiedIdentity>,
            CpCheck,
        ) -> Result<T, Early>,
    ) -> Result<T, Early> {
        self.mark_admitted();
        match self.row.map(|r| r.need) {
            Some(Need::ControlPlane(check)) => {
                resolve(self.client.as_ref(), self.identity.as_ref(), check)
            }
            _ => Err(Box::new(Refused::AdminRequired.into_response())),
        }
    }

    #[cfg_attr(
        not(test),
        expect(
            clippy::unused_self,
            reason = "the probe it marks exists in test builds only"
        )
    )]
    fn mark_admitted(&self) {
        #[cfg(test)]
        if let Some(probe) = &self.probe {
            probe.admitted();
        }
    }
}

/// Test builds only: a handler that answers without admitting its caller
/// fails the test that sent the request.
#[cfg(test)]
pub(super) mod probe {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use axum::extract::{MatchedPath, Request};
    use axum::middleware::Next;
    use axum::response::Response;

    use super::super::access_table::{self, Need};

    #[derive(Default)]
    pub(in crate::gateway::ui) struct Probe {
        admitted: AtomicBool,
    }

    impl Probe {
        pub(super) fn admitted(&self) {
            self.admitted.store(true, Ordering::SeqCst);
        }
    }

    /// Statuses an answer can carry without the handler having run its
    /// admission: refusals, and the extractor rejections axum answers itself.
    const UNADMITTED_OK: &[u16] = &[400, 401, 403, 405, 415, 422];

    /// The layer: panics on an answer a guarded handler gave unadmitted.
    pub(in crate::gateway::ui) async fn layer(mut request: Request, next: Next) -> Response {
        let probe = Arc::new(Probe::default());
        let row = request
            .extensions()
            .get::<MatchedPath>()
            .and_then(|path| access_table::row_for(path.as_str(), request.method()));
        let what = format!("{} {}", request.method(), request.uri().path());
        request.extensions_mut().insert(Arc::clone(&probe));
        let response = next.run(request).await;
        let guarded = row.is_some_and(|r| r.need != Need::Open);
        let status = response.status().as_u16();
        assert!(
            !guarded || probe.admitted.load(Ordering::SeqCst) || UNADMITTED_OK.contains(&status),
            "{what} answered {status} without admitting its caller through the Guard"
        );
        response
    }
}

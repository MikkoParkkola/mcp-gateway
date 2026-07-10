// SPDX-License-Identifier: MIT

//! Canonical projection schema (MIK-3530 / MIK-3531).
//!
//! The gateway proxies the union of many heterogeneous backend tool surfaces
//! (linear, github, gws-*, slack, hebb, ...). The same concept wears different
//! field names across them — an "actor" is `assignee.email` on one backend,
//! `user.login` on another, `organizer.email` on a third. This module defines a
//! small canonical vocabulary those shapes can be projected onto so agents see
//! consistent fields.
//!
//! Projection is never lossy: [`Projected`] always pairs the canonical view with
//! the untouched backend payload under `_raw`.
//!
//! This module is the foundation (MIK-3531). It defines the types and their
//! serialization contract only; the projection *logic* that maps a backend
//! response onto these shapes via a [`ProjectionSpec`] lands in subsequent PRs
//! (MIK-3533 / MIK-3534).

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A canonical actor: assignee / author / organizer / sender / user.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Actor {
    /// Stable identifier, if the backend exposes one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Human-readable display name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Email address, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Handle / login / username, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
}

/// A canonical subject: the primary entity a tool result is about (issue, PR,
/// event, message, ...).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subject {
    /// Stable identifier of the subject.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Human-readable title / summary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Backend-specific kind (e.g. `issue`, `pull_request`, `event`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}

/// Canonical timestamps for an entity. Values are RFC-3339 strings as emitted
/// by the backend; they are not re-parsed here.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvTime {
    /// Creation timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
    /// Last-updated timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated: Option<String>,
}

/// A canonical URL: a link plus an optional human-readable label.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Url {
    /// The link target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub href: Option<String>,
    /// Optional display label for the link.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// A canonical body: free-text content plus its format hint.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Body {
    /// The body text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// Format hint (e.g. `markdown`, `plain`, `html`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
}

/// A projected canonical view `T` paired with the untouched backend payload.
///
/// Projection must never drop data a caller might need, so the original
/// response is always preserved under `_raw`. The canonical fields of `T` are
/// flattened alongside `_raw` in the serialized form.
///
/// `T` must be a struct/map-like type whose serialized form is a JSON object
/// (all the canonical views in this module qualify); flattening a scalar or
/// array view is not supported by serde and is not a valid projection target.
/// The top-level `_raw` key is reserved for the wrapper — a canonical view must
/// not itself serialize a field named `_raw`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Projected<T> {
    /// The canonical projected view.
    #[serde(flatten)]
    pub view: T,
    /// The untouched backend payload.
    #[serde(rename = "_raw")]
    pub raw: Value,
}

impl<T> Projected<T> {
    /// Wrap a canonical view together with the raw backend payload it was
    /// derived from.
    pub fn new(view: T, raw: Value) -> Self {
        Self { view, raw }
    }
}

/// Per-field source paths for projecting an [`Actor`]. Each field is the dotted
/// JSON path into the backend payload that supplies the corresponding canonical
/// field (e.g. `email: Some("assignee.email")`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActorSpec {
    /// Source path for [`Actor::id`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Source path for [`Actor::display_name`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Source path for [`Actor::email`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Source path for [`Actor::handle`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
}

/// Per-field source paths for projecting a [`Subject`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubjectSpec {
    /// Source path for [`Subject::id`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Source path for [`Subject::title`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Source path for [`Subject::kind`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}

/// Per-field source paths for projecting [`EnvTime`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvTimeSpec {
    /// Source path for [`EnvTime::created`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
    /// Source path for [`EnvTime::updated`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated: Option<String>,
}

/// Per-field source paths for projecting a [`Url`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UrlSpec {
    /// Source path for [`Url::href`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub href: Option<String>,
    /// Source path for [`Url::label`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// Per-field source paths for projecting a [`Body`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BodySpec {
    /// Source path for [`Body::text`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// Source path for [`Body::format`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
}

/// Declarative, **per-field** mapping from canonical fields to source paths in a
/// backend response. A `None` bucket means "this backend does not expose that
/// concept"; within a bucket, a `None` field means that specific canonical
/// field has no source.
///
/// Per-field (rather than per-bucket) mapping is deliberate: the motivating
/// cases are leaf mappings such as `assignee.email` → [`Actor::email`] and
/// `user.login` → [`Actor::handle`], which a single path-per-bucket spec could
/// not express. This is the *specification* consumed by the projection logic in
/// later PRs; this foundation PR defines the shape and its serialization only.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectionSpec {
    /// Field mapping for the [`Actor`] bucket.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<ActorSpec>,
    /// Field mapping for the [`Subject`] bucket.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<SubjectSpec>,
    /// Field mapping for the [`EnvTime`] bucket.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env_time: Option<EnvTimeSpec>,
    /// Field mapping for the [`Url`] bucket.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<UrlSpec>,
    /// Field mapping for the [`Body`] bucket.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<BodySpec>,
}

#[cfg(test)]
mod tests {
    use super::{
        Actor, ActorSpec, Body, EnvTime, Projected, ProjectionSpec, Subject, SubjectSpec, Url,
    };
    use serde_json::json;

    #[test]
    fn empty_canonical_types_serialize_to_empty_objects() {
        // skip_serializing_if = none means an all-default value is `{}`.
        assert_eq!(serde_json::to_value(Actor::default()).unwrap(), json!({}));
        assert_eq!(serde_json::to_value(Subject::default()).unwrap(), json!({}));
        assert_eq!(serde_json::to_value(EnvTime::default()).unwrap(), json!({}));
        assert_eq!(serde_json::to_value(Url::default()).unwrap(), json!({}));
        assert_eq!(serde_json::to_value(Body::default()).unwrap(), json!({}));
        assert_eq!(
            serde_json::to_value(ProjectionSpec::default()).unwrap(),
            json!({})
        );
    }

    #[test]
    fn actor_round_trips() {
        let actor = Actor {
            id: Some("u1".into()),
            display_name: Some("Alice".into()),
            email: Some("alice@example.com".into()),
            handle: Some("alice".into()),
        };
        let json = serde_json::to_value(&actor).unwrap();
        let back: Actor = serde_json::from_value(json).unwrap();
        assert_eq!(actor, back);
    }

    #[test]
    fn projected_flattens_view_and_preserves_raw() {
        let raw = json!({"assignee": {"email": "alice@example.com"}, "extra": 42});
        let view = Actor {
            email: Some("alice@example.com".into()),
            ..Default::default()
        };
        let projected = Projected::new(view, raw.clone());

        let serialized = serde_json::to_value(&projected).unwrap();
        // Canonical field is flattened to the top level...
        assert_eq!(serialized["email"], json!("alice@example.com"));
        // ...and the untouched payload is preserved under `_raw`.
        assert_eq!(serialized["_raw"], raw);

        let back: Projected<Actor> = serde_json::from_value(serialized).unwrap();
        assert_eq!(back, projected);
    }

    #[test]
    fn projection_spec_round_trips() {
        // Leaf mappings: assignee.email -> Actor.email, user.login -> Actor.handle.
        let spec = ProjectionSpec {
            actor: Some(ActorSpec {
                email: Some("assignee.email".into()),
                handle: Some("user.login".into()),
                ..Default::default()
            }),
            subject: Some(SubjectSpec {
                title: Some("issue.title".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let json = serde_json::to_value(&spec).unwrap();
        assert_eq!(
            json,
            json!({
                "actor": {"email": "assignee.email", "handle": "user.login"},
                "subject": {"title": "issue.title"}
            })
        );
        let back: ProjectionSpec = serde_json::from_value(json).unwrap();
        assert_eq!(spec, back);
    }
}

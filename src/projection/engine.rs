//! Projection engine (MIK-3533): map a backend response onto the canonical
//! schema described by a [`ProjectionSpec`], always preserving the original
//! payload under `_raw`.
//!
//! This is the logic half of the projection layer. The types live in
//! [`super::schema`]; this module turns a `(response, spec)` pair into a
//! projected value.
//!
//! **Fail-fast:** if a spec resolves *no* canonical fields against a response
//! (every mapped source path is absent), [`project`] returns the original
//! response unchanged rather than handing the caller an empty projection. A
//! projection must never silently drop a caller's data.

use serde_json::{Map, Value};

use super::schema::{ActorSpec, BodySpec, EnvTimeSpec, ProjectionSpec, SubjectSpec, UrlSpec};

/// Resolve a dotted JSON path (e.g. `assignee.email`) against `root`. Returns
/// `None` if any path segment is missing.
fn resolve_path<'a>(root: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = root;
    for segment in path.split('.') {
        current = current.get(segment)?;
    }
    Some(current)
}

/// Resolve an optional source path to a scalar string. Strings pass through;
/// numbers and booleans are stringified; everything else (objects, arrays,
/// null, or an absent path) yields `None`.
fn resolve_scalar(root: &Value, path: Option<&String>) -> Option<String> {
    let value = resolve_path(root, path?)?;
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// Insert `key: value` into `map` when `value` is `Some`. Returns whether a
/// value was inserted (so the caller can track whether anything was projected).
fn insert_opt(map: &mut Map<String, Value>, key: &str, value: Option<String>) -> bool {
    if let Some(v) = value {
        map.insert(key.to_string(), Value::String(v));
        true
    } else {
        false
    }
}

/// Build one canonical bucket object from a per-field spec. Returns `None` when
/// the spec is absent or resolves no fields, so empty buckets are omitted.
fn project_bucket<F>(root: &Value, present: &mut bool, build: F) -> Option<Value>
where
    F: FnOnce(&Value, &mut Map<String, Value>) -> bool,
{
    let mut obj = Map::new();
    let any = build(root, &mut obj);
    if any {
        *present = true;
        Some(Value::Object(obj))
    } else {
        None
    }
}

/// Project `response` onto the canonical schema per `spec`.
///
/// The result is an object with the populated canonical buckets (`actor`,
/// `subject`, `env_time`, `url`, `body`) plus `_raw` holding the original
/// response. If nothing maps, the original `response` is returned unchanged
/// (fail-fast).
#[must_use]
pub fn project(response: &Value, spec: &ProjectionSpec) -> Value {
    let mut present = false;
    let mut out = Map::new();

    if let Some(actor) = spec.actor.as_ref()
        && let Some(v) = project_bucket(response, &mut present, |r, m| build_actor(r, actor, m))
    {
        out.insert("actor".to_string(), v);
    }
    if let Some(subject) = spec.subject.as_ref()
        && let Some(v) = project_bucket(response, &mut present, |r, m| build_subject(r, subject, m))
    {
        out.insert("subject".to_string(), v);
    }
    if let Some(env_time) = spec.env_time.as_ref()
        && let Some(v) = project_bucket(response, &mut present, |r, m| {
            build_env_time(r, env_time, m)
        })
    {
        out.insert("env_time".to_string(), v);
    }
    if let Some(url) = spec.url.as_ref()
        && let Some(v) = project_bucket(response, &mut present, |r, m| build_url(r, url, m))
    {
        out.insert("url".to_string(), v);
    }
    if let Some(body) = spec.body.as_ref()
        && let Some(v) = project_bucket(response, &mut present, |r, m| build_body(r, body, m))
    {
        out.insert("body".to_string(), v);
    }

    if !present {
        // Fail-fast: nothing mapped — return the untouched response rather than
        // an empty projection.
        return response.clone();
    }

    out.insert("_raw".to_string(), response.clone());
    Value::Object(out)
}

fn build_actor(r: &Value, s: &ActorSpec, m: &mut Map<String, Value>) -> bool {
    let mut any = false;
    any |= insert_opt(m, "id", resolve_scalar(r, s.id.as_ref()));
    any |= insert_opt(
        m,
        "display_name",
        resolve_scalar(r, s.display_name.as_ref()),
    );
    any |= insert_opt(m, "email", resolve_scalar(r, s.email.as_ref()));
    any |= insert_opt(m, "handle", resolve_scalar(r, s.handle.as_ref()));
    any
}

fn build_subject(r: &Value, s: &SubjectSpec, m: &mut Map<String, Value>) -> bool {
    let mut any = false;
    any |= insert_opt(m, "id", resolve_scalar(r, s.id.as_ref()));
    any |= insert_opt(m, "title", resolve_scalar(r, s.title.as_ref()));
    any |= insert_opt(m, "kind", resolve_scalar(r, s.kind.as_ref()));
    any
}

fn build_env_time(r: &Value, s: &EnvTimeSpec, m: &mut Map<String, Value>) -> bool {
    let mut any = false;
    any |= insert_opt(m, "created", resolve_scalar(r, s.created.as_ref()));
    any |= insert_opt(m, "updated", resolve_scalar(r, s.updated.as_ref()));
    any
}

fn build_url(r: &Value, s: &UrlSpec, m: &mut Map<String, Value>) -> bool {
    let mut any = false;
    any |= insert_opt(m, "href", resolve_scalar(r, s.href.as_ref()));
    any |= insert_opt(m, "label", resolve_scalar(r, s.label.as_ref()));
    any
}

fn build_body(r: &Value, s: &BodySpec, m: &mut Map<String, Value>) -> bool {
    let mut any = false;
    any |= insert_opt(m, "text", resolve_scalar(r, s.text.as_ref()));
    any |= insert_opt(m, "format", resolve_scalar(r, s.format.as_ref()));
    any
}

#[cfg(test)]
mod tests {
    use super::project;
    use crate::projection::schema::{ActorSpec, ProjectionSpec, SubjectSpec, UrlSpec};
    use serde_json::json;

    fn linear_like() -> serde_json::Value {
        json!({
            "assignee": {"email": "alice@example.com", "login": "alice"},
            "issue": {"id": "ISS-1", "title": "Fix the bug"},
            "url": "https://linear.app/x/ISS-1",
            "noise": {"secret": "xyz"}
        })
    }

    #[test]
    fn projects_leaf_paths_onto_canonical_buckets() {
        let spec = ProjectionSpec {
            actor: Some(ActorSpec {
                email: Some("assignee.email".into()),
                handle: Some("assignee.login".into()),
                ..Default::default()
            }),
            subject: Some(SubjectSpec {
                id: Some("issue.id".into()),
                title: Some("issue.title".into()),
                ..Default::default()
            }),
            url: Some(UrlSpec {
                href: Some("url".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let raw = linear_like();
        let out = project(&raw, &spec);

        assert_eq!(out["actor"]["email"], json!("alice@example.com"));
        assert_eq!(out["actor"]["handle"], json!("alice"));
        assert_eq!(out["subject"]["id"], json!("ISS-1"));
        assert_eq!(out["subject"]["title"], json!("Fix the bug"));
        assert_eq!(out["url"]["href"], json!("https://linear.app/x/ISS-1"));
        // _raw always preserves the full payload (incl. fields not projected).
        assert_eq!(out["_raw"], raw);
        assert_eq!(out["_raw"]["noise"]["secret"], json!("xyz"));
        // Buckets with no resolved fields are omitted.
        assert!(out.get("env_time").is_none());
        assert!(out.get("body").is_none());
    }

    #[test]
    fn fail_fast_returns_raw_when_nothing_maps() {
        // Spec points at fields absent from this response.
        let spec = ProjectionSpec {
            actor: Some(ActorSpec {
                email: Some("nonexistent.path".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let raw = json!({"id": "x", "name": "y"});
        let out = project(&raw, &spec);
        // No canonical field resolved -> return the response unchanged.
        assert_eq!(out, raw);
        assert!(
            out.get("_raw").is_none(),
            "no projection wrapper when nothing maps"
        );
    }

    #[test]
    fn empty_spec_returns_raw() {
        let raw = json!({"a": 1});
        assert_eq!(project(&raw, &ProjectionSpec::default()), raw);
    }

    #[test]
    fn partial_resolution_still_projects_and_preserves_raw() {
        // One field resolves, one does not — the resolved one is projected,
        // the missing one is simply absent, and _raw is preserved.
        let spec = ProjectionSpec {
            actor: Some(ActorSpec {
                email: Some("assignee.email".into()),
                id: Some("assignee.missing".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let raw = linear_like();
        let out = project(&raw, &spec);
        assert_eq!(out["actor"]["email"], json!("alice@example.com"));
        assert!(out["actor"].get("id").is_none());
        assert_eq!(out["_raw"], raw);
    }

    #[test]
    fn stringifies_numbers_and_bools() {
        let spec = ProjectionSpec {
            subject: Some(SubjectSpec {
                id: Some("n".into()),
                kind: Some("flag".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let raw = json!({"n": 42, "flag": true});
        let out = project(&raw, &spec);
        assert_eq!(out["subject"]["id"], json!("42"));
        assert_eq!(out["subject"]["kind"], json!("true"));
    }
}

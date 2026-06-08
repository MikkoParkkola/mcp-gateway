//! Backend-result → [`EvidenceState`] adapter (spike MIK-5854, EVGUARD.1).
//!
//! This is the **additive** glue that maps a gateway backend invocation outcome
//! onto the typed evidence model. It is pure and deterministic, depends only on
//! the existing [`crate::error::Error`] enum and `serde_json::Value`, and is
//! **not** wired into any production invoke / result-proxy path — wiring is a
//! later phase (attach a `SourceId` at the invoke boundary and route the result
//! here before the result is assembled).
//!
//! The mapping is the load-bearing decision of the whole apparatus: it is where a
//! *failure to check* is kept categorically distinct from an *authoritative
//! negative*. A transport error, a timeout, a missing backend, or an auth refusal
//! all become "could-not-check" variants; only a genuine empty-but-successful
//! response becomes [`EvidenceState::CheckedNoHit`].

use serde_json::Value;

use crate::error::Error;

use super::state::{EvidenceState, SourceId};

/// True when an MCP tool result carries a tool-level error (`isError: true`).
///
/// MCP backends can return a *successful transport response* whose body reports
/// a tool error. That is a failure to obtain an authoritative answer, not a
/// negative finding, so it must not be read as [`EvidenceState::CheckedNoHit`].
#[must_use]
pub fn mcp_is_error(value: &Value) -> bool {
    value.get("isError").and_then(Value::as_bool) == Some(true)
}

/// True when a successful backend result carries no usable data.
///
/// Treats JSON null, an empty array, an empty object, an empty/whitespace string,
/// and the MCP shape `{ "content": [] }` (or absent/null `content`) as empty. A
/// non-empty `content` array, or any other non-empty value, is data.
#[must_use]
pub fn value_is_empty(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::String(s) => s.trim().is_empty(),
        Value::Array(a) => a.is_empty(),
        Value::Object(map) => {
            if let Some(content) = map.get("content") {
                // MCP envelope: emptiness is decided by the content payload.
                return match content {
                    Value::Null => true,
                    Value::Array(a) => a.is_empty(),
                    _ => false,
                };
            }
            map.is_empty()
        }
        // Numbers and booleans are data.
        _ => false,
    }
}

/// Map a backend invocation outcome to an [`EvidenceState`] for `source`.
///
/// - `Ok` with a tool-level error (`isError: true`) → [`EvidenceState::Failed`].
/// - `Ok` with no usable data → [`EvidenceState::CheckedNoHit`] (a trustworthy negative).
/// - `Ok` with data → [`EvidenceState::CheckedHit`].
/// - `Err` is mapped to the matching could-not-check variant (see the match).
///
/// # Examples
///
/// ```
/// use mcp_gateway::evidence::{adapter::evidence_from_result, EvidenceState, SourceId};
/// use serde_json::json;
///
/// let hit = evidence_from_result(SourceId::new("registry"), &Ok(json!({"content": [{"text": "x"}]})));
/// assert!(matches!(hit, EvidenceState::CheckedHit { .. }));
///
/// let empty = evidence_from_result(SourceId::new("registry"), &Ok(json!({"content": []})));
/// assert!(matches!(empty, EvidenceState::CheckedNoHit { .. }));
/// ```
#[must_use]
pub fn evidence_from_result(source: SourceId, result: &Result<Value, Error>) -> EvidenceState {
    match result {
        Ok(value) => {
            if mcp_is_error(value) {
                EvidenceState::Failed {
                    source,
                    detail: Some("backend returned a tool-level error (isError=true)".to_string()),
                }
            } else if value_is_empty(value) {
                EvidenceState::CheckedNoHit {
                    source,
                    detail: None,
                }
            } else {
                EvidenceState::CheckedHit {
                    source,
                    detail: None,
                }
            }
        }
        Err(error) => evidence_from_error(source, error),
    }
}

/// Map a gateway [`Error`] to its could-not-check [`EvidenceState`].
///
/// Kept separate so the error taxonomy is expressed once and is easy to extend
/// as the gateway error enum grows.
fn evidence_from_error(source: SourceId, error: &Error) -> EvidenceState {
    let detail = Some(error.to_string());
    match error {
        // The backend was reached but did not answer in time.
        Error::BackendTimeout(_) => EvidenceState::Timeout { source, detail },

        // Authorization was refused.
        Error::OAuth(_) => EvidenceState::NotAuthorized { source, detail },

        // The source / tool is not present or not configured in this gateway.
        Error::BackendNotFound(_)
        | Error::ToolNotFound(_)
        | Error::Config(_)
        | Error::ConfigValidation(_)
        | Error::ConfigWatcher(_)
        | Error::CapabilityHashMismatch { .. } => {
            EvidenceState::NotConfigured { source, detail }
        }

        // Everything else is an unavailability / transport / protocol failure:
        // the source could not produce an authoritative answer.
        _ => EvidenceState::Failed { source, detail },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn src() -> SourceId {
        SourceId::new("test-source")
    }

    #[test]
    fn ok_with_content_is_checked_hit() {
        let r = Ok(json!({"content": [{"type": "text", "text": "found"}], "isError": false}));
        assert!(matches!(
            evidence_from_result(src(), &r),
            EvidenceState::CheckedHit { .. }
        ));
    }

    #[test]
    fn ok_empty_content_is_checked_no_hit_not_failure() {
        // The crown-jewel distinction: queried-and-empty is a trustworthy
        // negative, NOT a failure to check.
        for v in [json!({"content": []}), json!(null), json!([]), json!({})] {
            assert!(
                matches!(
                    evidence_from_result(src(), &Ok(v.clone())),
                    EvidenceState::CheckedNoHit { .. }
                ),
                "expected CheckedNoHit for {v}"
            );
        }
    }

    #[test]
    fn ok_with_tool_level_error_is_failed_not_no_hit() {
        let r = Ok(json!({"content": [], "isError": true}));
        assert!(
            matches!(evidence_from_result(src(), &r), EvidenceState::Failed { .. }),
            "isError=true must be Failed, never CheckedNoHit"
        );
    }

    #[test]
    fn timeout_maps_to_timeout() {
        let r: Result<Value, Error> = Err(Error::BackendTimeout("slow".into()));
        assert!(matches!(
            evidence_from_result(src(), &r),
            EvidenceState::Timeout { .. }
        ));
    }

    #[test]
    fn oauth_maps_to_not_authorized() {
        let r: Result<Value, Error> = Err(Error::OAuth("refused".into()));
        assert!(matches!(
            evidence_from_result(src(), &r),
            EvidenceState::NotAuthorized { .. }
        ));
    }

    #[test]
    fn missing_backend_maps_to_not_configured() {
        for e in [
            Error::BackendNotFound("x".into()),
            Error::ToolNotFound("y".into()),
            Error::Config("z".into()),
        ] {
            let r: Result<Value, Error> = Err(e);
            assert!(matches!(
                evidence_from_result(src(), &r),
                EvidenceState::NotConfigured { .. }
            ));
        }
    }

    #[test]
    fn transport_and_circuit_map_to_failed() {
        for e in [
            Error::CircuitOpen("open".into()),
            Error::BackendUnavailable("down".into()),
            Error::Transport("reset".into()),
            Error::Internal("boom".into()),
        ] {
            let r: Result<Value, Error> = Err(e);
            assert!(matches!(
                evidence_from_result(src(), &r),
                EvidenceState::Failed { .. }
            ));
        }
    }

    #[test]
    fn source_id_is_preserved() {
        let r = Ok(json!({"content": [{"text": "x"}]}));
        let st = evidence_from_result(SourceId::new("alpha"), &r);
        match st {
            EvidenceState::CheckedHit { source, .. } => assert_eq!(source.as_str(), "alpha"),
            other => panic!("expected CheckedHit, got {other:?}"),
        }
    }
}

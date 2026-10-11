// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The FSM workflow-state and routing-profile meta-tools.

use super::{
    Error, InvokeScope, MetaMcp, NO_SESSION_FOR_PROFILE, NO_SESSION_FOR_STATE, Result, Value,
    debug, extract_required_str, json, session_fp, session_key,
};

// ============================================================================
// FSM workflow state meta-tool
// ============================================================================

impl MetaMcp {
    /// Handle `gateway_set_state` — transition the session's FSM workflow state.
    ///
    /// Returns the previous state, the new state, and the number of capability
    /// tools visible in the new state (across all capability backends).
    pub(super) fn set_state(
        &self,
        args: &Value,
        session_id: Option<&str>,
        scope: InvokeScope<'_>,
    ) -> Result<Value> {
        // Refused rather than filtered, and refused HERE rather than inside
        // `SessionStateStore`: the write is the whole point of this call, so a
        // store that quietly dropped it would turn a refusal the caller can see
        // into a silent no-op — a worse defect than the one being fixed. The
        // read side is guarded in the store's readers instead (`ORDER.2` Q4,
        // ratified 2026-09-06).
        let Some(sid) = session_key(session_id) else {
            return Err(Error::Protocol(NO_SESSION_FOR_STATE.to_string()));
        };

        let new_state = extract_required_str(args, "state")?;
        let previous = self.session_state.set_state(sid, new_state);

        // Count the visible capability tools this caller could invoke (A3).
        let visible_tools = self.get_capabilities().map_or(0, |cap| {
            cap.get_tools_for_state(new_state)
                .iter()
                .filter(|t| {
                    self.may_invoke(&cap.name, &t.name, scope, session_id)
                        .is_ok()
                })
                .count()
        });

        debug!(
            session_id = %session_fp(sid),
            previous = %previous,
            current = new_state,
            visible_tools = visible_tools,
            "Session FSM state transition"
        );

        Ok(json!({
            "previous": previous,
            "current": new_state,
            "visible_tools": visible_tools,
            "session_id": sid,
        }))
    }
}

// ============================================================================
// Routing profile meta-tools
// ============================================================================

/// A profile as a caller may see it. The allow/deny patterns name backends and
/// tools a non-admin may not reach, so only an admin is shown them (A3).
pub(super) fn described(profile: &crate::routing_profile::RoutingProfile, is_admin: bool) -> Value {
    if is_admin {
        profile.describe()
    } else {
        json!({ "name": profile.name, "description": profile.description })
    }
}

impl MetaMcp {
    pub(super) fn set_profile(
        &self,
        args: &Value,
        session_id: Option<&str>,
        is_admin: bool,
    ) -> Result<Value> {
        let Some(sid) = session_key(session_id) else {
            return Err(Error::Protocol(NO_SESSION_FOR_PROFILE.to_string()));
        };

        let profile_name = extract_required_str(args, "profile")?;

        if !self.profile_registry.contains(profile_name) {
            let available = self.profile_registry.profile_names();
            return Err(Error::Protocol(format!(
                "Unknown routing profile '{profile_name}'. Available profiles: {}",
                if available.is_empty() {
                    "none configured".to_string()
                } else {
                    available.join(", ")
                }
            )));
        }

        self.session_profiles.set_profile(sid, profile_name);
        let profile = self.profile_registry.get(profile_name);
        Ok(json!({
            "profile": profile_name,
            "session_id": sid,
            "description": described(&profile, is_admin),
            "message": format!("Routing profile set to '{profile_name}'")
        }))
    }

    pub(super) fn get_profile(&self, session_id: Option<&str>, is_admin: bool) -> Result<Value> {
        let Some(sid) = session_key(session_id) else {
            return Err(Error::Protocol(NO_SESSION_FOR_PROFILE.to_string()));
        };
        let profile = self.active_profile(Some(sid));
        Ok(json!({
            "profile": profile.name,
            "session_id": sid,
            "description": described(&profile, is_admin),
            "available_profiles": self.profile_registry.profile_names(),
        }))
    }

    #[allow(clippy::unnecessary_wraps)]
    pub(super) fn list_profiles(&self) -> Result<Value> {
        let summaries = self.profile_registry.profile_summaries();
        let total = summaries.len();
        let default_name = self.profile_registry.default_name();
        Ok(json!({ "profiles": summaries, "default": default_name, "total": total }))
    }
}

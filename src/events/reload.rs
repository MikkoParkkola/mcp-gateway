// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Capability reloads and webhook event schemas (design §9, T52): a reload
//! that keeps an event name but drops one of its filters or mapped fields is
//! refused, and the routes already live stay live. Additive changes apply.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::capability::{CapabilityDefinition, WebhookDefinition};
use crate::gateway::WebhookRegistry;

/// What subscribers rely on in one webhook event type.
#[derive(Debug, Default, Clone)]
pub(crate) struct Shape {
    filters: BTreeSet<String>,
    fields: BTreeSet<String>,
}

fn shape_of(def: &WebhookDefinition) -> Option<Shape> {
    let event = def.event.as_ref()?;
    if def.transform.data.is_empty() {
        return None;
    }
    Some(Shape {
        filters: event.filters.iter().cloned().collect(),
        fields: def.transform.data.keys().cloned().collect(),
    })
}

/// The first event name whose shape `new` narrows, if any.
fn first_incompatible(
    old: &BTreeMap<String, Shape>,
    new: &BTreeMap<String, Shape>,
) -> Option<String> {
    old.iter()
        .find(|(name, before)| {
            new.get(*name).is_some_and(|after| {
                !before.filters.is_subset(&after.filters) || !before.fields.is_subset(&after.fields)
            })
        })
        .map(|(name, _)| name.clone())
}

/// Re-register the webhook routes of `capabilities`, unless the reload
/// narrows a live event type (T52). Returns the new routes' shapes: a stored
/// subscription they do not offer or serve is held, never deleted (MIK-8057,
/// MIK-8076; see [`judge`]).
///
/// # Errors
/// The name of the live event type the reload would narrow; the registry is
/// then left as it was.
pub(crate) fn refresh_webhooks(
    registry: &Arc<parking_lot::RwLock<WebhookRegistry>>,
    capabilities: &[CapabilityDefinition],
) -> Result<BTreeMap<String, Shape>, String> {
    let old: BTreeMap<String, Shape> = shapes(registry.read().event_routes().into_iter());
    let new: BTreeMap<String, Shape> = shapes(capabilities.iter().flat_map(|cap| {
        cap.webhooks
            .iter()
            .map(move |(route, def)| (cap.name.clone(), route.clone(), def.clone()))
    }));
    if let Some(name) = first_incompatible(&old, &new) {
        return Err(name);
    }
    registry.write().replace_capabilities(capabilities);
    Ok(new)
}

/// Each routed event type's shape, by event name.
fn shapes(
    routes: impl Iterator<Item = (String, String, WebhookDefinition)>,
) -> BTreeMap<String, Shape> {
    routes
        .filter_map(|(cap, route, def)| {
            shape_of(&def).map(|s| (format!("webhook.{cap}.{route}.received"), s))
        })
        .collect()
}

/// Whether the routes `shapes` serve `sub`, a stored webhook subscription:
/// its type offered, every filter key a declared filter and mapped field,
/// every payload field it was committed with still carried. A row with no
/// payload fields yet takes its type's fields now. `None` for any other row.
pub(crate) fn judge(
    sub: &crate::events::records::Subscription,
    shapes: &BTreeMap<String, Shape>,
) -> Option<super::store::Judged> {
    use super::store::{Held, Judged};
    if !sub.name.starts_with(super::webhook_source::NAME_PREFIX) {
        return None;
    }
    let Some(shape) = shapes.get(&sub.name) else {
        return Some(Judged {
            held: Some(Held {
                reason: "event type no longer offered; the subscription resumes if it returns",
                key: None,
            }),
            backfill: None,
        });
    };
    let filters = sub.arguments.as_object().into_iter().flat_map(|m| m.keys());
    let unserved = filters
        .filter(|key| *key != "event_type")
        .find(|key| !shape.filters.contains(*key) || !shape.fields.contains(*key))
        .or_else(|| {
            sub.payload_fields
                .iter()
                .find(|field| !shape.fields.contains(*field))
        });
    Some(Judged {
        held: unserved.map(|key| Held {
            reason: "not served by the event's current route; the subscription resumes if it returns",
            key: Some(key.clone()),
        }),
        backfill: Some(shape.fields.iter().cloned().collect()),
    })
}

/// The payload fields event type `name` carries on `registry`'s routes now.
pub(crate) fn payload_fields(
    registry: &parking_lot::RwLock<WebhookRegistry>,
    name: &str,
) -> Vec<String> {
    shapes(registry.read().event_routes().into_iter())
        .remove(name)
        .map(|s| s.fields.into_iter().collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shape(filters: &[&str], fields: &[&str]) -> Shape {
        Shape {
            filters: filters.iter().map(|s| (*s).to_owned()).collect(),
            fields: fields.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    #[test]
    fn narrowing_is_refused_and_widening_accepted() {
        let old = BTreeMap::from([("e".to_owned(), shape(&["repo", "ref"], &["repo", "ref"]))]);
        let narrowed = BTreeMap::from([("e".to_owned(), shape(&["repo"], &["repo"]))]);
        assert_eq!(first_incompatible(&old, &narrowed).as_deref(), Some("e"));
        let widened = BTreeMap::from([(
            "e".to_owned(),
            shape(&["repo", "ref"], &["repo", "ref", "sha"]),
        )]);
        assert_eq!(first_incompatible(&old, &widened), None);
        assert_eq!(
            first_incompatible(&old, &BTreeMap::new()),
            None,
            "removal is not narrowing"
        );
    }
}

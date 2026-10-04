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
#[derive(Debug, Default)]
struct Shape {
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
/// narrows a live event type. Returns the event types the reload removed:
/// their subscriptions are deleted (design §9).
///
/// # Errors
/// The name of the event type the reload would narrow; the registry is
/// then left as it was.
pub(crate) fn refresh_webhooks(
    registry: &Arc<parking_lot::RwLock<WebhookRegistry>>,
    capabilities: &[CapabilityDefinition],
) -> Result<Vec<String>, String> {
    let old: BTreeMap<String, Shape> = registry
        .read()
        .event_routes()
        .into_iter()
        .filter_map(|(cap, route, def)| {
            shape_of(&def).map(|s| (format!("webhook.{cap}.{route}.received"), s))
        })
        .collect();
    let new: BTreeMap<String, Shape> = capabilities
        .iter()
        .flat_map(|cap| {
            cap.webhooks.iter().filter_map(move |(route, def)| {
                shape_of(def).map(|s| (format!("webhook.{}.{route}.received", cap.name), s))
            })
        })
        .collect();
    if let Some(name) = first_incompatible(&old, &new) {
        return Err(name);
    }
    registry.write().replace_capabilities(capabilities);
    Ok(removed(&old, &new))
}

/// The event names `old` has and `new` does not.
fn removed(old: &BTreeMap<String, Shape>, new: &BTreeMap<String, Shape>) -> Vec<String> {
    old.keys()
        .filter(|name| !new.contains_key(*name))
        .cloned()
        .collect()
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

    #[test]
    fn removed_names_only_the_types_the_reload_dropped() {
        let old = BTreeMap::from([
            ("kept".to_owned(), shape(&[], &["a"])),
            ("gone".to_owned(), shape(&[], &["a"])),
        ]);
        let new = BTreeMap::from([
            ("kept".to_owned(), shape(&[], &["a"])),
            ("added".to_owned(), shape(&[], &["a"])),
        ]);
        assert_eq!(removed(&old, &new), vec!["gone".to_owned()]);
        assert!(removed(&old, &old).is_empty());
    }
}

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A save's secret slots: checked against its secrets and the loader's
//! size limit before any entry exists, then filled with the entries'
//! references.

use std::time::Instant;

use super::{Entries, ReplaceError, SecretStep, create_entries};
use crate::config_persistence::keyedit::{SlotId, Template};

/// The template's slots name exactly the step's fields (none without a
/// step): a slot with no secret, or a secret with no slot, is refused before
/// any entry exists. Compared as sorted lists: two secrets for one field
/// would leave an entry no field names.
pub(super) fn same_fields(
    template: &Template,
    step: Option<&SecretStep>,
) -> Result<(), ReplaceError> {
    let mut slots: Vec<String> = template.slot_ids().map(SlotId::display).collect();
    let mut fields: Vec<String> = step
        .map(|s| s.values.iter().map(|v| v.field.clone()).collect())
        .unwrap_or_default();
    slots.sort();
    fields.sort();
    if slots == fields {
        Ok(())
    } else {
        Err(ReplaceError::Refused(
            "the new config's secret slots and the saved secrets name different fields".to_string(),
        ))
    }
}

/// The filled file fits the parser's limit whatever references the store
/// returns: each slot counted at its escaped worst case (a control byte
/// escapes to four bytes, plus the quotes). Checked before any entry exists.
pub(super) fn fits_when_filled(template: &Template) -> Result<(), ReplaceError> {
    let worst = crate::secret_store::MAX_REFERENCE_LEN
        .checked_mul(4)
        .and_then(|n| n.checked_add(2))
        .and_then(|n| n.checked_mul(template.slot_ids().count()))
        .and_then(|n| n.checked_add(template.bytes().len()));
    match worst {
        Some(size) if size <= crate::yaml::MAX_YAML_BYTES => Ok(()),
        _ => Err(ReplaceError::Refused(
            "the new config could grow past the largest file the loader reads once its secrets are filled in"
                .to_string(),
        )),
    }
}

/// Each slot's reference: the entry made for the field the slot displays as.
fn by_slot(
    template: &Template,
    fields: &[String],
    refs: &[String],
) -> std::collections::BTreeMap<SlotId, String> {
    template
        .slot_ids()
        .filter_map(|id| {
            let shown = id.display();
            let at = fields.iter().position(|f| *f == shown)?;
            Some((id.clone(), refs.get(at)?.clone()))
        })
        .collect()
}

#[cfg_attr(
    not(any(test, feature = "webui")),
    expect(
        dead_code,
        reason = "first callers: the web UI settings save and discovery adopt"
    )
)]
/// Creates the step's entries, records them in `entries` (so a refusal
/// below still removes them) and fills the template with their references.
pub(super) async fn fill_secrets(
    template: Template,
    step: SecretStep,
    deadline: Instant,
    entries: &mut Entries,
) -> Result<Vec<u8>, ReplaceError> {
    let fields: Vec<String> = step.values.iter().map(|v| v.field.clone()).collect();
    let pending = create_entries(step, deadline).await?;
    let too_long = pending
        .refs()
        .iter()
        .any(|r| r.len() > crate::secret_store::MAX_REFERENCE_LEN);
    let refs = by_slot(&template, &fields, pending.refs());
    entries.pending = Some(pending);
    // The size bound counted every reference at this length: one longer
    // would let the filled file outgrow what the loader reads. Refused
    // before the file is written; the entries go.
    if too_long {
        return Err(ReplaceError::Refused(
            "the secret store returned a reference longer than the writer allows".to_string(),
        ));
    }
    template.fill(&refs).map_err(|_| {
        ReplaceError::Refused("the saved secrets could not be placed in the new config".to_string())
    })
}

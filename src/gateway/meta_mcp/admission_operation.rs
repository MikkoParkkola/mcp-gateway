// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The operation a keyed call is fingerprinted by: which `_meta` keys stay in
//! it, and a meta-tool's arguments reduced to them.

use serde_json::Value;

/// `_meta` keys that change WHAT a meta-tool call does, and so stay in its
/// operation fingerprint (MIK-8192). Empty: every request `_meta` key the
/// gateway reads on `tools/call` is per-request transport (era, declared
/// capabilities, progress and trace correlation, the key and nonces). The
/// operation-defining facts (tool, arguments, `params.task`) live outside
/// `_meta`. A key added here enters the fingerprint; nothing else can.
pub(crate) const OPERATION_DEFINING_META: &[&str] = &[];

/// A meta-tool's arguments as its operation fingerprint reads them: the
/// client's `_meta` (merged in by `merge_client_meta`) reduced to `allowed`,
/// and dropped when nothing allowed remains, so a retry differing only in a
/// fresh `progressToken` or declared capabilities is the same operation.
pub(crate) fn operation_arguments(arguments: &Value, allowed: &[&str]) -> Value {
    let mut operation = arguments.clone();
    if let Some(object) = operation.as_object_mut()
        && let Some(meta) = object.remove("_meta")
    {
        let kept: serde_json::Map<String, Value> = meta
            .as_object()
            .into_iter()
            .flatten()
            .filter(|(key, _)| allowed.contains(&key.as_str()))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        if !kept.is_empty() {
            object.insert("_meta".to_string(), Value::Object(kept));
        }
    }
    operation
}

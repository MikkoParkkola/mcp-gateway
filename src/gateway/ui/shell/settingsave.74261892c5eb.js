// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The shared Settings save flow: a review of the masked diff on
// the page, then a confirm, then the save. RED STUB: exports the entry point
// and does nothing, so every row of ui-tests/tests/settingsave.spec.mjs fails
// at its own assertion before the flow exists.

/**
 * @param {{host: Element, fields: object[], object: string, key: string, opener?: Element}} _spec
 * @returns {Promise<{outcome: string, answer?: object, error?: Error}>}
 */
export async function settingsSave(_spec) {
  return undefined;
}

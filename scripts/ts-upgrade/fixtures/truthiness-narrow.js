// @ts-check

/**
 * Truthiness narrowing: a `string | null | undefined` is narrowed to `string`
 * inside an `if (value)` guard, so `.toUpperCase()` needs no explicit cast.
 *
 * @param {string | null | undefined} value
 * @returns {string}
 */
export function truthinessNarrow(value) {
  if (value) {
    // `value` is narrowed to `string` here.
    return value.toUpperCase();
  }
  return "";
}

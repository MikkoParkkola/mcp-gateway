// @ts-check

/**
 * `typeof` guard: a `string | number` union is narrowed to each member by a
 * `typeof` check, exposing member-specific methods without a cast.
 *
 * @param {string | number} input
 * @returns {string}
 */
export function typeofGuard(input) {
  if (typeof input === "number") {
    // `input` is narrowed to `number` here.
    return input.toFixed(2);
  }
  // `input` is narrowed to `string` here.
  return input.trim();
}

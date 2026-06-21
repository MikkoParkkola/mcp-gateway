// @ts-check

/**
 * Nullable-parameter narrowing: a `{ name?: string } | null` parameter is
 * narrowed by a chained truthiness guard (`user && user.name`) so the optional
 * property is treated as a `string` in the guarded branch.
 *
 * @param {{ name?: string } | null} user
 * @returns {string}
 */
export function greet(user) {
  if (user && user.name) {
    // `user` is non-null and `user.name` is `string` here.
    return `Hello, ${user.name}`;
  }
  return "Hello, guest";
}

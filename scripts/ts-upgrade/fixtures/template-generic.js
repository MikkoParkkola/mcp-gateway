// @ts-check

/**
 * `@template` generic: the element type `T` flows from the array argument to
 * the return type, preserving type information without a cast at the call site.
 *
 * @template T
 * @param {T[]} items
 * @returns {T | undefined}
 */
export function first(items) {
  return items.length > 0 ? items[0] : undefined;
}

/**
 * @template T
 * @param {T[]} items
 * @param {(item: T) => boolean} predicate
 * @returns {T | undefined}
 */
export function findFirst(items, predicate) {
  for (const item of items) {
    if (predicate(item)) {
      return item;
    }
  }
  return undefined;
}

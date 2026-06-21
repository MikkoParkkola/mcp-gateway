/**
 * @template T
 * @param {T} x
 * @returns {T}
 */
function identity(x) {
  return x;
}

/**
 * @param {string} s
 */
function useIdentity(s) {
  const out = identity(s);
  // out should be string
  return out.toLowerCase();
}

module.exports = { identity, useIdentity };

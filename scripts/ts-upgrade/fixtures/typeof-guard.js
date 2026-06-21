/**
 * typeof type guard narrowing.
 * @param {unknown} value
 */
function describe(value) {
  if (typeof value === 'string') {
    return 'string:' + value.length;
  }
  if (typeof value === 'number') {
    return 'number:' + (value + 1);
  }
  if (typeof value === 'boolean') {
    return 'bool:' + (value ? 't' : 'f');
  }
  return 'other';
}

module.exports = { describe };

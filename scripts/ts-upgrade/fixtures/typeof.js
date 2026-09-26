/**
 * @param {string | number} value
 * @returns {number}
 */
function lengthOf(value) {
  if (typeof value === "string") {
    return value.length;
  }
  return value;
}

lengthOf("ab");

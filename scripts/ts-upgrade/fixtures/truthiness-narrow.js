/**
 * Truthiness narrowing via JSDoc.
 * @param {string | null | undefined} input
 */
function processInput(input) {
  if (input) {
    // After truthy check, input should be string (non-null, non-undefined)
    return input.toUpperCase() + input.length;
  }
  return '';
}

module.exports = { processInput };

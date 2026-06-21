/**
 * Nullable param narrowing.
 * @param {string | null} name
 * @param {number | undefined} [age]
 */
function greet(name, age) {
  if (name != null) {
    // name is string
    let base = 'Hi ' + name.trim();
    if (age != null) {
      base += ' age ' + age;
    }
    return base;
  }
  return 'Hi anon';
}

module.exports = { greet };

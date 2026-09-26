/**
 * @param {string | undefined} name
 * @returns {string}
 */
function greet(name) {
  if (name) {
    return name;
  }
  return "there";
}

greet("a");

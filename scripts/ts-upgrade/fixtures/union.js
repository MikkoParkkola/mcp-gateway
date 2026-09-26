/**
 * @typedef {{ kind: "a", n: number } | { kind: "b", s: string }} Item
 * @param {Item} item
 * @returns {string}
 */
function label(item) {
  if (item.kind === "a") {
    return String(item.n);
  }
  return item.s;
}

label({ kind: "b", s: "ok" });

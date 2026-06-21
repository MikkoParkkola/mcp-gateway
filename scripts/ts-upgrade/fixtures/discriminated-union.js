/**
 * Discriminated union narrowing via literal kind tag.
 * @typedef {{ kind: 'text'; content: string }} Text
 * @typedef {{ kind: 'count'; n: number }} Count
 * @typedef {Text | Count} Msg
 */

/**
 * @param {Msg} msg
 */
function format(msg) {
  if (msg.kind === 'text') {
    return 'TEXT:' + msg.content.toUpperCase();
  }
  // narrowed to Count
  return 'COUNT:' + (msg.n * 2);
}

module.exports = { format };

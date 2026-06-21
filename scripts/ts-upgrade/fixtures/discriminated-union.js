// @ts-check

/**
 * Discriminated-union narrowing: switching on the `kind` discriminant narrows
 * `Shape` to the matching member, so member-specific fields are accessible.
 *
 * @typedef {{ kind: "circle", radius: number }} Circle
 * @typedef {{ kind: "square", side: number }} Square
 * @typedef {Circle | Square} Shape
 */

/**
 * @param {Shape} shape
 * @returns {number}
 */
export function area(shape) {
  switch (shape.kind) {
    case "circle":
      // `shape` narrowed to `Circle`.
      return Math.PI * shape.radius * shape.radius;
    case "square":
      // `shape` narrowed to `Square`.
      return shape.side * shape.side;
    default:
      return 0;
  }
}

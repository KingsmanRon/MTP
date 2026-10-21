'use strict';

// Validate iteratively before recursive walkers. Track the active path rather
// than every visited node: shared acyclic children are valid ASTs.
module.exports = ast => {
  const pending = [[ast, 0, false]];
  const ancestors = new WeakSet();
  while (pending.length) {
    const [node, depth, exit] = pending.pop();
    if (exit) { ancestors.delete(node); continue; }
    if (depth > 128) throw new SyntaxError('Brace AST exceeds safe depth of 128');
    if (ancestors.has(node)) throw new SyntaxError('Brace AST must be acyclic');
    ancestors.add(node);
    pending.push([node, depth, true]);
    if (node.nodes) {
      for (const child of node.nodes) pending.push([child, depth + 1, false]);
    }
  }
};

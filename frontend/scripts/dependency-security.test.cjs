'use strict';
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { createRequire } = require('node:module');
const braces = require('braces');

for (const consumer of ['micromatch', 'chokidar']) {
  test(`${consumer} resolves the patched braces implementation`, () => {
    const fromConsumer = createRequire(require.resolve(consumer));
    assert.equal(fromConsumer.resolve('braces'), require.resolve('braces'));
  });
}
for (const operation of ['parse', 'compile', 'expand', 'stringify']) {
  test(`${operation} refuses deep patterns before stack exhaustion`, () => {
    for (const [open, close] of [['{', '}'], ['(', ')']]) {
      const pattern = open.repeat(4000) + 'x,y' + close.repeat(4000);
      assert.throws(() => braces[operation](pattern), { name: 'SyntaxError', message: /safe depth/ });
    }
  });
}
for (const operation of ['compile', 'expand', 'stringify']) {
  test(`${operation} bounds supplied ASTs and detects cycles`, () => {
    let ast = { type: 'text', value: 'x' };
    for (let i = 0; i < 12000; i++) ast = { type: 'root', nodes: [ast] };
    assert.throws(() => braces[operation](ast), { name: 'SyntaxError', message: /safe depth/ });
    const cycle = { type: 'root', nodes: [] };
    cycle.nodes.push(cycle);
    assert.throws(() => braces[operation](cycle), { name: 'SyntaxError', message: /acyclic/ });
  });
}
test('ordinary glob expansion, nesting and shared nodes remain supported', () => {
  assert.deepEqual(braces.expand('a/{1..3}/{x,y}'), ['a/1/x', 'a/1/y', 'a/2/x', 'a/2/y', 'a/3/x', 'a/3/y']);
  assert.equal(braces.compile('src/**/*.{ts,tsx}'), 'src/**/*.(ts|tsx)');
  assert.doesNotThrow(() => braces.compile('{'.repeat(64) + 'x,y' + '}'.repeat(64)));
  const leaf = { type: 'text', value: 'a' };
  assert.equal(braces.stringify({ type: 'root', nodes: [leaf, leaf] }), 'aa');
  assert.deepEqual(require('micromatch')(['src/a.ts', 'src/b.tsx', 'src/c.js'], 'src/*.{ts,tsx}'), ['src/a.ts', 'src/b.tsx']);
});
test('patched sharp native image codecs work', async () => {
  const sharp = require('sharp');
  const input = { create: { width: 3, height: 2, channels: 3, background: '#123456' } };
  for (const format of ['png', 'webp', 'avif']) {
    const encoded = await sharp(input).toFormat(format).toBuffer();
    const meta = await sharp(encoded).metadata();
    assert.equal(meta.width, 3);
    assert.equal(meta.height, 2);
    await sharp(encoded).resize(1, 1).raw().toBuffer();
  }
});

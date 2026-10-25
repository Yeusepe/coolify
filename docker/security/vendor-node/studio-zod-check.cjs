const assert = require('node:assert/strict');
const path = require('node:path');
const root = path.resolve(process.argv[2]);
const z = require(root);
const v4 = require(path.join(root, 'v4/index.cjs'));
const manifest = require(path.join(root, 'package.json'));
assert.equal(manifest.racconify.upstreamSource, 'zod@4.6.7');
assert.equal(manifest.racconify.defaultApi, 'zod/v3');
let calls = 0;
const item = z.string().refine(() => { calls++; return true; });
for (const [schema, input] of [
  [z.array(item).max(1), ['a', 'b']],
  [z.array(item).length(1), ['a', 'b']],
  [z.set(item).max(1), new Set(['a', 'b'])],
]) {
  const result = schema.safeParse(input);
  assert.equal(result.success, false);
  assert.equal(result.error.issues[0].code, 'too_big');
}
assert.equal(calls, 0);
assert.deepEqual(z.array(z.string()).parse(['ok']), ['ok']);
assert.deepEqual(v4.object({value:v4.string()}).parse({value:'ok'}), {value:'ok'});
console.log(JSON.stringify({legacyUpperBoundsPassed:true, explicitV4Passed:true, source:manifest.racconify.upstreamSource}));

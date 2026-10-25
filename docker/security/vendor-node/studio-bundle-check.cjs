const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const roots = process.argv.slice(2);
assert(roots.length, 'Supply compiled Studio directories');
let checked = 0;
function walk(root) {
  for (const entry of fs.readdirSync(root, {withFileTypes:true})) {
    const file = path.join(root, entry.name);
    if (entry.isDirectory()) { walk(file); continue; }
    if (!entry.name.endsWith('.js')) continue;
    const text = fs.readFileSync(file, 'utf8');
    if (!text.includes('ZodArray') || !text.includes('exactLength')) continue;
    let offset = 0;
    while ((offset = text.indexOf('.exactLength', offset)) !== -1) {
      const minimum = text.indexOf('.minLength', offset);
      const async = text.indexOf('.common.async', minimum);
      const element = text.indexOf('get element()', offset);
      // Locate the minified v3 array parser rather than its schema constructors.
      if (minimum < 0 || async < 0 || element < async || async - offset > 3000) { offset++; continue; }
      const exact = text.slice(offset, minimum);
      const max = text.lastIndexOf('.maxLength.value', async);
      assert(max > minimum, 'Unknown compiled Zod array layout');
      assert(/return [\w$]+/.test(exact), 'Missing exact upper-bound exit: '+file);
      assert(/return [\w$]+/.test(text.slice(max, async)), 'Missing maximum upper-bound exit: '+file);
      checked++;
      offset = element;
    }
  }
}
roots.forEach(walk);
assert(checked >= 2, 'Expected compiled legacy validation paths');
console.log(JSON.stringify({compiledLegacyArrayGuards:checked}));

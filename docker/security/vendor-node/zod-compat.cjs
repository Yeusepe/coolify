const fs = require('node:fs');
const path = require('node:path');
module.exports = function preserveZod3(root) {
  // Zod 4 ships both runtimes. Legacy consumers keep v3 while explicit v4 imports get the fixed release.
  const file = path.join(root, 'package.json');
  const manifest = JSON.parse(fs.readFileSync(file));
  for (const kind of ['import', 'require']) {
    const extension = kind === 'import' ? 'js' : 'cjs';
    manifest.exports['.'][kind] = { types: './v3/index.d.' + (kind === 'import' ? 'ts' : 'cts'), default: './v3/index.' + extension };
  }
  manifest.exports['.'].types = './v3/index.d.cts';
  if (manifest.exports['.']['@zod/source']) manifest.exports['.']['@zod/source'] = './src/v3/index.ts';
  manifest.main = './v3/index.cjs'; manifest.module = './v3/index.js'; manifest.types = './v3/index.d.cts';
  manifest.racconify = { defaultApi: 'zod/v3', explicitV4: '4.6.7', securityBackport: 'CVE-2023-54404 upper-size gates' };
  fs.writeFileSync(file, JSON.stringify(manifest, null, 2));
  for (const extension of ['js', 'cjs']) {
    const file = path.join(root, 'v3/types.' + extension);
    let text = fs.readFileSync(file, 'utf8');
    const invalid = extension === 'cjs' ? 'parseUtil_js_1.INVALID' : 'INVALID';
    for (const [name, next] of [['ZodArray', 'ZodObject'], ['ZodSet', 'ZodFunction']]) {
      const start = text.indexOf('class ' + name + ' extends');
      const end = text.indexOf('class ' + next + ' extends', start);
      if (start < 0 || end < 0) throw new Error('Unexpected Zod 3 structure');
      let block = text.slice(start, end);
      const expected = name === 'ZodArray' ? 3 : 2;
      if (block.split('status.dirty();').length - 1 !== expected) throw new Error('Unexpected Zod bound checks');
      // Fail oversized containers before mapping or refining any elements, as the upstream v4 fix does.
      if (name === 'ZodArray') block = block.replace('status.dirty();', 'if (tooBig) return ' + invalid + ';\n                status.dirty();');
      const last = block.lastIndexOf('status.dirty();');
      block = block.slice(0, last) + 'return ' + invalid + ';' + block.slice(last + 'status.dirty();'.length);
      text = text.slice(0, start) + block + text.slice(end);
    }
    fs.writeFileSync(file, text);
  }
};

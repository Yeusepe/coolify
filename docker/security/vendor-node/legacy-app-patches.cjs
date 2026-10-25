const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const {createRequire} = require('node:module');
const profile = process.argv[2];
const config = require('./profiles.json')[profile];
if (!config) throw new Error('Unknown profile');
if (profile === 'meta') {
  const file = '/usr/src/app/dist/server/server.js';
  let text = fs.readFileSync(file, 'utf8');
  assert(text.includes('buildApp({ logger })') && text.includes('buildAdminApp({ logger })'));
  text = text.replace('buildApp({ logger })', 'buildApp({ loggerInstance: logger })').replace('buildAdminApp({ logger })', 'buildAdminApp({ loggerInstance: logger })');
  fs.writeFileSync(file, text);
}
const seen = new Set(), cores = [], zods = [];
function walk(root) {
  let real; try { real = fs.realpathSync(root); } catch (error) { if (error.code === 'ENOENT') return; throw error; }
  if (seen.has(real) || !real.startsWith(config.root)) return;
  seen.add(real);
  const file = path.join(real, 'package.json');
  if (fs.existsSync(file)) {
    const p = JSON.parse(fs.readFileSync(file));
    if (p.name === '@opentelemetry/core' && typeof p.version === 'string' && p.version.startsWith('1.')) cores.push(real);
    if (p.name === 'zod' && p.racconify) zods.push(real);
  }
  for (const e of fs.readdirSync(real, {withFileTypes:true})) if ((e.isDirectory() || e.isSymbolicLink()) && e.name !== '.bin') walk(path.join(real,e.name));
}
walk(config.root);
for (const root of cores) {
  for (const tree of ['src','esm','esnext']) {
    const file = path.join(root, 'build', tree, 'baggage/propagation/W3CBaggagePropagator.js');
    if (!fs.existsSync(file)) continue;
    let text = fs.readFileSync(file, 'utf8');
    const marker = 'const headerValue = getter.get(carrier, constants_1.BAGGAGE_HEADER);';
    const esmMarker = 'const headerValue = getter.get(carrier, BAGGAGE_HEADER);';
    const found = [marker, esmMarker, esmMarker.replace('const ', 'var ')].find(value => text.includes(value));
    assert(found, 'Unknown baggage propagator');
    text = text.replace(found, found + `
        // Backport the W3C inbound bounds without changing the vendor's core major.
        const values = Array.isArray(headerValue) ? headerValue : [headerValue];
        if (values.length > 180) return context;
        let totalBytes = 0;
        for (const value of values) {
            if (typeof value !== 'string' || value.length > 8192) return context;
            totalBytes += new TextEncoder().encode(value).length + 1;
            if (totalBytes > 8193) return context;
        }
        const bounded = values.join(',').split(',');
        if (bounded.length > 180 || bounded.some(value => new TextEncoder().encode(value).length > 4096)) return context;
`);
    fs.writeFileSync(file, text);
  }
  const req = createRequire(path.join(root, 'package.json'));
  const api = req('@opentelemetry/api');
  const {W3CBaggagePropagator} = req(root);
  const propagator = new W3CBaggagePropagator();
  const extract = value => api.propagation.getBaggage(propagator.extract(api.ROOT_CONTEXT, {baggage:value}, api.defaultTextMapGetter));
  assert.equal(extract('one=two').getEntry('one').value, 'two');
  for (const value of ['a='+'x'.repeat(9000), 'a='+'é'.repeat(3000), Array.from({length:181},(_,i)=>'k'+i+'=v').join(',')]) assert.equal(extract(value), undefined);
}
for (const root of zods) {
  const req = createRequire(path.join(root, '../package.json'));
  const z = req(root);
  let parsed = 0;
  const item = z.string().refine(() => {parsed++; return true;});
  for (const schema of [z.array(item).max(1),z.array(item).length(1),z.set(item).max(1)]) {
    const input = schema instanceof z.ZodSet ? new Set(['a','b']) : ['a','b'];
    const result = schema.safeParse(input);
    assert.equal(result.success,false); assert.equal(result.error.issues[0].code,'too_big');
  }
  assert.equal(parsed,0);
  assert.deepEqual(z.array(z.string()).parse(['ok']), ['ok']);
}
console.log(JSON.stringify({profile, baggageBackports:cores.length, legacyZodGates:zods.length}));

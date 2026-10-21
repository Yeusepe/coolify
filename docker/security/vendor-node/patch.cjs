const fs = require('node:fs');
const profile = process.argv[2];
const entries = profile === 'meta' ? [
  ['piscina', '5.3.2', '/usr/src/app/node_modules/piscina'],
  ['proxy-addr', '2.0.8', '/usr/src/app/node_modules/proxy-addr'],
  ['tinypool', '2.1.2', '/usr/src/app/node_modules/oxfmt/node_modules/tinypool'],
] : profile === 'storage' ? [
  ['fastify', '5.12.7', '/app/node_modules/fastify'],
  ['undici', '7.29.1', '/app/node_modules/undici'],
] : null;
if (!entries) throw new Error('Unknown security profile');
for (const [name, version, target] of entries) {
  const resolved = fs.realpathSync(target);
  if (!resolved.startsWith(profile === 'meta' ? '/usr/src/app/node_modules/' : '/app/node_modules/')) throw new Error('Package escapes application directory');
  const source = '/tmp/runtime-security/node_modules/' + name;
  const manifest = JSON.parse(fs.readFileSync(source + '/package.json', 'utf8'));
  if (manifest.name !== name || manifest.version !== version) throw new Error('Unexpected package version');
  // Nested installs retain each repaired module's dependency tree without
  // changing dependency resolution for the rest of the vendor application.
  fs.rmSync(resolved, { recursive: true });
  fs.cpSync(source, resolved, { recursive: true });
}
fs.mkdirSync('/usr/share/racconify', { recursive: true });
fs.copyFileSync('/tmp/runtime-security/package-lock.json', '/usr/share/racconify/' + profile + '-security-package-lock.json');
console.log(JSON.stringify({ profile, packages: entries.map(([name, version]) => ({ name, version })) }));

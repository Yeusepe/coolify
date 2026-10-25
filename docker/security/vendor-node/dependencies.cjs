const fs = require('node:fs');
const cp = require('node:child_process');
const profile = require('./profiles.json')[process.argv[2]];
if (!profile) throw new Error('Unknown security profile');
const targets = [], seen = new Set();
function walk(path) {
  const resolved = fs.realpathSync(path);
  if (!resolved.startsWith(profile.root + '/') || seen.has(resolved)) return;
  seen.add(resolved);
  const manifest = resolved + '/package.json';
  if (fs.existsSync(manifest)) {
    const p = JSON.parse(fs.readFileSync(manifest));
    const version = profile.packages[p.name]?.[p.version.split('.')[0]];
    if (version && p.version !== version) targets.push({name:p.name, version, target:resolved});
  }
  for (const entry of fs.readdirSync(resolved, {withFileTypes:true})) {
    if ((entry.isDirectory() || entry.isSymbolicLink()) && entry.name !== '.bin') walk(resolved + '/' + entry.name);
  }
}
for (const entry of fs.readdirSync(profile.root, {withFileTypes:true})) {
  if (entry.isDirectory() && entry.name !== '.bin') walk(profile.root + '/' + entry.name);
}
const dependencies = {}, aliases = {};
for (const t of targets) {
  const key = t.name + '@' + t.version;
  if (!aliases[key]) { const alias = 'patch-' + Object.keys(aliases).length; aliases[key] = alias; dependencies[alias] = 'npm:' + key; }
}
fs.mkdirSync('/tmp/runtime-security', {recursive:true});
fs.writeFileSync('/tmp/runtime-security/package.json', JSON.stringify({name:'runtime-security',private:true,dependencies}));
cp.execFileSync(process.execPath, ['/opt/security-npm/bin/npm-cli.js','install','--prefix','/tmp/runtime-security','--install-strategy=nested','--omit=dev','--ignore-scripts','--no-audit','--no-fund'], {stdio:'inherit'});
for (const t of targets) {
  const source = '/tmp/runtime-security/node_modules/' + aliases[t.name + '@' + t.version];
  const p = JSON.parse(fs.readFileSync(source + '/package.json'));
  if (p.name !== t.name || p.version !== t.version) throw new Error('Unexpected package');
  fs.rmSync(t.target, {recursive:true}); fs.cpSync(source, t.target, {recursive:true});
}
fs.mkdirSync('/usr/share/racconify', {recursive:true});
fs.copyFileSync('/tmp/runtime-security/package-lock.json','/usr/share/racconify/' + process.argv[2] + '-reviewed-package-lock.json');
console.log(JSON.stringify({updated:targets}));
fs.rmSync('/tmp/runtime-security', {recursive:true});

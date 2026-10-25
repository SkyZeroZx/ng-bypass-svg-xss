#!/usr/bin/env node
// The compiler-side half of the report, checked without a browser, for every
// AOT fixture in .lab:
//
//   1. what the security schema registers for SVG, and whether `use` is in it
//   2. what the production bundle emits for each <use> binding
//   3. what the URL and RESOURCE_URL sanitizers do with the attacker values
//
//   node scripts/check-angular.mjs
import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { ROOT } from './lib/pin.mjs';
import { ANGULAR_BUILDS } from './lib/baseline.mjs';

const VALUES = {
  'A data:': 'data:image/svg+xml;base64,PHN2Zy8+#x',
  'B same-origin': '/uploads/avatar.png#x',
  'javascript:': 'javascript:void(0)',
};

// The runtime warns on the javascript: control; that is expected noise.
console.warn = () => {};

for (const major of Object.keys(ANGULAR_BUILDS)) {
  const fixture = join(ROOT, '.lab', 'angular' + major);
  const compiler = await readFile(
    join(fixture, 'node_modules/@angular/compiler/fesm2022/compiler.mjs'),
    'utf8',
  );
  const core = await import(
    pathToFileURL(join(fixture, 'node_modules/@angular/core/fesm2022/core.mjs')).href
  );
  console.log('Angular ' + core.VERSION.full);

  const svgEntries = compiler.match(/registerContext\(SecurityContext\.\w+, SVG_NAMESPACE\$1, \[\[[^\n]*?\]\]\]\)/g) || [];
  for (const entry of svgEntries) console.log('  schema   ' + entry);
  // From the first registerContext call to the end of the block holding the
  // last one. The block's shape differs between majors; the calls do not.
  const first = compiler.indexOf('registerContext(SecurityContext.');
  const last = compiler.lastIndexOf('registerContext(SecurityContext.');
  if (first === -1) throw new Error('No security schema found in ' + fixture);
  const schemaBlock = compiler.slice(first, compiler.indexOf('\n}', last));
  console.log(
    '  schema   ' +
      (schemaBlock.match(/registerContext\(/g) || []).length +
      " registerContext calls, 'use' occurs " +
      (schemaBlock.match(/'use'/g) || []).length +
      ' times',
  );

  const dist = join(fixture, 'dist', 'ng-bypass-svg-xss', 'browser');
  const bundle = (await readdir(dist)).find((name) => /^main.*\.js$/.test(name));
  const code = await readFile(join(dist, bundle), 'utf8');
  const bindings = [...new Set(code.match(/\w+\("href",\w+\.(?:assetUrl|iconUrl)(?:,null,"xlink")?\)/g) || [])];
  for (const binding of bindings) console.log('  bundle   ' + binding + '   <- no sanitizer argument');

  for (const [name, value] of Object.entries(VALUES)) {
    const url = core.ɵ_sanitizeUrl(value);
    let resource;
    try {
      core.ɵɵsanitizeResourceUrl(value);
      resource = 'passes';
    } catch (error) {
      resource = String(error.message).match(/NG0\d+/)?.[0] || 'throws';
    }
    console.log(
      '  sanitize ' +
        name.padEnd(14) +
        ' URL: ' +
        (url === value ? 'unchanged' : url).padEnd(28) +
        ' RESOURCE_URL: ' +
        resource,
    );
  }
  console.log('');
}

#!/usr/bin/env node
// Builds the same component source as an AOT production app under each pinned
// Angular major, into .lab/angular{20,21,22}. The matrix serves these bundles.
//
//   node scripts/build-fixtures.mjs            # all three
//   node scripts/build-fixtures.mjs 22         # one major
//
// Each fixture gets its own package.json with exact versions, so a bundle hash
// in the evidence always maps to one compiler release.
import { spawn } from 'node:child_process';
import { copyFile, cp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { join, resolve, sep } from 'node:path';
import { ROOT } from './lib/pin.mjs';
import { ANGULAR_BUILDS } from './lib/baseline.mjs';

const TYPESCRIPT = { 20: '5.9.3', 21: '5.9.3', 22: '6.0.2' };

function run(command, cwd) {
  return new Promise((done, reject) => {
    const child = spawn(command, { cwd, shell: true, stdio: 'inherit', windowsHide: true });
    child.once('error', reject);
    child.once('close', (code) =>
      code === 0 ? done() : reject(new Error(command + ' exited with ' + code)),
    );
  });
}

const majors = process.argv.slice(2).length ? process.argv.slice(2) : Object.keys(ANGULAR_BUILDS);
for (const major of majors) {
  const version = ANGULAR_BUILDS[major];
  if (!version) throw new Error('Unknown Angular major: ' + major);
  const fixture = join(ROOT, '.lab', 'angular' + major);
  if (!resolve(fixture).startsWith(resolve(ROOT, '.lab') + sep)) {
    throw new Error('Refusing to build outside .lab: ' + fixture);
  }
  await mkdir(fixture, { recursive: true });
  for (const file of ['angular.json', 'tsconfig.json', 'tsconfig.app.json', 'tsconfig.spec.json']) {
    await copyFile(join(ROOT, file), join(fixture, file));
  }
  for (const folder of ['src', 'public', 'dist']) {
    await rm(join(fixture, folder), { recursive: true, force: true });
  }
  await cp(join(ROOT, 'src'), join(fixture, 'src'), { recursive: true });
  await cp(join(ROOT, 'public'), join(fixture, 'public'), { recursive: true });

  // Angular 20 still needs zone.js without an explicit zoneless provider. All
  // three load it so the only variable between bundles is the compiler.
  const main = join(fixture, 'src', 'main.ts');
  await writeFile(main, "import 'zone.js';\n" + (await readFile(main, 'utf8')), 'utf8');

  const manifest = {
    name: 'ng-svg-xss-angular' + major,
    version: '1.0.0',
    private: true,
    scripts: { build: 'ng build --configuration production' },
    dependencies: {
      '@angular/common': version,
      '@angular/compiler': version,
      '@angular/core': version,
      '@angular/platform-browser': version,
      '@angular/router': version,
      rxjs: '7.8.2',
      'zone.js': '0.15.1',
    },
    devDependencies: {
      '@angular/build': version,
      '@angular/cli': version,
      '@angular/compiler-cli': version,
      typescript: TYPESCRIPT[major],
    },
  };
  await writeFile(join(fixture, 'package.json'), JSON.stringify(manifest, null, 2) + '\n', 'utf8');
  console.log('Building Angular ' + version);
  await run('npm install --no-audit --no-fund', fixture);
  await run('npm run build', fixture);
}

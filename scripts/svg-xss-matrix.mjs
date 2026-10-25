#!/usr/bin/env node
// Angular SVG <use> XSS matrix.
//
//   node scripts/svg-xss-matrix.mjs --chrome 119 --chrome 120 --angular 22
//   node scripts/svg-xss-matrix.mjs open --chrome 119 --case data-svg-base64
//
// Browsers are pinned by version and fetched by @puppeteer/browsers into a
// cache outside the repository. Nothing is installed system-wide, profiles are
// temporary, and the payloads only touch the lab's own loopback origin.
import { join } from 'node:path';
import { DEFAULT_CACHE, ROOT, assertVersion, pinBrowser } from './lib/pin.mjs';
import { launchSession } from './lib/session.mjs';
import { startOrigin } from './lib/origin.mjs';
import { angularVectors, htmlVectors, SUITE_NAMES, SINKS } from './lib/vectors.mjs';
import { angularBundle, openWriter, runCase } from './lib/run.mjs';
import { ANGULAR_BUILDS, BASELINE_FLOORS } from './lib/baseline.mjs';

const USAGE = [
  'Angular SVG <use> XSS matrix',
  '',
  'Usage:',
  '  node scripts/svg-xss-matrix.mjs [run] [options]',
  '  node scripts/svg-xss-matrix.mjs open   [options]     launch one headed browser and stop',
  '  node scripts/svg-xss-matrix.mjs floors                print the Angular Baseline floors',
  '',
  'Browsers (repeat to add more; a version, or stable/latest/esr):',
  '  --chrome 119          Chrome for Testing, 113 and later',
  '  --firefox 119         Firefox release; 115.43.1esr style also works',
  "  --at-floor            add each selected Angular major's floor browsers",
  '',
  'Scope:',
  '  --angular 20|21|22    repeat; default all three AOT builds present in .lab',
  '  --suite NAME          ' + SUITE_NAMES.join(' | ') + ' (default floor)',
  '  --sink NAME           ' + Object.keys(SINKS).join(' | '),
  '  --case ID             run one case id; repeat to add more',
  '  --layer angular|html  restrict to one layer; default both',
  '  --runs N              repetitions per case (default 2)',
  '',
  'Behaviour:',
  '  --headed              show the browser windows',
  '  --dwell MS            observation window after load (default 1500)',
  '  --timeout MS          navigation timeout (default 30000)',
  '  --offline             fail instead of downloading a missing browser',
  '  --cache-dir PATH      browser cache (default ' + DEFAULT_CACHE + ')',
  '  --output PATH         JSONL evidence path',
].join('\n');

function parseArgs(argv) {
  const options = {
    command: 'run',
    chrome: [],
    firefox: [],
    angular: [],
    cases: [],
    suite: 'floor',
    sink: 'image-onerror',
    layer: null,
    runs: 2,
    dwell: 1500,
    timeout: 30000,
    headed: false,
    offline: false,
    atFloor: false,
    cacheDir: DEFAULT_CACHE,
    output: null,
  };
  const lists = {
    '--chrome': 'chrome',
    '--firefox': 'firefox',
    '--angular': 'angular',
    '--case': 'cases',
  };
  const values = {
    '--suite': 'suite',
    '--sink': 'sink',
    '--layer': 'layer',
    '--cache-dir': 'cacheDir',
    '--output': 'output',
  };
  const numbers = { '--runs': 'runs', '--dwell': 'dwell', '--timeout': 'timeout' };
  const flags = { '--headed': 'headed', '--offline': 'offline', '--at-floor': 'atFloor' };

  for (let index = 0; index < argv.length; index++) {
    const flag = argv[index];
    if (index === 0 && ['run', 'open', 'floors'].includes(flag)) {
      options.command = flag;
      continue;
    }
    if (flag === '--help' || flag === '-h') {
      console.log(USAGE);
      process.exit(0);
    }
    if (flag in flags) {
      options[flags[flag]] = true;
      continue;
    }
    const key = lists[flag] || values[flag] || numbers[flag];
    if (!key) throw new Error('Unknown option: ' + flag + '\n\n' + USAGE);
    const value = argv[++index];
    if (value === undefined) throw new Error('Missing value for ' + flag);
    if (lists[flag]) options[key].push(value);
    else if (numbers[flag]) {
      const parsed = Number(value);
      if (!Number.isFinite(parsed) || parsed < 0)
        throw new Error(flag + ' needs a non-negative number');
      options[key] = parsed;
    } else options[key] = value;
  }

  if (!options.angular.length) options.angular = Object.keys(ANGULAR_BUILDS);
  for (const major of options.angular) {
    if (!(major in ANGULAR_BUILDS)) throw new Error('Unknown Angular major: ' + major);
  }
  if (!SUITE_NAMES.includes(options.suite)) {
    throw new Error('Unknown suite: ' + options.suite + ' (use ' + SUITE_NAMES.join(', ') + ')');
  }
  if (!(options.sink in SINKS)) {
    throw new Error(
      'Unknown sink: ' + options.sink + ' (use ' + Object.keys(SINKS).join(', ') + ')',
    );
  }
  if (options.layer && !['angular', 'html'].includes(options.layer)) {
    throw new Error('--layer must be angular or html');
  }
  if (options.atFloor) {
    for (const major of options.angular) {
      const floor = BASELINE_FLOORS[major];
      if (!options.chrome.includes(String(floor.chrome))) options.chrome.push(String(floor.chrome));
      if (!options.firefox.includes(String(floor.firefox)))
        options.firefox.push(String(floor.firefox));
    }
  }
  if (!options.chrome.length && !options.firefox.length) options.chrome.push('stable');
  if (options.runs < 1) options.runs = 1;
  return options;
}

function selectedVectors(options) {
  const html = htmlVectors({ suite: options.suite, sink: options.sink });
  const angular = angularVectors({ suite: options.suite, sink: options.sink });
  let all = [...angular, ...html];
  if (options.layer) all = all.filter((entry) => entry.layer === options.layer);
  if (options.cases.length) {
    all = all.filter((entry) => options.cases.includes(entry.id));
    if (!all.length) throw new Error('No case matched ' + options.cases.join(', '));
  }
  return all;
}

function distFor(major) {
  return join(ROOT, '.lab', 'angular' + major, 'dist', 'ng-bypass-svg-xss', 'browser');
}

function describe(verdict) {
  if (verdict.error) return 'ERROR';
  if (verdict.executed) return verdict.cookieReadable ? 'EXECUTED+COOKIE' : 'EXECUTED';
  if (verdict.rendered) return 'rendered only';
  return 'blocked';
}

async function commandFloors() {
  console.log('Angular Baseline floors (baseline-browser-mapping 2.11.32)');
  console.log('');
  console.log('  major  baseline date  chrome/edge  firefox  safari');
  for (const [major, floor] of Object.entries(BASELINE_FLOORS)) {
    console.log(
      '  ' +
        major.padEnd(6) +
        ' ' +
        floor.date.padEnd(14) +
        ' ' +
        String(floor.chrome).padEnd(12) +
        ' ' +
        String(floor.firefox).padEnd(8) +
        ' ' +
        floor.safari,
    );
  }
}

async function commandOpen(options) {
  const vectors = selectedVectors(options);
  const specimen = vectors[0];
  if (!specimen) throw new Error('No case selected');
  const engine = options.chrome.length ? 'chrome' : 'firefox';
  const version = options.chrome[0] || options.firefox[0];
  const major = options.angular[0];
  const pinned = await pinBrowser(engine, version, {
    cacheDir: options.cacheDir,
    allowDownload: !options.offline,
  });
  const server = await startOrigin({ dist: distFor(major) });
  const session = await launchSession(pinned, { headed: true, cacheDir: options.cacheDir });
  const actual = assertVersion(pinned, session.reported);
  server.setCase(specimen);
  const target =
    specimen.layer === 'angular'
      ? server.origin + '/case/' + specimen.route
      : server.origin + '/html/' + specimen.id;
  await session.page.goto(target, { waitUntil: 'load', timeout: options.timeout }).catch(() => {});
  console.log('');
  console.log('  browser   ' + engine + ' ' + actual + '  via ' + session.transport);
  console.log('  angular   ' + ANGULAR_BUILDS[major] + ' (' + specimen.layer + ' layer)');
  console.log('  case      ' + specimen.id + ' - ' + specimen.note);
  console.log('  origin    ' + server.origin);
  console.log('  sibling   ' + server.siblingOrigin + '  (cross-origin control)');
  console.log('  url       ' + target);
  console.log('');
  console.log('  In the browser console: window.__ngSvgXss  /  window.__ngSvgBound');
  console.log('  Close the browser window to shut the lab origin down.');
  await session.onDisconnect();
  await session.dispose();
  await server.close();
}

async function commandRun(options) {
  const vectors = selectedVectors(options);
  const stamp = new Date().toISOString().replace(/[-:]/g, '').replace(/\..+/, '');
  const writer = await openWriter(
    options.output || join(ROOT, 'evidence', 'matrix-' + stamp + '.jsonl'),
  );
  const browsers = [
    ...options.chrome.map((version) => ({ engine: 'chrome', version })),
    ...options.firefox.map((version) => ({ engine: 'firefox', version })),
  ];

  console.log(
    'suite ' +
      options.suite +
      ' / sink ' +
      options.sink +
      ' / ' +
      vectors.length +
      ' cases x ' +
      options.runs +
      ' runs',
  );
  console.log('browsers: ' + browsers.map((b) => b.engine + ' ' + b.version).join(', '));
  console.log('angular:  ' + options.angular.map((m) => ANGULAR_BUILDS[m]).join(', '));
  console.log('evidence: ' + writer.path);
  console.log('');

  let executions = 0;
  let rows = 0;
  const failures = [];

  for (const major of options.angular) {
    const dist = distFor(major);
    let bundle;
    try {
      bundle = await angularBundle(dist);
    } catch (error) {
      console.log('SKIP Angular ' + major + ': ' + error.message);
      continue;
    }
    const server = await startOrigin({ dist });
    try {
      for (const spec of browsers) {
        let pinned;
        try {
          pinned = await pinBrowser(spec.engine, spec.version, {
            cacheDir: options.cacheDir,
            allowDownload: !options.offline,
          });
        } catch (error) {
          console.log('SKIP ' + spec.engine + ' ' + spec.version + ': ' + error.message);
          failures.push(spec.engine + ' ' + spec.version + ': ' + error.message);
          continue;
        }
        let session;
        try {
          session = await launchSession(pinned, {
            headed: options.headed,
            cacheDir: options.cacheDir,
          });
        } catch (error) {
          console.log(
            'SKIP ' +
              spec.engine +
              ' ' +
              spec.version +
              ' (launch): ' +
              String(error.message).split('\n')[0],
          );
          failures.push(
            spec.engine + ' ' + spec.version + ' launch: ' + String(error.message).split('\n')[0],
          );
          continue;
        }
        let actual;
        try {
          actual = assertVersion(pinned, session.reported);
        } catch (error) {
          await session.dispose();
          console.log('SKIP ' + spec.engine + ' ' + spec.version + ': ' + error.message);
          failures.push(error.message);
          continue;
        }
        console.log(
          'ng' + major + ' / ' + spec.engine + ' ' + actual + '  via ' + session.transport,
        );
        try {
          for (const specimen of vectors) {
            for (let run = 1; run <= options.runs; run++) {
              let result;
              try {
                result = await runCase(session.page, server, specimen, options);
              } catch (error) {
                result = {
                  verdict: {
                    executed: false,
                    rendered: false,
                    error: String(error.message).slice(0, 200),
                  },
                  observation: null,
                  reached: [],
                };
              }
              if (result.verdict.executed) executions++;
              rows++;
              await writer.write({
                angular: ANGULAR_BUILDS[major],
                angular_major: Number(major),
                angular_bundle: bundle.file,
                angular_bundle_sha256: bundle.sha256,
                engine: spec.engine,
                browser_requested: spec.version,
                browser_build: pinned.buildId,
                browser_actual: actual,
                browser_reported: session.reported,
                transport: session.transport,
                suite: options.suite,
                sink: specimen.sink,
                layer: specimen.layer,
                case: specimen.id,
                note: specimen.note,
                bound_url: specimen.url ?? specimen.navigate ?? null,
                run,
                verdict: result.verdict,
                observation: result.observation,
                reached: result.reached,
                http: result.http ?? [],
              });
              if (run === 1) {
                const mark = describe(result.verdict);
                const flag = result.verdict.executed ? '!!' : '  ';
                console.log(
                  '  ' +
                    flag +
                    ' ' +
                    specimen.layer.padEnd(7) +
                    ' ' +
                    specimen.id.padEnd(28) +
                    ' ' +
                    mark +
                    (result.verdict.credentialedFetch ? ' +fetch' : '') +
                    (result.verdict.cspBlocked ? ' +csp' : ''),
                );
              }
            }
          }
        } finally {
          await session.dispose();
        }
      }
    } finally {
      await server.close();
    }
  }

  console.log('');
  console.log(rows + ' rows, ' + executions + ' executions recorded');
  console.log('evidence: ' + writer.path);
  if (failures.length) {
    console.log('');
    console.log('not run:');
    for (const failure of failures) console.log('  ' + failure);
  }
  return rows === 0 ? 1 : 0;
}

try {
  const options = parseArgs(process.argv.slice(2));
  if (options.command === 'floors') await commandFloors();
  else if (options.command === 'open') await commandOpen(options);
  else process.exitCode = await commandRun(options);
} catch (error) {
  console.error(error.stack || String(error));
  process.exitCode = 1;
}

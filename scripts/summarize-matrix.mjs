#!/usr/bin/env node
// Turns JSONL evidence into the Markdown tables used in the README. Every cell
// is counted from the rows, so a table can always be regenerated from the
// evidence rather than edited by hand.
//
//   node scripts/summarize-matrix.mjs evidence/*.jsonl
//
// Rows are grouped by suite before anything is counted. Suites carry different
// case lists, and pooling them turns clean cells into ratios.
import { readFile } from 'node:fs/promises';
import { BASELINE_FLOORS } from './lib/baseline.mjs';

// Which floor-suite case belongs to which attacker route. The data route needs
// nothing but a string in a field; the same-origin route needs the attacker's
// bytes on the application's own origin.
const ROUTES = {
  data: ['data-svg-base64', 'data-text-xml', 'ng-data-literal', 'ng-data-constructed'],
  origin: ['origin-image-svg-xml', 'ng-origin-svg-mime', 'ng-origin-xlink'],
};

function routeOf(name) {
  for (const [route, cases] of Object.entries(ROUTES)) {
    if (cases.includes(name)) return route;
  }
  return 'control';
}

function versionKey(row) {
  return row.engine + ' ' + row.browser_actual;
}

function compareVersions(a, b) {
  const [engineA, versionA] = a.split(' ');
  const [engineB, versionB] = b.split(' ');
  if (engineA !== engineB) return engineA < engineB ? -1 : 1;
  const left = versionA.split('.').map(Number);
  const right = versionB.split('.').map(Number);
  for (let index = 0; index < Math.max(left.length, right.length); index++) {
    const difference = (left[index] || 0) - (right[index] || 0);
    if (difference) return difference;
  }
  return 0;
}

function shortVersion(browser) {
  const [engine, version] = browser.split(' ');
  return (engine === 'chrome' ? 'Cr ' : 'FF ') + version.split('.')[0];
}

// A cell is a verdict over repeated runs, not a single observation. Mixed
// results are reported as such instead of being rounded to a yes or a no.
function cell(rows) {
  if (!rows.length) return '—';
  const executed = rows.filter((row) => row.verdict.executed).length;
  const errored = rows.filter((row) => row.verdict.error).length;
  const rendered = rows.filter((row) => row.verdict.rendered).length;
  if (errored === rows.length) return 'error';
  if (executed === rows.length) return 'yes';
  if (executed === 0) return rendered > 0 ? 'no (renders)' : 'no';
  return executed + '/' + rows.length;
}

function table(header, rows) {
  const widths = header.map((name, index) =>
    Math.max(name.length, ...rows.map((row) => String(row[index]).length)),
  );
  const line = (cells) =>
    '| ' + cells.map((value, index) => String(value).padEnd(widths[index])).join(' | ') + ' |';
  return [
    line(header),
    '| ' + widths.map((width) => '-'.repeat(width)).join(' | ') + ' |',
    ...rows.map((row) => line(row)),
  ].join('\n');
}

function supported(angularMajor, browser) {
  const [engine, version] = browser.split(' ');
  const floor = BASELINE_FLOORS[angularMajor];
  const major = Number(version.split('.')[0]);
  return engine === 'chrome' ? major >= floor.chrome : major >= floor.firefox;
}

function floorSection(rows) {
  const majors = [...new Set(rows.map((row) => row.angular_major))].sort();
  const browsers = [...new Set(rows.map(versionKey))].sort(compareVersions);
  const out = ['## Floor matrix', ''];
  out.push('`yes` = a handler from the referenced SVG executed in the application origin.');
  out.push('`no (renders)` = the sprite is drawn but no handler runs. `*` = outside that');
  out.push("major's Baseline floor.");
  out.push('');
  for (const route of ['data', 'origin']) {
    out.push(
      route === 'data'
        ? '### Route A — `data:` string, no upload'
        : '### Route B — SVG bytes on the app origin',
    );
    out.push('');
    const lines = browsers.map((browser) => [
      ...browser.split(' '),
      ...majors.map((angularMajor) => {
        const matching = rows.filter(
          (row) =>
            versionKey(row) === browser &&
            row.angular_major === angularMajor &&
            routeOf(row.case) === route,
        );
        return cell(matching) + (supported(angularMajor, browser) ? '' : ' *');
      }),
    ]);
    out.push(table(['engine', 'version', ...majors.map((m) => 'Angular ' + m)], lines));
    out.push('');
  }

  out.push("### Inside each major's own floor");
  out.push('');
  const summary = majors.map((angularMajor) => {
    const floor = BASELINE_FLOORS[angularMajor];
    const inWindow = rows.filter(
      (row) => row.angular_major === angularMajor && supported(angularMajor, versionKey(row)),
    );
    const affected = (route) =>
      [
        ...new Set(
          inWindow
            .filter((row) => routeOf(row.case) === route && row.verdict.executed)
            .map(versionKey),
        ),
      ]
        .sort(compareVersions)
        .map(shortVersion)
        .join(', ') || 'none';
    return [
      'Angular ' + angularMajor,
      'Chrome ' + floor.chrome + ' / Firefox ' + floor.firefox,
      affected('data'),
      affected('origin'),
    ];
  });
  out.push(table(['Angular', 'floor', 'executes A', 'executes B'], summary));
  out.push('');

  // Controls must stay silent. A control that executes invalidates the matrix.
  const leaking = rows.filter((row) => routeOf(row.case) === 'control' && row.verdict.executed);
  out.push(
    'Controls (`javascript:`, fragmentless, image/png, page CSP, safe sprite): ' +
      (leaking.length
        ? leaking.length + ' executed — ' + [...new Set(leaking.map((row) => row.case))].join(', ')
        : '0 executions across ' +
          rows.filter((row) => routeOf(row.case) === 'control').length +
          ' rows.'),
  );
  out.push('');
  return out;
}

// Case-by-browser grid for the suites that vary one property per case.
function gridSection(suite, rows) {
  const browsers = [...new Set(rows.map(versionKey))].sort(compareVersions);
  const cases = [...new Set(rows.map((row) => row.layer + ' ' + row.case))];
  const out = ['## Suite `' + suite + '`', ''];
  const lines = cases.map((key) => {
    const [layer, name] = key.split(' ');
    return [
      (layer === 'angular' ? 'ng: ' : '') + name,
      ...browsers.map((browser) =>
        cell(
          rows.filter(
            (row) => versionKey(row) === browser && row.layer === layer && row.case === name,
          ),
        ),
      ),
    ];
  });
  out.push(table(['case', ...browsers.map(shortVersion)], lines));
  out.push('');
  return out;
}

// Where the handler ran, per engine build, over every execution through
// <use>. The controls suite is left out: its direct navigations make the SVG
// the page itself, which is not the question this table answers.
function handlerSection(rows) {
  const executed = rows.filter(
    (row) => row.suite !== 'controls' && row.verdict.executed && row.verdict.handler,
  );
  const groups = new Map();
  for (const row of executed) {
    const handler = row.verdict.handler;
    const key = versionKey(row);
    const where =
      handler.root === 'shadow:use'
        ? 'clone in the `<use>` shadow tree'
        : handler.sameDoc === false
          ? 'node in the external document, page global'
          : handler.root === 'document'
            ? 'node in the page document'
            : 'detached `<' + String(handler.root).toLowerCase() + '>`';
    const entry = groups.get(key) || { where: new Set(), events: new Set(), trusted: 0, count: 0 };
    entry.where.add(where);
    entry.events.add(handler.event);
    if (handler.trusted === true) entry.trusted++;
    entry.count++;
    groups.set(key, entry);
  }
  const lines = [...groups.entries()]
    .sort(([a], [b]) => compareVersions(a, b))
    .map(([key, entry]) => [
      key,
      [...entry.where].join(' + '),
      [...entry.events].join(', '),
      entry.trusted + '/' + entry.count,
    ]);
  return [
    '## Where the handler ran',
    '',
    table(['browser', 'handler `this`', 'event', 'trusted'], lines),
    '',
  ];
}

const files = process.argv.slice(2);
if (!files.length) {
  console.error('Usage: node scripts/summarize-matrix.mjs <evidence.jsonl> [...]');
  process.exit(1);
}

const all = [];
for (const file of files) {
  const text = await readFile(file, 'utf8');
  for (const line of text.split('\n')) {
    if (line.trim()) all.push(JSON.parse(line));
  }
}

const out = [];
const suites = [...new Set(all.map((row) => row.suite))];
for (const suite of ['floor', 'data', 'origin', 'sinks', 'controls']) {
  if (!suites.includes(suite)) continue;
  const rows = all.filter((row) => row.suite === suite);
  out.push(...(suite === 'floor' ? floorSection(rows) : gridSection(suite, rows)));
}
out.push(...handlerSection(all));

const executions = all.filter((row) => row.verdict.executed);
out.push('## Totals', '');
out.push('- rows: ' + all.length + ' (errors: ' + all.filter((row) => row.verdict.error).length + ')');
out.push('- executions: ' + executions.length);
out.push(
  '- executions that read the page cookie: ' +
    executions.filter((row) => row.verdict.cookieReadable).length,
);
out.push(
  '- executions the server saw as a credentialed request: ' +
    executions.filter((row) => row.verdict.credentialedFetch).length,
);
out.push(
  '- browsers: ' +
    [...new Set(all.map(versionKey))].sort(compareVersions).join(', '),
);
out.push('- Angular builds: ' + [...new Set(all.map((row) => row.angular))].sort().join(', '));
console.log(out.join('\n'));

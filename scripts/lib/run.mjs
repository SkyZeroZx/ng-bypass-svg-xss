// Case execution and evidence recording.
//
// One row per (angular build, browser, layer, case, run). A row carries the
// resolved browser version and binary hash, the bundle hash, the bound URL,
// the HTTP responses the lab origin served for it, what the handler reported
// from inside the page -- including which document it ran in -- and whether
// the origin received a credentialed request from it. The verdict is derived
// from those fields, so re-reading the JSONL is enough to audit a claim.
import { createHash } from 'node:crypto';
import { appendFile, mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { release, arch, version as osVersion } from 'node:os';
import { setTimeout as sleep } from 'node:timers/promises';
import { CLICK_SINKS, MARKER } from './vectors.mjs';

// Read back inside the page. getBBox() on the <use> is independent evidence
// that the browser adopted and laid out the external document; findings are
// what the handler itself pushed.
function observeScript(marker) {
  return `(() => {
    const use = document.getElementById('bound-use');
    const img = document.getElementById('img-control');
    let box = null;
    if (use) {
      try { const b = use.getBBox(); box = { width: b.width, height: b.height }; } catch (e) { box = null; }
    }
    return {
      use: !!use,
      img: !!img,
      bound: use
        ? (use.getAttribute('href') || use.getAttributeNS('http://www.w3.org/1999/xlink', 'href') || '')
        : img ? img.getAttribute('src') : null,
      box,
      findings: (window['${marker}'] || []).slice(0, 8),
      csp: (window.__ngSvgCsp || []).slice(0, 8),
      ngVersion: (document.querySelector('[ng-version]') || {}).getAttribute
        ? document.querySelector('[ng-version]').getAttribute('ng-version')
        : null,
      href: location.href,
      // The button case renders its own click count, so a row can tell whether
      // the app's handler ran as well as whatever the clone did.
      appClicks: (document.getElementById('app-clicks') || {}).textContent || null,
      contentType: document.contentType || null,
    };
  })()`;
}

function sha256(data) {
  return createHash('sha256').update(data).digest('hex');
}

// A case executed when a handler pushed a finding whose reported origin is the
// application's own origin. Rendering alone is not execution.
//
// handler says where it ran:
//   shadow:use   a node cloned into the <use> shadow tree of the page
//   document     a node in some document; sameDoc tells whether that document
//                is the page's own, or a separate one (the external SVG) whose
//                handler nevertheless ran with the page as its global
function verdictOf(observation, reached, origin) {
  const findings = observation?.findings || [];
  const sameOrigin = findings.filter((finding) => finding.origin === origin);
  const first = sameOrigin[0];
  return {
    executed: sameOrigin.length > 0,
    rendered: (observation?.box?.width || 0) > 0,
    cookieReadable: sameOrigin.some((finding) => finding.cookie === true),
    credentialedFetch: reached.some((hit) => hit.cookie === true),
    sinksFired: [...new Set(sameOrigin.map((finding) => finding.sink))],
    handler: first
      ? {
          root: first.root ?? null,
          sameDoc: first.sameDoc ?? null,
          elDoc: first.elDoc ?? null,
          globalDoc: first.globalDoc ?? null,
          event: first.event ?? null,
          trusted: first.trusted ?? null,
        }
      : null,
    cspBlocked: (observation?.csp || []).length > 0,
  };
}

async function waitFor(page, script, predicate, timeout) {
  const deadline = Date.now() + timeout;
  let last;
  while (Date.now() < deadline) {
    last = await page.evaluate(script).catch(() => null);
    if (last && predicate(last)) return last;
    await sleep(100);
  }
  return last;
}

// The handler's fetch is fire-and-forget, so a marker can be read before the
// request lands. Without a short grace period credentialedFetch would be a
// lower bound rather than a measurement.
async function settleReach(server, observation) {
  let reached = server.reached();
  if (!reached.length && (observation?.findings || []).length > 0) {
    const deadline = Date.now() + 1000;
    while (Date.now() < deadline && !reached.length) {
      await sleep(100);
      reached = server.reached();
    }
  }
  return reached;
}

// Top-level navigation to the attacker file, from a blank same-origin page.
// With attachment the browser turns it into a download (denied in Chrome,
// confined to the throwaway profile in Firefox) and the blank page remains;
// with inline the SVG becomes the top document and runs as such.
async function runNavigation(page, server, specimen, options) {
  const origin = server.origin;
  await page.goto(origin + '/blank', { waitUntil: 'load', timeout: options.timeout });
  server.setCase(specimen);
  let navigationError = null;
  try {
    await page.goto(origin + specimen.navigate, { waitUntil: 'load', timeout: 10000 });
  } catch (error) {
    navigationError = String(error.message || error).split('\n')[0].slice(0, 120);
  }
  const script = observeScript(MARKER);
  const observation = await waitFor(
    page,
    script,
    (state) => (state.findings || []).length > 0,
    options.dwell,
  );
  const reached = await settleReach(server, observation);
  return {
    verdict: verdictOf(observation, reached, origin),
    observation: observation ? { ...observation, navigationError } : { navigationError },
    reached: reached.map((hit) => ({ sink: hit.sink, cookie: hit.cookie, server: hit.server })),
    http: server.http(),
  };
}

export async function runCase(page, server, specimen, options) {
  if (specimen.navigate) return runNavigation(page, server, specimen, options);
  const origin = server.origin;
  server.setCase(specimen);
  const target =
    specimen.layer === 'angular'
      ? origin + '/case/' + specimen.route
      : origin + '/html/' + specimen.id;

  await page.goto(target, { waitUntil: 'load', timeout: options.timeout });
  const script = observeScript(MARKER);
  // Wait for the binding. Angular needs a tick to render the component; the
  // plain page binds in its own script.
  let observation = await waitFor(
    page,
    script,
    (state) => (state.use || state.img) && state.bound !== null,
    8000,
  );
  if (!observation || !(observation.use || observation.img)) {
    return {
      verdict: { executed: false, rendered: false, error: 'binding never rendered' },
      observation: observation || null,
      reached: [],
      http: server.http(),
    };
  }
  // Some sinks need a real pointer event. Everything else gets the same dwell,
  // so a slow external load is not scored as a block.
  if (CLICK_SINKS.has(specimen.sink) && observation.use) {
    await page.click('#bound-use').catch(() => {});
  }
  observation = await waitFor(
    page,
    script,
    (state) => (state.findings || []).length > 0,
    options.dwell,
  );
  const reached = await settleReach(server, observation);
  return {
    verdict: verdictOf(observation, reached, origin),
    observation,
    reached: reached.map((hit) => ({ sink: hit.sink, cookie: hit.cookie, server: hit.server })),
    http: server.http(),
  };
}

export async function angularBundle(dist) {
  const files = await readdir(dist);
  const main = files.find((name) => /^main.*\.js$/.test(name));
  if (!main) throw new Error('No AOT main bundle in ' + dist);
  return { file: main, sha256: sha256(await readFile(join(dist, main))) };
}

export async function fileSha256(path) {
  return sha256(await readFile(path));
}

export async function openWriter(path) {
  await mkdir(dirname(path), { recursive: true });
  // Truncate. Appending silently merges two runs into one file, and a summary
  // built over that mixes bundles: it once reported "12/16" cells that were
  // really 4/8 from a stale build plus 8/8 from the current one.
  await writeFile(path, '');
  const environment = {
    os: osVersion() + ' ' + release() + ' ' + arch(),
    node: process.version,
  };
  return {
    path,
    environment,
    async write(row) {
      await appendFile(
        path,
        JSON.stringify({ time_utc: new Date().toISOString(), ...environment, ...row }) + '\n',
      );
    },
  };
}

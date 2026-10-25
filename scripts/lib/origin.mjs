// The lab origin.
//
// Everything the attacker controls is generated in memory and never written to
// disk. The only files read are the Angular AOT bundles, opened read-only. The
// server also owns a sibling origin on a second port so a cross-origin control
// is a real cross-origin request rather than a simulated one.
//
// Every response for an attacker path is logged per case -- status, the
// headers that matter, and a hash of the exact bytes -- so a row carries the
// HTTP evidence for its own verdict.
import { createServer } from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import { extname, join, resolve, sep } from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { CANARY, PROBE_PATH, SAFE_SVG, payload } from './vectors.mjs';

const APP_CSP = "default-src 'self'; script-src 'self'; img-src 'self' data:; object-src 'none'";

const STATIC_TYPES = {
  '.js': 'text/javascript',
  '.css': 'text/css',
  '.html': 'text/html; charset=utf-8',
  '.ico': 'image/x-icon',
  '.svg': 'image/svg+xml',
  '.json': 'application/json',
};

const ATTACKER_PATHS = new Set(['/asset.svg', '/uploads/avatar.png', '/uploads/note.txt']);

// The page that stands in for an application with no Angular on it. Its setup
// code is an external script, so a page CSP of script-src 'self' leaves it
// working while still blocking an inline handler that arrives inside an
// adopted SVG. By default it holds a <use> and nothing else, so a positive row
// cannot be blamed on any other element loading the same bytes.
function harnessPage(config) {
  return [
    '<!doctype html>',
    '<html lang="en"><head><meta charset="utf-8">',
    '<title>SVG use harness</title>',
    '</head><body>',
    '<p id="case">' + escapeHtml(config.id) + '</p>',
    '<script type="application/json" id="ng-svg-config">' +
      JSON.stringify(config).replace(/</g, '\\u003c') +
      '</script>',
    config.bindUse
      ? '<svg width="100" height="100" aria-label="bound use"><use id="bound-use"></use></svg>'
      : '',
    config.withImg ? '<img id="img-control" alt="ordinary image control">' : '',
    '<script src="/harness.js"></script>',
    '</body></html>',
  ].join('\n');
}

function escapeHtml(value) {
  return String(value).replace(
    /[&<>"]/g,
    (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[char],
  );
}

// Runs in the page. Binds the case's URL to <use>, or to an <img> for the
// control that checks the same bytes without <use>.
const HARNESS_JS = `
(function () {
  var cfg = JSON.parse(document.getElementById('ng-svg-config').textContent);
  var use = document.getElementById('bound-use');
  var img = document.getElementById('img-control');
  window.__ngSvgCsp = [];
  document.addEventListener('securitypolicyviolation', function (event) {
    window.__ngSvgCsp.push({
      directive: event.violatedDirective,
      blocked: String(event.blockedURI || '').slice(0, 80),
    });
  });
  window.__ngSvgBound = cfg.url;
  if (use) {
    if (cfg.attribute === 'xlink:href') {
      use.setAttributeNS('http://www.w3.org/1999/xlink', 'xlink:href', cfg.url);
    } else {
      use.setAttribute('href', cfg.url);
    }
  }
  if (img) img.setAttribute('src', cfg.url);
})();
`;

// A same-origin page with nothing on it. The direct-navigation controls start
// here, so if the navigation turns into a download the page that remains has
// no marker of its own.
const BLANK_PAGE = '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>blank</title></head><body></body></html>';

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

export async function startOrigin({ dist } = {}) {
  const root = dist ? resolve(dist) : null;
  const cookieValue = CANARY + '=' + randomUUID();
  // The case under test. Runs are sequential per browser, so one slot is
  // enough and keeps the Angular layer possible at all: its components hold
  // compiled-in URLs, so the response is the only thing left to vary.
  let active = { id: 'none', resource: { mime: 'image/svg+xml', sink: 'image-onerror' } };
  const reached = [];
  const http = [];

  function send(res, code, body, type, extra = {}) {
    const bytes = Buffer.isBuffer(body) ? body : Buffer.from(body, 'utf8');
    const headers = {
      'Content-Type': type,
      'Content-Length': bytes.length,
      'Cache-Control': 'no-store',
    };
    for (const [name, value] of Object.entries(extra)) {
      if (value !== null && value !== undefined) headers[name] = value;
    }
    res.writeHead(code, headers);
    res.end(bytes);
    return { headers, bytes };
  }

  function attackerBytes() {
    const resource = active.resource || {};
    return payload(resource.sink || 'image-onerror', {
      id: resource.rootId === undefined ? 'x' : resource.rootId,
    });
  }

  function resourceHeaders() {
    const resource = active.resource || {};
    return {
      'Content-Disposition': (resource.disposition || 'attachment') + '; filename="icon.svg"',
      'X-Content-Type-Options': resource.nosniff === false ? null : 'nosniff',
      'Content-Security-Policy': resource.resourceCsp || null,
    };
  }

  function log(server, req, status, headers, bytes) {
    http.push({
      server,
      path: new URL(req.url, 'http://127.0.0.1').pathname,
      dest: req.headers['sec-fetch-dest'] || null,
      mode: req.headers['sec-fetch-mode'] || null,
      status,
      type: headers['Content-Type'] || null,
      disposition: headers['Content-Disposition'] || null,
      nosniff: headers['X-Content-Type-Options'] || null,
      csp: headers['Content-Security-Policy'] || null,
      location: headers.Location || null,
      bytes: bytes ? bytes.length : 0,
      sha256: bytes && bytes.length ? sha256(bytes) : null,
    });
  }

  const handler = (name, siblingOrigin) => async (req, res) => {
    try {
      const url = new URL(req.url, 'http://127.0.0.1');
      const path = decodeURIComponent(url.pathname);

      // Credentialed reach probe, called by a handler that fired. The cookie
      // flag is read from the request itself, not reported by the page.
      if (path.startsWith(PROBE_PATH + '/')) {
        reached.push({
          server: name,
          sink: path.slice(PROBE_PATH.length + 1),
          cookie: (req.headers.cookie || '').includes(CANARY),
          referer: req.headers.referer || null,
          at: Date.now(),
        });
        send(res, 204, '', 'text/plain', { 'Access-Control-Allow-Origin': '*' });
        return;
      }

      // Nested references some sinks rely on. They must fail.
      if (path === '/__missing' || path === '/1') {
        send(res, 404, 'missing', 'text/plain');
        return;
      }

      if (path === '/harness.js') {
        send(res, 200, HARNESS_JS, 'text/javascript');
        return;
      }

      if (path === '/blank') {
        send(res, 200, BLANK_PAGE, 'text/html; charset=utf-8', {
          'Set-Cookie': cookieValue + '; Path=/; SameSite=Lax',
        });
        return;
      }

      if (path === '/safe.svg') {
        send(res, 200, SAFE_SVG, 'image/svg+xml');
        return;
      }

      // The attacker's uploaded bytes, under three path shapes so a file
      // extension can be shown to be no defence on its own.
      if (ATTACKER_PATHS.has(path)) {
        const resource = active.resource || {};
        const sent = send(
          res,
          200,
          attackerBytes(),
          resource.mime || 'image/svg+xml',
          resourceHeaders(),
        );
        log(name, req, 200, sent.headers, sent.bytes);
        return;
      }

      if (path === '/redirect/same' || path === '/redirect/cross') {
        const location =
          path === '/redirect/same'
            ? '/asset.svg'
            : (siblingOrigin || 'http://127.0.0.1:1') + '/asset.svg';
        res.writeHead(302, { Location: location, 'Cache-Control': 'no-store' });
        res.end();
        log(name, req, 302, { Location: location }, null);
        return;
      }

      // Plain-HTML page. The case id is in the path so every case is a fresh
      // document rather than a same-document fragment change.
      if (/^\/html\/[a-zA-Z0-9._-]+$/.test(path)) {
        const config = {
          id: active.id,
          url: active.crossPort ? siblingOrigin + '/asset.svg#x' : active.url || '',
          attribute: active.attribute || 'href',
          bindUse: active.bindUse !== false,
          withImg: active.withImg === true,
        };
        send(res, 200, harnessPage(config), 'text/html; charset=utf-8', {
          'Set-Cookie': cookieValue + '; Path=/; SameSite=Lax',
          'Content-Security-Policy': active.appCsp ? APP_CSP : null,
        });
        return;
      }

      // The Angular application. Every /case/... route returns index.html and
      // the router picks the component, so the CSP header can be applied per
      // case without touching the build.
      if (
        root &&
        (path === '/' || path === '/index.html' || /^\/case\/[a-zA-Z0-9-]+$/.test(path))
      ) {
        const body = await readFile(join(root, 'index.html'));
        send(res, 200, body, 'text/html; charset=utf-8', {
          'Set-Cookie': cookieValue + '; Path=/; SameSite=Lax',
          'Content-Security-Policy': active.appCsp ? APP_CSP : null,
        });
        return;
      }

      if (root) {
        const file = resolve(root, '.' + path);
        if (!file.startsWith(root + sep)) {
          send(res, 403, 'forbidden', 'text/plain');
          return;
        }
        const details = await stat(file).catch(() => null);
        if (details?.isFile()) {
          send(
            res,
            200,
            await readFile(file),
            STATIC_TYPES[extname(file)] || 'application/octet-stream',
          );
          return;
        }
      }
      send(res, 404, 'not found', 'text/plain');
    } catch (error) {
      send(res, 500, String(error), 'text/plain');
    }
  };

  async function listen(server) {
    await new Promise((done, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', done);
    });
    return 'http://127.0.0.1:' + server.address().port;
  }

  // The sibling exists only to be a different origin. It serves the same
  // attacker bytes, so a blocked cross-origin row cannot be blamed on a 404.
  const sibling = createServer((req, res) => handler('sibling', null)(req, res));
  const siblingOrigin = await listen(sibling);
  const primary = createServer((req, res) => handler('app', siblingOrigin)(req, res));
  const origin = await listen(primary);

  return {
    origin,
    siblingOrigin,
    cookie: cookieValue,
    setCase(next) {
      active = next;
      reached.length = 0;
      http.length = 0;
    },
    reached: () => reached.slice(),
    http: () => http.slice(),
    close: async () => {
      await Promise.all(
        [primary, sibling].map((server) => new Promise((done) => server.close(() => done()))),
      );
    },
  };
}

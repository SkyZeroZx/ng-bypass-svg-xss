#!/usr/bin/env node
// Minimal cross-check that shares nothing with the matrix but browser pinning.
//
// One static page holds <svg><use href=...></use></svg>. The referenced SVG is
// Mozilla bug 1912763's testcase 1 (<image href="1" onerror=...>), and the
// handler's only action is a credentialed fetch back to the server. Chrome is
// launched directly with --dump-dom, with no CDP, Puppeteer or page script, so
// the server log is the only signal. That is also what lets it measure Chrome
// 113 and 114, which Puppeteer cannot attach to.
//
//   node scripts/crosscheck.mjs --mode origin 113 114 115 116 121 122 156
//   node scripts/crosscheck.mjs --mode data-base64 --trials 8 113 114 115 116 117
//
// Modes: origin, data-base64, data-percent, data-text-xml.
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { pinBrowser } from './lib/pin.mjs';

const args = process.argv.slice(2);
let mode = 'origin';
let trials = 1;
const versions = [];
for (let index = 0; index < args.length; index++) {
  if (args[index] === '--mode') mode = args[++index];
  else if (args[index] === '--trials') trials = Number(args[++index]);
  else versions.push(args[index]);
}

const beacon =
  "top.fetch('/hit?doc=' + encodeURIComponent(this.ownerDocument.URL), { credentials: 'include' })";
const svg = (reference) =>
  '<svg xmlns="http://www.w3.org/2000/svg" id="x" viewBox="0 0 40 40" width="40" height="40">' +
  '<rect width="40" height="40" fill="orange"/>' +
  '<image href="' + reference + '" onerror="' + beacon + '"/></svg>';
// A data: document has no base URL, so the relative "1" cannot fail there.
const DATA_SVG = svg('data:image/png;base64,Zm9v');
const HREF = {
  origin: '/test.svg#x',
  'data-base64': 'data:image/svg+xml;base64,' + Buffer.from(DATA_SVG).toString('base64') + '#x',
  'data-percent': 'data:image/svg+xml,' + encodeURIComponent(DATA_SVG) + '#x',
  'data-text-xml': 'data:text/xml;base64,' + Buffer.from(DATA_SVG).toString('base64') + '#x',
}[mode];
if (!HREF) throw new Error('Unknown --mode ' + mode);

const PAGE =
  '<!doctype html><meta charset="utf-8"><title>crosscheck</title>' +
  '<svg width="100" height="100"><use href="' + HREF.replace(/"/g, '&quot;') + '"></use></svg>';

const log = [];
const server = createServer((req, res) => {
  log.push({ url: req.url, cookie: (req.headers.cookie || '').includes('sid=') });
  if (req.url === '/') {
    res.writeHead(200, { 'Content-Type': 'text/html', 'Set-Cookie': 'sid=lab; Path=/' });
    return res.end(PAGE);
  }
  if (req.url === '/test.svg') {
    res.writeHead(200, { 'Content-Type': 'image/svg+xml' });
    return res.end(svg('1'));
  }
  res.writeHead(req.url.startsWith('/hit') ? 204 : 404);
  res.end();
});
await new Promise((done) => server.listen(0, '127.0.0.1', done));
const origin = 'http://127.0.0.1:' + server.address().port;

console.log('mode ' + mode + ', ' + trials + ' trial(s) per build');
for (const version of versions) {
  const pinned = await pinBrowser('chrome', version, { allowDownload: false });
  let hits = 0;
  let where = null;
  for (let trial = 0; trial < trials; trial++) {
    const profile = await mkdtemp(join(tmpdir(), 'ngsvg-cross-'));
    log.length = 0;
    const child = spawn(
      pinned.executablePath,
      [
        '--headless=new',
        '--no-first-run',
        '--user-data-dir=' + profile,
        '--virtual-time-budget=4000',
        '--dump-dom',
        origin + '/',
      ],
      { stdio: 'ignore', windowsHide: true },
    );
    const timer = setTimeout(() => child.kill(), 30000);
    await new Promise((done) => child.once('close', done));
    clearTimeout(timer);
    await new Promise((done) => setTimeout(done, 300));
    const hit = log.find((entry) => entry.url.startsWith('/hit') && entry.cookie);
    if (hit) {
      hits++;
      where = decodeURIComponent(hit.url.slice('/hit?doc='.length)).slice(0, 40);
    }
    await rm(profile, { recursive: true, force: true }).catch(() => {});
  }
  console.log(
    '  chrome ' + pinned.buildId.padEnd(16) + ' ' + hits + '/' + trials +
      (where ? '  handler document: ' + where : ''),
  );
}
server.close();

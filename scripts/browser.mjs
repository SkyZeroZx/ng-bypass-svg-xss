#!/usr/bin/env node
// Opens one pinned browser build by hand. You start the app yourself; this only
// gives you the exact Chrome or Firefox version to test it in.
//
//   npm run browser -- --chrome 121 http://localhost:4200
//   npm run browser -- --firefox 119 http://localhost:4200
//   npm run browser -- --firefox 115.43.1esr
//
// The binary comes from the same cache the matrix uses and is downloaded if it
// is missing. Each launch gets a throwaway profile, deleted when the window
// closes, and nothing is attached to the browser: no CDP, WebDriver or
// automation flags, so it behaves like a normal install of that version.
import { spawn } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { setTimeout as sleep } from 'node:timers/promises';
import { DEFAULT_CACHE, pinBrowser } from './lib/pin.mjs';

const USAGE = [
  'Usage: npm run browser -- (--chrome VERSION | --firefox VERSION) [URL]',
  '',
  '  --chrome 121          Chrome for Testing, 113 and later',
  '  --firefox 119         Firefox release; 115.43.1esr, esr and stable also work',
  '  URL                   page to open (default about:blank)',
  '  --offline             fail instead of downloading a missing build',
  '  --cache-dir PATH      browser cache (default ' + DEFAULT_CACHE + ')',
].join('\n');

// An old Firefox build updates itself on first run unless told not to, which
// would silently replace the pinned version in the cache.
const FIREFOX_USER_JS = [
  'user_pref("app.update.auto", false);',
  'user_pref("app.update.enabled", false);',
  'user_pref("app.update.disabledForTesting", true);',
  'user_pref("browser.shell.checkDefaultBrowser", false);',
  'user_pref("browser.startup.homepage_override.mstone", "ignore");',
  'user_pref("datareporting.policy.dataSubmissionEnabled", false);',
  'user_pref("toolkit.telemetry.enabled", false);',
  '',
].join('\n');

function parseArgs(argv) {
  const options = {
    engine: null,
    version: null,
    url: 'about:blank',
    offline: false,
    cacheDir: DEFAULT_CACHE,
  };
  for (let index = 0; index < argv.length; index++) {
    const arg = argv[index];
    if (arg === '--help' || arg === '-h') {
      console.log(USAGE);
      process.exit(0);
    } else if (arg === '--chrome' || arg === '--firefox') {
      if (options.engine) throw new Error('Pick one browser per launch');
      options.engine = arg.slice(2);
      options.version = argv[++index];
      if (!options.version) throw new Error('Missing version for ' + arg);
    } else if (arg === '--offline') {
      options.offline = true;
    } else if (arg === '--cache-dir') {
      options.cacheDir = argv[++index];
    } else if (!arg.startsWith('--')) {
      options.url = arg;
    } else {
      throw new Error('Unknown option: ' + arg + '\n\n' + USAGE);
    }
  }
  if (!options.engine) throw new Error(USAGE);
  return options;
}

async function removeProfile(dir) {
  // Windows keeps profile files mapped until Firefox's content processes are
  // gone, which can take a few seconds after the main window closes.
  for (let attempt = 0; attempt < 20; attempt++) {
    try {
      await rm(dir, { recursive: true, force: true });
      return;
    } catch {
      await sleep(500);
    }
  }
  console.log('Could not remove the profile, delete it by hand: ' + dir);
}

try {
  const options = parseArgs(process.argv.slice(2));
  const pinned = await pinBrowser(options.engine, options.version, {
    cacheDir: options.cacheDir,
    allowDownload: !options.offline,
  });
  const profile = await mkdtemp(join(tmpdir(), 'ngsvg-manual-' + options.engine + '-'));

  let args;
  if (options.engine === 'firefox') {
    await writeFile(join(profile, 'user.js'), FIREFOX_USER_JS, 'utf8');
    args = ['-no-remote', '-new-instance', '-profile', profile, options.url];
  } else {
    args = [
      '--user-data-dir=' + profile,
      '--no-first-run',
      '--no-default-browser-check',
      options.url,
    ];
  }

  const build = String(pinned.buildId).replace(/^(stable|esr|beta|nightly|devedition)_/, '');
  console.log(options.engine + ' ' + build + (pinned.source === 'download' ? ' (downloaded)' : ''));
  console.log('  binary   ' + pinned.executablePath);
  console.log('  profile  ' + profile + '  (deleted on close)');
  console.log('  url      ' + options.url);
  console.log('Close the window to exit.');

  const child = spawn(pinned.executablePath, args, { stdio: 'ignore' });
  const stop = () => child.kill();
  process.once('SIGINT', stop);
  process.once('SIGTERM', stop);
  await new Promise((done, reject) => {
    child.once('error', reject);
    child.once('close', done);
  });
  await removeProfile(profile);
} catch (error) {
  console.error(error.message || String(error));
  process.exitCode = 1;
}

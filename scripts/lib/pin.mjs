// Browser pinning for the SVG <use> matrix.
//
// Every binary comes from @puppeteer/browsers, so pinning a version is a string
// in the corpus and nothing is installed system-wide. Downloads land in one
// cache directory outside the repository (see DEFAULT_CACHE) and each launch
// gets a throwaway profile in the OS temp directory.
import {
  canDownload,
  computeExecutablePath,
  install,
  detectBrowserPlatform,
  resolveBuildId,
} from '@puppeteer/browsers';
import puppeteer from 'puppeteer-core';
import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdir, mkdtemp, rm } from 'node:fs/promises';
import { setTimeout as sleep } from 'node:timers/promises';
import { join, resolve } from 'node:path';
import { homedir, tmpdir } from 'node:os';

export const ROOT = resolve(import.meta.dirname, '../..');

// The cache deliberately sits outside the repository. A checkout can live in a
// synced folder such as OneDrive, and unpacking a few hundred megabytes of
// browser there both corrupts the extraction and uploads the binaries to the
// user's cloud storage. --cache-dir overrides this.
export const DEFAULT_CACHE =
  process.env.NG_SVG_XSS_CACHE ||
  join(
    process.platform === 'win32'
      ? process.env.LOCALAPPDATA || join(homedir(), 'AppData', 'Local')
      : process.env.XDG_CACHE_HOME || join(homedir(), '.cache'),
    'ng-bypass-svg-xss',
    'browsers',
  );

// A channel name is resolved by @puppeteer/browsers and reports back the real
// version, so `--firefox stable` on two different days is two different rows
// rather than one ambiguous one.
const CHANNELS = new Set([
  'stable',
  'latest',
  'esr',
  'beta',
  'nightly',
  'devedition',
  'dev',
  'canary',
]);

// Firefox build IDs carry their channel. `119` and `119.0` are accepted as
// shorthand for the stable release so the CLI stays short.
function firefoxBuildId(version) {
  if (/^(stable|esr|beta|nightly|devedition)_/.test(version)) return version;
  if (/^\d+(\.\d+)*esr$/.test(version)) return 'esr_' + version;
  if (/^\d+$/.test(version)) return 'stable_' + version + '.0';
  return 'stable_' + version;
}

export function normalizeSpec(engine, version) {
  if (engine === 'firefox') {
    return {
      browser: 'firefox',
      buildId: CHANNELS.has(version) ? version : firefoxBuildId(version),
      isChannel: CHANNELS.has(version),
    };
  }
  if (engine === 'chrome')
    return { browser: 'chrome', buildId: version, isChannel: CHANNELS.has(version) };
  if (engine === 'chromium')
    return { browser: 'chromium', buildId: version, isChannel: CHANNELS.has(version) };
  throw new Error('Unknown engine: ' + engine);
}

// The archive is unpacked with the platform's own extractor. @puppeteer/browsers
// unzips through a Node library that hangs indefinitely on a ~150 MB Chrome
// archive on this Windows host, while bsdtar finishes the same file in under a
// second. bsdtar ships with Windows 10+, macOS and most Linux distributions;
// unzip is the fallback.
async function runTool(file, args) {
  return new Promise((done) => {
    const child = spawn(file, args, { stdio: 'ignore', windowsHide: true });
    child.once('error', () => done(false));
    child.once('close', (code) => done(code === 0));
  });
}

export async function extractArchive(archive, target) {
  await mkdir(target, { recursive: true });
  const bsdtar =
    process.platform === 'win32'
      ? join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'tar.exe')
      : 'tar';
  if (await runTool(bsdtar, ['-xf', archive, '-C', target])) return 'bsdtar';
  if (await runTool('unzip', ['-q', '-o', archive, '-d', target])) return 'unzip';
  throw new Error('Could not extract ' + archive + ': no working bsdtar or unzip');
}

// A pinned version is reported back with the build ID that was actually
// resolved, so a row never claims a version the corpus only asked for.
export async function pinBrowser(
  engine,
  version,
  { cacheDir = DEFAULT_CACHE, allowDownload = true } = {},
) {
  const platform = detectBrowserPlatform();
  if (!platform) throw new Error('Unsupported platform for browser download');
  const spec = normalizeSpec(engine, version);
  let buildId = spec.buildId;
  if (spec.browser !== 'firefox' || spec.isChannel) {
    buildId = await resolveBuildId(spec.browser, platform, spec.buildId);
  }
  const target = { browser: spec.browser, buildId, cacheDir, platform };
  const executablePath = computeExecutablePath(target);
  const result = { engine, requested: version, buildId, executablePath, platform, source: 'cache' };
  if (existsSync(executablePath)) return result;
  if (!allowDownload)
    throw new Error('Not cached and --offline was given: ' + engine + ' ' + version);
  if (!(await canDownload(target))) {
    throw new Error(
      'No downloadable build for ' +
        engine +
        ' ' +
        version +
        ' (resolved ' +
        buildId +
        ') on ' +
        platform +
        (spec.browser === 'chrome'
          ? '. Chrome for Testing publishes 113 and later only, so earlier majors cannot be pinned to a release build.'
          : ''),
    );
  }
  // Firefox arrives as a platform installer that the library already handles.
  // Chrome and Chromium arrive as a zip, which is where the hang lives.
  if (spec.browser === 'firefox') {
    const installed = await install(target);
    return { ...result, executablePath: installed.executablePath, source: 'download' };
  }
  const archive = await install({ ...target, unpack: false });
  const archivePath = typeof archive === 'string' ? archive : archive.path;
  // This is the layout @puppeteer/browsers computes paths against. Building it
  // from cacheDir keeps macOS right, where the binary sits several levels deep
  // inside an .app bundle.
  const unpackRoot = join(cacheDir, spec.browser, platform + '-' + buildId);
  await rm(unpackRoot, { recursive: true, force: true });
  const extractor = await extractArchive(archivePath, unpackRoot);
  // The archive is ~150 MB per build and is of no further use once unpacked.
  await rm(archivePath, { force: true });
  if (!existsSync(executablePath)) {
    throw new Error(
      'Extracted ' +
        engine +
        ' ' +
        buildId +
        ' with ' +
        extractor +
        ' but no binary at ' +
        executablePath,
    );
  }
  return { ...result, source: 'download', extractor };
}

// Prefs and flags only reduce background noise (updates, telemetry, first-run
// pages). None of them relax a security boundary, because the matrix is
// measuring the browser's default behaviour.
const FIREFOX_PREFS = {
  'app.update.auto': false,
  'app.update.enabled': false,
  'browser.shell.checkDefaultBrowser': false,
  'browser.startup.homepage_override.mstone': 'ignore',
  'datareporting.policy.dataSubmissionEnabled': false,
  'toolkit.telemetry.enabled': false,
  'network.prefetch-next': false,
};

// Firefox ignores browser.download.dir unless folderList is 2, and falls back
// to the user's real Downloads folder. The direct-navigation controls do
// trigger a download, so it has to land inside the throwaway profile and be
// deleted with it, without a prompt that would stall the session.
export function firefoxDownloadPrefs(profile) {
  return {
    'browser.download.folderList': 2,
    'browser.download.dir': join(profile, 'downloads'),
    'browser.download.useDownloadDir': true,
    'browser.download.start_downloads_in_tmp_dir': false,
    'browser.download.always_ask_before_handling_new_types': false,
    'browser.download.manager.showWhenStarting': false,
    'browser.download.alwaysOpenPanel': false,
    'browser.helperApps.neverAsk.saveToDisk':
      'image/svg+xml,text/xml,application/xml,image/png,text/plain,application/octet-stream,text/html',
  };
}

const CHROME_ARGS = [
  '--no-first-run',
  '--no-default-browser-check',
  '--disable-background-networking',
  '--disable-component-update',
  '--disable-sync',
  '--metrics-recording-only',
  '--password-store=basic',
];

// Windows keeps Firefox's key4.db mapped for a moment after the process exits,
// so Puppeteer's own profile cleanup throws EBUSY from a detached promise and
// takes the run down with it. The profile is therefore ours to create and ours
// to remove, with a short retry.
async function removeProfile(dir) {
  for (let attempt = 0; attempt < 10; attempt++) {
    try {
      await rm(dir, { recursive: true, force: true, maxRetries: 3 });
      return true;
    } catch {
      await sleep(250);
    }
  }
  return false;
}

export async function launchPinned(pinned, { headed = false } = {}) {
  const isFirefox = pinned.engine === 'firefox';
  const profile = await mkdtemp(join(tmpdir(), 'ngsvg-' + pinned.engine + '-'));
  let browser;
  try {
    browser = await puppeteer.launch({
      browser: isFirefox ? 'firefox' : 'chrome',
      executablePath: pinned.executablePath,
      headless: !headed,
      protocol: isFirefox ? 'webDriverBiDi' : 'cdp',
      timeout: 120000,
      dumpio: false,
      userDataDir: profile,
      args: isFirefox ? [] : CHROME_ARGS,
      extraPrefsFirefox: isFirefox
        ? { ...FIREFOX_PREFS, ...firefoxDownloadPrefs(profile) }
        : undefined,
    });
  } catch (error) {
    await removeProfile(profile);
    throw error;
  }
  const reported = await browser.version();
  return {
    browser,
    reported,
    profile,
    dispose: async () => {
      try {
        await browser.close();
      } catch {
        try {
          browser.process()?.kill('SIGKILL');
        } catch {}
      }
      return removeProfile(profile);
    },
  };
}

// The matrix refuses to record a row if the launched binary is not the one that
// was pinned, which is what keeps a "Chrome 119" verdict honest. The comparison
// uses the resolved build ID rather than the requested string, because the CLI
// also accepts aliases such as stable, latest and esr.
export function assertVersion(pinned, reported) {
  const actual = (reported.match(/(\d+(?:\.\d+)*)/g) || []).at(-1) || reported;
  const wanted = String(pinned.buildId)
    .replace(/^(stable|esr|beta|nightly|devedition)_/, '')
    .replace(/esr$/, '');
  const wantedMajor = wanted.split('.')[0];
  const actualMajor = actual.split('.')[0];
  if (!/^\d+$/.test(wantedMajor)) {
    throw new Error(
      'Cannot verify ' + pinned.engine + ' build ' + pinned.buildId + ' against ' + reported,
    );
  }
  if (wantedMajor !== actualMajor) {
    throw new Error('Pinned ' + pinned.engine + ' ' + pinned.buildId + ' but launched ' + reported);
  }
  return actual;
}

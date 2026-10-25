// Firefox transport for the versions Puppeteer cannot drive.
//
// Puppeteer talks to Firefox over WebDriver BiDi and sends the current
// capability shape:
//
//   unhandledPromptBehavior: { default: 'ignore' }
//
// Firefox only began accepting that object in the 125 era. Every release below
// it answers session.new with
//
//   invalid argument Expected [object String] "unhandledPromptBehavior" to be
//   a string, got [object Object]
//
// which is fatal, and holds for Puppeteer 22 as well as 24. The Firefox
// releases this lab cares about are exactly the ones below that line -- 104 and
// 112 are the Angular 20 and 21 floors, 119 is the Angular 22 floor, and 121 is
// the last release before Firefox removed data: from <use> -- so those rows
// would simply not exist on a Puppeteer-only harness. WebDriver classic through
// geckodriver covers the whole range, and this module wraps it in the same
// page surface run.mjs already uses for Chrome, so nothing downstream changes.
import { spawn } from 'node:child_process';
import { createServer } from 'node:net';
import { existsSync } from 'node:fs';
import { mkdir, mkdtemp, rename, rm, writeFile } from 'node:fs/promises';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { createWriteStream } from 'node:fs';
import { setTimeout as sleep } from 'node:timers/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { extractArchive, firefoxDownloadPrefs } from './pin.mjs';

// geckodriver 0.36 requires Firefox 115 or newer; 0.33 reaches back to 102.
const DRIVERS = {
  '0.33.0': { max: 114 },
  '0.36.0': { min: 115 },
};

const PLATFORM_ASSET = {
  win32: 'win64.zip',
  darwin: 'macos.tar.gz',
  linux: 'linux64.tar.gz',
};

export function driverVersionFor(firefoxMajor) {
  for (const [version, range] of Object.entries(DRIVERS)) {
    if (range.max !== undefined && firefoxMajor <= range.max) return version;
    if (range.min !== undefined && firefoxMajor >= range.min) return version;
  }
  return '0.36.0';
}

export async function ensureGeckodriver(firefoxMajor, cacheDir) {
  const version = driverVersionFor(firefoxMajor);
  const directory = join(cacheDir, 'geckodriver', version);
  const binary = join(directory, process.platform === 'win32' ? 'geckodriver.exe' : 'geckodriver');
  if (existsSync(binary)) return { version, binary };

  const asset = PLATFORM_ASSET[process.platform];
  if (!asset) throw new Error('No geckodriver asset for platform ' + process.platform);
  const url =
    'https://github.com/mozilla/geckodriver/releases/download/v' +
    version +
    '/geckodriver-v' +
    version +
    '-' +
    asset;
  await mkdir(directory, { recursive: true });
  const archive = join(directory, 'geckodriver.' + (asset.endsWith('.zip') ? 'zip' : 'tar.gz'));
  const response = await fetch(url, { redirect: 'follow', signal: AbortSignal.timeout(180000) });
  if (!response.ok || !response.body) {
    throw new Error('geckodriver download failed: ' + response.status + ' ' + url);
  }
  const partial = archive + '.part';
  await pipeline(Readable.fromWeb(response.body), createWriteStream(partial));
  await rename(partial, archive);
  await extractArchive(archive, directory);
  await rm(archive, { force: true });
  if (!existsSync(binary))
    throw new Error('geckodriver not found at ' + binary + ' after extraction');
  return { version, binary };
}

async function freePort() {
  const server = createServer();
  await new Promise((done, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', done);
  });
  const { port } = server.address();
  await new Promise((done) => server.close(done));
  return port;
}

// Prefs mirror the Puppeteer launch path: no updates, no telemetry, downloads
// confined to the throwaway profile.
const PREFS = {
  'app.update.auto': false,
  'app.update.enabled': false,
  'browser.shell.checkDefaultBrowser': false,
  'datareporting.policy.dataSubmissionEnabled': false,
  'toolkit.telemetry.enabled': false,
  'network.prefetch-next': false,
};

export async function launchGecko(pinned, { headed = false, cacheDir } = {}) {
  const major = Number(
    String(pinned.buildId)
      .replace(/^[a-z]+_/, '')
      .split('.')[0],
  );
  const driver = await ensureGeckodriver(major, cacheDir);
  const port = await freePort();
  const endpoint = 'http://127.0.0.1:' + port;
  const profile = await mkdtemp(join(tmpdir(), 'ngsvg-firefox-'));
  await writeFile(join(profile, 'user.js'), '');
  const child = spawn(driver.binary, ['--port', String(port), '--log', 'fatal'], {
    stdio: 'ignore',
    windowsHide: true,
  });

  async function request(method, route, body) {
    const response = await fetch(endpoint + route, {
      method,
      headers: body === undefined ? {} : { 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(60000),
    });
    const parsed = await response.json().catch(() => ({}));
    if (!response.ok || parsed.value?.error) {
      throw new Error(method + ' ' + route + ': ' + (parsed.value?.message || response.statusText));
    }
    return parsed.value;
  }

  let sessionId;
  const stop = async () => {
    if (sessionId) {
      try {
        await request('DELETE', '/session/' + sessionId);
      } catch {}
      sessionId = null;
    }
    try {
      child.kill();
    } catch {}
    for (let attempt = 0; attempt < 10; attempt++) {
      try {
        await rm(profile, { recursive: true, force: true, maxRetries: 3 });
        break;
      } catch {
        await sleep(250);
      }
    }
  };

  try {
    let ready = false;
    for (let attempt = 0; attempt < 150; attempt++) {
      if (child.exitCode !== null) throw new Error('geckodriver exited with ' + child.exitCode);
      try {
        const status = await request('GET', '/status');
        if (status.ready) {
          ready = true;
          break;
        }
      } catch {}
      await sleep(200);
    }
    if (!ready) throw new Error('geckodriver never became ready');

    const session = await request('POST', '/session', {
      capabilities: {
        alwaysMatch: {
          browserName: 'firefox',
          pageLoadStrategy: 'normal',
          acceptInsecureCerts: true,
          'moz:firefoxOptions': {
            binary: pinned.executablePath,
            args: headed ? ['-profile', profile] : ['-headless', '-profile', profile],
            prefs: { ...PREFS, ...firefoxDownloadPrefs(profile) },
          },
        },
        firstMatch: [{}],
      },
    });
    sessionId = session.sessionId;
    if (!sessionId) throw new Error('geckodriver returned no session id');
    const base = '/session/' + sessionId;
    await request('POST', base + '/timeouts', { pageLoad: 60000, script: 20000 });

    // The subset of the Puppeteer page API that run.mjs uses. evaluate() is
    // given expression strings, which WebDriver needs turned into a return.
    const page = {
      async goto(url) {
        return request('POST', base + '/url', { url });
      },
      async evaluate(script) {
        if (typeof script !== 'string')
          throw new Error('The geckodriver page only evaluates strings');
        return request('POST', base + '/execute/sync', { script: 'return ' + script, args: [] });
      },
      async click(selector) {
        const element = await request('POST', base + '/element', {
          using: 'css selector',
          value: selector,
        });
        const id = element['element-6066-11e4-a52e-4f735466cecf'];
        if (!id) throw new Error('No element id for ' + selector);
        return request('POST', base + '/element/' + id + '/click', {});
      },
    };

    return {
      transport: 'geckodriver ' + driver.version,
      reported: 'firefox/' + (session.capabilities?.browserVersion || ''),
      page,
      pages: async () => [page],
      dispose: stop,
      onDisconnect: async () => {
        // Headed inspection ends when the window is gone, which shows up as a
        // failing status call rather than an event.
        for (;;) {
          try {
            await request('GET', base + '/url');
          } catch {
            return;
          }
          await sleep(500);
        }
      },
    };
  } catch (error) {
    await stop();
    throw error;
  }
}

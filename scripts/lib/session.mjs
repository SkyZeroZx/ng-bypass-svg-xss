// One browser session, whatever it takes to get one.
//
// Chrome and Chromium go through Puppeteer over CDP, which works for every
// build Chrome for Testing publishes. Firefox is attempted through Puppeteer
// over WebDriver BiDi first and falls back to geckodriver when the build is too
// old to accept Puppeteer's capability shape -- see gecko.mjs for the specific
// protocol error. The fallback is attempted rather than version-gated so a
// future Puppeteer or Firefox release does not need a new constant here.
import { launchPinned } from './pin.mjs';
import { launchGecko } from './gecko.mjs';

const BIDI_CAPABILITY_ERROR = /unhandledPromptBehavior|session\.new/i;

export async function launchSession(pinned, { headed = false, cacheDir } = {}) {
  if (pinned.engine !== 'firefox') {
    const launched = await launchPinned(pinned, { headed });
    const pages = await launched.browser.pages();
    const page = pages[0] || (await launched.browser.newPage());
    return {
      transport: 'puppeteer cdp',
      reported: launched.reported,
      page,
      dispose: launched.dispose,
      onDisconnect: () => new Promise((done) => launched.browser.once('disconnected', done)),
    };
  }

  try {
    const launched = await launchPinned(pinned, { headed });
    const pages = await launched.browser.pages();
    const page = pages[0] || (await launched.browser.newPage());
    return {
      transport: 'puppeteer bidi',
      reported: launched.reported,
      page,
      dispose: launched.dispose,
      onDisconnect: () => new Promise((done) => launched.browser.once('disconnected', done)),
    };
  } catch (error) {
    if (!BIDI_CAPABILITY_ERROR.test(String(error.message))) throw error;
    return launchGecko(pinned, { headed, cacheDir });
  }
}

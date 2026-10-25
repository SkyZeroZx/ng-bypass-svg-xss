// Angular's advertised browser support.
//
// Angular picks a Baseline "widely available" snapshot date per major rather
// than naming browser versions, so the floors below are computed, not quoted.
// The dates come from angular.dev/reference/versions and the versions from
// baseline-browser-mapping 2.11.32:
//
//   node -e "import('baseline-browser-mapping').then(m => console.log(
//     m.getCompatibleVersions({ widelyAvailableOnDate: '2026-05-07' })))"
//
// A floor is the oldest release of each browser that the major still claims to
// support. It is not a statement that the vendor still ships security updates
// for it, which is a separate question and the reason these rows matter.
export const BASELINE_FLOORS = {
  20: { date: '2025-04-30', chrome: 107, firefox: 104, safari: '16' },
  21: { date: '2025-10-20', chrome: 111, firefox: 112, safari: '16.4' },
  22: { date: '2026-05-07', chrome: 119, firefox: 119, safari: '17' },
};

export const ANGULAR_BUILDS = { 20: '20.3.34', 21: '21.2.25', 22: '22.2.3' };

// Where each engine stopped accepting the two routes, measured by this lab and
// recorded here so the README tables and the CLI agree on one source.
export const OBSERVED_CUTOFFS = {
  chrome: { dataBlockedFrom: 117, originHandlerBlockedFrom: 122 },
  firefox: { dataBlockedFrom: 122, originHandlerBlockedFrom: null },
};

export function supportsBrowser(angularMajor, engine, version) {
  const floor = BASELINE_FLOORS[angularMajor];
  if (!floor) return false;
  const major = Number(String(version).split('.')[0]);
  if (engine === 'chrome' || engine === 'chromium' || engine === 'edge')
    return major >= floor.chrome;
  if (engine === 'firefox') return major >= floor.firefox;
  return false;
}

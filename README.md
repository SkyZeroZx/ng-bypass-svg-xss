# Angular SVG `<use>` binding lab

The security schema gives SVG one URL entry, for `<a>`
([`dom_security_schema.ts#L106`](https://github.com/angular/angular/blob/v22.2.3/packages/compiler/src/schema/dom_security_schema.ts#L106)):

```ts
registerContext(SecurityContext.URL, SVG_NAMESPACE, [['a', ['href', 'xlink:href']]]);
```

`use` is not in the schema at all, so `<svg><use [attr.href]="value"></use></svg>` compiles to a plain
`ɵɵattribute('href', ctx.value)` with no sanitizer. `<use>` fetches the referenced SVG and puts it in
the page, so I wanted to know when an event handler inside that SVG actually runs in the app.

This repo builds the same components with Angular 20.3.34, 21.2.25 and 22.2.3, pins Chrome and Firefox
builds, and records one JSONL row per case.

## What I tested

Two ways an attacker gets a value into the binding:

|       | Attacker needs                                             | Bound value                     |
| ----- | ---------------------------------------------------------- | ------------------------------- |
| **A** | text in a field the app later binds                        | `data:image/svg+xml;base64,…#x` |
| **B** | an SVG file on the app's own origin, like an avatar upload | `/uploads/avatar.png#x`         |

A row only counts as executed when the handler ran with the app's `window`, read the app's cookie,
and the server received a credentialed request from it. The event also has to be trusted
(dispatched by the browser).

| Browser              | A            | B                      |
| -------------------- | ------------ | ---------------------- |
| Chrome 113–115       | intermittent | no                     |
| Chrome 116           | yes          | yes                    |
| Chrome 117–121       | no           | yes                    |
| Chrome 122, 156      | no           | no, the sprite renders |
| Firefox 104–121      | yes          | yes                    |
| Firefox 122, 158.0.1 | no           | yes                    |

Within each major's Baseline floor, computed with `baseline-browser-mapping` 2.11.32 from the dates on
[angular.dev/reference/versions](https://angular.dev/reference/versions):

| Angular | Floor                    | A runs on                       | B runs on                       |
| ------- | ------------------------ | ------------------------------- | ------------------------------- |
| 22      | Chrome 119 / Firefox 119 | Firefox 119–121                 | Chrome 119–121, Firefox 119–158 |
| 21      | Chrome 111 / Firefox 112 | Chrome 113–116, Firefox 112–121 | Chrome 116–121, Firefox 112–158 |
| 20      | Chrome 107 / Firefox 104 | Chrome 113–116, Firefox 104–121 | Chrome 116–121, Firefox 104–158 |

Firefox still runs B today. Mozilla closed
[bug 1912763](https://bugzilla.mozilla.org/show_bug.cgi?id=1912763) as INVALID because these
handlers only run when everything is same-origin, and an app that stores user SVG files on its own
origin is exactly that case.

Chrome 116–121 looks like it contradicts that bug, where Chrome 72+ does not fire. The bug compared
Chrome 71, 72 and the Chrome of 2024. I ran its testcase 1 on every build from 113: 113–115 do not
fire, 116–121 do, and 122 and later do not. In those builds the handler's `this` is the node in the
external document, while its global is the page. Headed and headless agree, and
`scripts/crosscheck.mjs` gets the same result without Puppeteer.

## What changes the result

From the `origin` and `controls` suites, same on every browser that runs B:

- Still runs: `Content-Disposition: attachment` with `nosniff`, a `.png` path with an
  `image/svg+xml` response, `text/xml` and `application/xml`, a same-origin 302, and a CSP of
  `script-src 'none'; sandbox` on the SVG response itself.
- Blocked: the same bytes served as `image/png`, `text/plain`, `application/octet-stream` or
  `text/html`, a cross-origin redirect or port, and a page CSP with `script-src 'self'`. With the page
  CSP the sprite still renders.
- Without `<use>`, the same file in an `<img>` or opened directly as an attachment never ran.

Handlers that fired: `<image onerror>` and `onclick` everywhere B runs, plus
`foreignObject > img onerror` on Firefox. `<script>`, `svg onload` and SMIL `onbegin` never ran.

## Why `SecurityContext.URL` would not be enough

The URL sanitizer
([`url_sanitizer.ts#L38`](https://github.com/angular/angular/blob/v22.2.3/packages/core/src/sanitization/url_sanitizer.ts#L38-L41))
only rejects `javascript:`, so both values above pass it unchanged. `RESOURCE_URL`, the context of
`iframe[src]` and `object[data]`, rejects them with `NG0904`. `scripts/check-angular.mjs` checks the
schema, the compiled bindings and both sanitizers for the three installed versions without a browser.

## Run it

```bash
npm install
npm run fixtures                                 # AOT builds into .lab/angular{20,21,22}
node scripts/check-angular.mjs                   # schema, bundle and sanitizers, no browser
npm run matrix -- --angular 22 --chrome 121 --firefox 121 --suite floor
npm run matrix -- open --firefox 121 --case data-svg-base64     # one case, headed
node scripts/crosscheck.mjs --mode origin 115 116 121 122
npm run matrix:summary -- evidence/*.jsonl
```

Versions are a number, `stable`, `latest`, `esr` or `115.43.1esr`. Suites: `floor`, `data`, `origin`,
`sinks`, `controls`, `full`. `--help` lists every flag.

To check by hand, start your app however you like and open it in the exact version you want:

```bash
npm run browser -- --chrome 121 http://localhost:4200
npm run browser -- --firefox 119 http://localhost:4200
```

It downloads the build if it isn't cached and opens it with a new profile and nothing attached, no
CDP or WebDriver. The profile is deleted when you close the window, and Firefox has updates turned off
so an old build stays that build.

Browsers come from `@puppeteer/browsers` into a cache outside the repo (`%LOCALAPPDATA%` or
`~/.cache`), profiles are temporary, and everything the attacker controls is generated in memory on a
loopback origin. Firefox below 125 rejects Puppeteer's BiDi capabilities, so those builds go through
geckodriver behind the same page API. The harness refuses to write a row if the launched browser is not
the pinned one. Cypress was not an option: it can't pin a browser version and it runs the app in an
iframe, which changes the origin handling this is testing.

## Evidence

Each row has the browser build, bundle hash, bound URL, the HTTP responses the server sent for that
case, what the handler reported (where it ran, event type, `isTrusted`, cookie) and whether the server
saw the credentialed request. Verdicts are derived from those fields.

| File                                    | Contents                                                             |
| --------------------------------------- | -------------------------------------------------------------------- |
| `evidence/floor-{chrome,firefox}.jsonl` | 4 `data:` and 4 same-origin cases, three Angular builds, 16 browsers |
| `evidence/data-*.jsonl`                 | 10 `data:` spellings and 7 negative controls                         |
| `evidence/origin-*.jsonl`               | 16 response, path and redirect variants plus the Angular cases       |
| `evidence/sinks-*.jsonl`                | 9 handler types                                                      |
| `evidence/controls-*.jsonl`             | the same file through `<img>` and direct navigation                  |
| `evidence/crosscheck.txt`               | `scripts/crosscheck.mjs` runs, Chrome 113–156                        |

2,456 rows, 645 executions, 1 error. Every execution read the page cookie and the server saw its
credentialed request. No negative control executed. The only control expected to run is opening the
file directly with `inline`, which is ordinary stored SVG XSS and not about `<use>`.

"Intermittent" for Chrome 113–115 comes from `crosscheck.txt`: 8 launches per spelling, 15, 20 and 16
hits out of 24 on 113, 114 and 115, against 24 of 24 on 116 and 0 of 24 on 117–119. The harness agrees
(about half the rows on 115).

## Not covered

- Safari, WebKit, Android WebView and iOS.
- Chrome before 113. Chrome for Testing starts there, and Puppeteer can't attach to 113 and 114, so
  those two are only in `crosscheck.txt`.
- A real application. This needs an app that binds untrusted input to `<use>` and a victim who opens
  the page. Picking an icon for your own page is self-XSS.
- The second `control-direct-attachment` run on Firefox 158 errors, because the BiDi session stays on
  the download. The first run is clean.

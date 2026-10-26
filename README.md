# Angular SVG `<use>` binding lab

The security schema gives SVG one URL entry, for `<a>`
([`dom_security_schema.ts#L106`](https://github.com/angular/angular/blob/v22.2.3/packages/compiler/src/schema/dom_security_schema.ts#L106)):

```ts
registerContext(SecurityContext.URL, SVG_NAMESPACE, [['a', ['href', 'xlink:href']]]);
```

`use` is not in the schema, so `<svg><use [attr.href]="value"></use></svg>` compiles to a plain
`ɵɵattribute('href', ctx.value)` with no sanitizer. `<use>` fetches the referenced SVG and clones it
into the page, so I wanted to know when a handler inside that clone runs in the app.

This repo builds the same components with Angular 20.3.34, 21.2.25 and 22.2.3, pins the browser builds
and writes one JSONL row per case. A row counts as executed only when the handler ran with the app's
`window`, read the app's cookie, and the server logged a credentialed request from it, on a trusted
event. The verdict only sees script: a `no` below means no handler ran, not that the document was not
fetched, parsed and rendered, that it sent no credentialed request of its own, or that nothing
navigated.

## Two ways the attacker gets a value in

|       | Attacker needs                             | Bound value                     |
| ----- | ------------------------------------------ | ------------------------------- |
| **A** | text in a field the app later binds        | `data:image/svg+xml;base64,…#x` |
| **B** | SVG bytes at a URL on the app's own origin | `/uploads/avatar.png#x`         |

B needs no upload and no SVG document: `<use>` resolves a fragment to an element id, so any same-origin
response that parses as XML and holds the attacker's subtree is enough.

| Browser          | A            | B                      |
| ---------------- | ------------ | ---------------------- |
| Chrome 113–115   | intermittent | no                     |
| Chrome 116       | yes          | yes                    |
| Chrome 117–121   | no           | yes                    |
| Chrome 122–158   | no           | no, the sprite renders |
| Firefox 104–121  | yes          | yes                    |
| Firefox 122–159  | no           | yes                    |
| WebKit 16.0–27.2 | no           | yes                    |

Within each major's Baseline floor, computed with `baseline-browser-mapping` 2.11.32 from the dates on
[angular.dev/reference/versions](https://angular.dev/reference/versions):

| Angular | Floor                    | A runs on                       | B runs on                       |
| ------- | ------------------------ | ------------------------------- | ------------------------------- |
| 22      | Chrome 119 / Firefox 119 | Firefox 119–121                 | Chrome 119–121, Firefox 119–159 |
| 21      | Chrome 111 / Firefox 112 | Chrome 113–116, Firefox 112–121 | Chrome 116–121, Firefox 112–159 |
| 20      | Chrome 107 / Firefox 104 | Chrome 113–116, Firefox 104–121 | Chrome 116–121, Firefox 104–159 |

I computed no floors for Safari, but WebKit runs B on all 19 builds I pinned, so B is in range for all
three majors there too. Firefox still runs B today, and Mozilla closed
[bug 1912763](https://bugzilla.mozilla.org/show_bug.cgi?id=1912763) as INVALID because these handlers
run only when everything is same-origin, which an app that stores user SVG files on its own origin is.
That bug has Chrome 72+ not firing, but it compared Chrome 71, 72 and the Chrome of 2024. I ran its
testcase 1 on every build from 113, headed, headless and without Puppeteer, and got the window above.

## What changes the result

| Condition                              | Chrome 116–121 | Firefox | WebKit         |
| -------------------------------------- | -------------- | ------- | -------------- |
| same-origin, with or without CORS      | required    | required | required          |
| a 2xx response                         | required    | required | required          |
| an XML or SVG media type               | required    | required | **never checked** |
| a fragment in the URL                  | required    | required | **not from 26.5** |
| `attachment`, `nosniff`, a `.png` path | no effect   | ditto    | ditto             |
| CSP on the SVG response itself         | no effect   | ditto    | ditto             |
| page CSP with `script-src 'self'`      | blocks      | blocks   | blocks            |

With the page CSP the sprite still renders. A cross-origin redirect or port is blocked everywhere;
`Access-Control-Allow-Origin: *`, an echoed origin with credentials and `crossorigin="anonymous"` do
not change it. Without `<use>`, the same file in an `<img>` or opened directly as an attachment never
ran. On WebKit no `data:` URL reached the document in 30 spellings, the box 0x0 every time, so there
the refusal is at the load and not at the handler.

The `xml` suite varies the document around the attacker's `<svg id="x">`, all served as `text/xml` so
the media type is not the variable:

| Response body                                              | Chrome 121 | Firefox 156 | WebKit |
| ---------------------------------------------------------- | ---------- | ----------- | ------ |
| feed, SOAP body, sitemap, XML API, XHTML page, record list  | yes         | yes     | yes    |
| the `<svg>` four levels deep in an unrelated namespace      | yes         | yes     | yes    |
| an `<?xml?>` prologue before it                             | yes         | yes     | yes    |
| bytes after the root element                                | yes         | **no**  | yes    |
| a JSON envelope, bytes before the root, or no `xmlns`       | no          | no      | no     |

## What fires inside the clone

| Sink                                             | Chrome      | Firefox | WebKit |
| ------------------------------------------------ | ----------- | ------- | ------ |
| Sink                                        | Chrome      | Firefox    | WebKit |
| ------------------------------------------- | ----------- | ---------- | ------ |
| `<image onerror>`, literal / relative / 404 | 116–121     | yes        | yes    |
| `<rect onclick>` on a trusted click         | 116–121     | yes        | yes    |
| `<image onload>` when the reference resolves| 116–121     | first load | yes    |
| `foreignObject > img onerror`               | no          | yes        | yes    |
| `foreignObject > details[open] ontoggle`    | no          | yes        | yes    |
| `<a href="javascript:">` on a trusted click | **115–122** | yes        | yes    |
| `<script>`, `svg onload`, SMIL `onbegin`    | no          | no         | no     |

`details[open] ontoggle` needs no interaction **and no resource load**. `<a href="javascript:">` is not
a handler at all but a live hyperlink in the clone, which is why it runs on Chrome 115 and 122 where
every handler is inert. A handler body held in an XML entity runs wherever the plain spelling does.

`<image onload>` on Firefox fires the first time the referenced document loads and not on repeats in the
same session, while the sprite keeps rendering: 1 of 2 runs on 104, 121 and 122, and 1 of 6 on a run of
six. Chrome 116 and 121 and both WebKit builds fire it every time.

## The Angular layer

Both spellings the schema registers for `<a>` reach `<use>` with nothing attached. After that the shape
of the bound string, and of the template around it, decides:

| Route                      | Binding                              | Chrome 116–121 | Firefox | WebKit 16.0 | WebKit ≥26.5 |
| -------------------------- | ------------------------------------ | -------------- | ------- | ----------- | ------------ |
| `same-origin-svg`          | `[attr.href]="'/asset.svg#x'"`       | yes         | yes     | yes         | yes          |
| `same-origin-xlink`        | `[attr.xlink:href]`                  | yes         | yes     | yes         | yes          |
| `same-origin-fragmentless` | `[attr.href]="'/asset.svg'"`         | no          | no      | no          | **yes**      |
| `xml-endpoint`             | `[attr.href]="'/api/profile.xml#x'"` | yes         | yes     | yes         | yes          |
| `use-inside-anchor`        | the same icon inside `<a href>`      | yes         | yes     | yes         | yes          |
| `use-inside-button`        | inside `<button (click)>`            | yes         | yes     | yes         | yes          |
| `fragment-only`            | `[attr.href]="'/safe.svg#' + id"`    | no          | no      | no          | no           |

`xml-endpoint` is not an upload: the component binds one of the app's own XML endpoints, and 9 of the
12 envelopes above run through it. The two wrapping routes carry the cloned-anchor sink, so one click
on the icon runs the attacker's `javascript:` and not the app's `href`: the page never reached `/safe`.
In `use-inside-button` the app's own handler ran as well, its rendered counter going to 1, on Chrome
121, Firefox 156 and WebKit 16.0, while WebKit 27.2 left it at 0 and ran only the clone.
`fragment-only` binds a hostile icon id into a reviewed sprite and stays inert on every engine;
`same-origin-fragmentless` is the opposite end, no concatenation and no `#` at all, which is all
current Safari needs.

`scripts/check-angular.mjs` checks the schema, the compiled bindings and both sanitizers for the three
installed versions without a browser. The URL sanitizer
([`url_sanitizer.ts#L38`](https://github.com/angular/angular/blob/v22.2.3/packages/core/src/sanitization/url_sanitizer.ts#L38-L41))
only rejects `javascript:`, so both values above pass it unchanged, while `RESOURCE_URL`, the context
of `iframe[src]` and `object[data]`, rejects them with `NG0904`.

## Run it

```bash
npm install
npm run fixtures                                 # AOT builds into .lab/angular{20,21,22}
node scripts/check-angular.mjs                   # schema, bundle and sanitizers, no browser
npm run matrix -- --angular 22 --chrome 121 --firefox 121 --suite floor
npm run matrix -- --angular 22 --chrome 121 --suite xml
npm run matrix -- --angular 22 --chrome 122 --suite sinks --case sink-anchor-javascript
npm run matrix -- open --firefox 121 --case data-svg-base64     # one case, headed
npm run matrix:summary -- evidence/*.jsonl
```

Versions are a number, `stable`, `latest`, `esr` or `115.43.1esr`. Suites: `floor`, `data`, `origin`,
`xml`, `sinks`, `controls`, `full`. `--help` lists every flag. `npm run browser -- --chrome 121 <url>`
opens one build by hand against your own app, with a throwaway profile and nothing attached. Builds
come from `@puppeteer/browsers` into a cache outside the repo, Firefox below 125 goes through
geckodriver behind the same page API, and the harness refuses to write a row if the launched browser is
not the pinned one.

## Evidence

Each row carries the browser build, bundle hash, bound URL, the HTTP responses, what the handler
reported and whether the server saw the credentialed request, so re-reading the JSONL audits a claim.

| File                                    | Contents                                                             |
| --------------------------------------- | -------------------------------------------------------------------- |
| `evidence/floor-{chrome,firefox}.jsonl` | 4 `data:` and 4 same-origin cases, three Angular builds, 16 browsers |
| `evidence/data-*.jsonl`                 | 16 `data:` spellings and the negative controls                       |
| `evidence/origin-*.jsonl`               | response, path and redirect variants plus the Angular cases          |
| `evidence/xml-*.jsonl`                  | 12 envelopes, both layers, through `/api/profile.xml` on the Angular one |
| `evidence/sinks-*.jsonl`                | the 12 handler and hyperlink sinks                                   |
| `evidence/anchor-chrome.jsonl`          | the cloned-anchor ceiling, Chrome 115 to 156                         |
| `evidence/anchor-angular.jsonl`         | the two wrapping routes under the cloned-anchor sink                 |
| `evidence/controls-*.jsonl`             | the same file through `<img>` and direct navigation                   |
| `evidence/crosscheck.txt`               | `scripts/crosscheck.mjs` runs, Chrome 113–156                        |

3,002 rows, 930 executions, 1 error. Every execution read the page cookie and the server saw its
credentialed request, and no negative control executed. The only one expected to run is the file opened
directly with `inline`, ordinary stored SVG XSS and not about `<use>`. "Intermittent" for Chrome
113–115 is 15, 20 and 16 hits out of 24 launches, against 24 of 24 on 116. The WebKit rows are not in
`evidence/`: 2,130 rows and 612 executions over 19 builds, 11 versions from 16.0 to 27.2, run through
Playwright with this repo's corpus and verdict code but a runner that lives outside it, so
`npm run matrix` does not reproduce them. Those builds are Playwright's WebKit, not Safari itself.

## Manual Testing

```bash
ng serve
npm run browser -- --chrome 116 http://localhost:4200
```

Any pinned build, or your own Chrome, Firefox or Safari at the same URL. `ng serve` only serves the app,
so the bytes behind the binding are yours to serve.

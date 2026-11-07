# Browser page

`web/` is a static page that runs the key checks of RangeProbe from a browser. It exists to show
what *this browser* receives: the same URL can behave differently for a page than for the CLI,
because of CORS, header visibility, automatic content decoding and the preflight rules. The page
is a companion to the CLI, not a replacement: it runs five checks, not ten, and it sees less.

It is plain HTML, CSS and ES modules. No build step, no dependencies, no server of ours: the
requests go from the browser straight to the URL you enter, and the reference file is read in place.

## Use

1. Open the page, enter the file URL and choose a local copy of the file (the reference).
2. The page lists the requests it will send. **Start** sends them one after another; **Cancel**
   stops the run and lists the unsent checks as skipped.
3. Each check shows two separate results:
   - **Bytes vs reference**: the received bytes equal the matching slice of the reference, differ
     from it, or could not be compared (with the reason).
   - **Protocol evidence**: whether the page could read the headers it needed. `Content-Range` is the
     one that matters; on a cross-origin response it is often hidden.
4. **Download JSON report** saves the report ([format](report-format.md#browser-report)). If the URL
   has query parameters, the page warns that they may be secrets and offers to save the report with
   their values replaced by `REDACTED`.

A correct body with a hidden `Content-Range` is reported as `inconclusive` with a matching
bytes result: the bytes are right, the header half of the check could not be completed. That is
not a failure of the server and not a pass.

## What runs

The plan is the CLI's planner (`internal/plan`) restricted to its key checks, with the same offsets
and the same skip reasons: `first-byte`, `head`, `middle`, `tail` and `suffix`. The CLI's
`open-ended`, `past-eof`, `unsatisfiable`, `overlap` and `reread` are not run. `testdata/shared/plan.json`
holds the cases both implementations must satisfy.

- An empty reference sends only `first-byte`; the others are skipped with `SKIP_ZERO_LENGTH`.
- A file smaller than the probe size is read whole by each check (the range is clamped to the file).
- Offsets use the length the server reported when the page could read it (`Content-Range`), else the
  length of the reference.

## Limits

Every request is a `GET` with `credentials: omit`, `cache: no-store`, `redirect: follow`,
`referrerPolicy: no-referrer` and one header, `Range`.

| Limit | Value |
| --- | --- |
| Requests | 5 planned, 8 at most |
| Sampled range length | 4 KiB (1 B to 1 MiB) |
| Body bytes of one response | 2 MiB |
| Body bytes over the run | 8 MiB |
| A `200` to a range request | 64 KiB read, then the transfer is cancelled |
| Bodies of `416` and error statuses | 4 KiB |
| Time per request, including its body | 30 s (1 to 120 s) |
| Time for the whole run | 2 min (1 to 600 s) |

A server that ignores `Range` and starts sending the whole file is read for 64 KiB, compared
with the start of the reference, and cut off with `reader.cancel()`. The lab proves this against a
256 MiB response (see below).

## What a page cannot see

These limits are the reason the page reports what it reports.

- **Raw bytes.** The browser sets `Accept-Encoding` and decodes content codings before the page
  reads the body. The page compares the bytes it receives. They equal the bytes on the wire only if
  no coding was applied.
- **Cross-origin headers.** Only CORS-safelisted headers (`Content-Length`, `Content-Type`,
  `Last-Modified`, `Cache-Control`, ...) and those in `Access-Control-Expose-Headers` are readable.
  A header that is not readable looks the same as one that is absent. So on a cross-origin 206 a
  missing `Content-Range` is reported as `CONTENT_RANGE_NOT_VISIBLE` (inconclusive), never as
  `STATUS_206_NO_CONTENT_RANGE`. Only a same-origin response (`response.type === "basic"`) shows all
  headers.
- **Why a request failed.** A rejected `fetch()` carries `TypeError` and a short message, no cause.
  CORS refusal, a rejected preflight, DNS, connection or TLS failure, mixed content, an extension
  and being offline look alike. The page shows the error it got and `FETCH_REJECTED` lists these as
  possible causes. For a cross-origin target CORS is *one possible cause*, never an established one.
  The browser's developer console usually names the cause; a page cannot read it.
- **Redirects.** The browser follows them; the page sees the final URL and `redirected`.

### When bytes are compared

The body is compared with the reference only when all of these hold:

1. The status is `206`, or `200` (then only the first 64 KiB are compared, as a sanity check).
2. No `Content-Encoding` other than `identity` is readable. A readable coding gives
   `ENCODING_DECODED_BY_BROWSER` and no comparison.
3. The interval the bytes belong to is known: the readable `Content-Range`, or, when it is hidden,
   the requested interval resolved against the reference length, and only if the body has exactly
   that length (a shorter or longer body is `not_compared`: the interval it belongs to is unknown).
4. The reference could be read. A read error is reported as `REFERENCE_CHANGED`.

A difference is always reported as *bytes differ from the reference* (`BYTES_MISMATCH_REFERENCE`):
the reference may be another file or version. If the server reports another length than the
reference, or ETag, length or `Last-Modified` change during the run, the difference becomes
`inconclusive`, as in the CLI.

When no `Content-Encoding` is readable on a cross-origin response, the page cannot tell absent from
hidden, so the encoding is recorded as `not_observable` on each check and once in the run
(`ENCODING_NOT_OBSERVABLE`). It does not stop a pass, but two things follow:

- rules that equate the *decoded body length* with a declared length (`BODY_TRUNCATED`,
  `BODY_EXCESS`) are downgraded to `inconclusive`, because a decoded body can differ in length;
- `Content-Length` is not taken as the file length on a `200`, because it may be the encoded length.

Two headers contradicting each other (`Content-Length` against `Content-Range`) involve no body and
stay a violation.

## Same rules as the CLI

The page ports `internal/interpret` for what a page can observe and uses the CLI's diagnostic IDs.
`web/js/registry.js` is generated from `internal/model/diagnostics.go` (kinds, titles, conditions),
and the four IDs only the page emits (`CONTENT_RANGE_NOT_VISIBLE`, `ENCODING_DECODED_BY_BROWSER`,
`ENCODING_NOT_OBSERVABLE`, `FETCH_REJECTED`) are marked in [diagnostics.md](diagnostics.md).

`testdata/shared/judge.json` holds 42 cases: one request, one response, one reference slice and the
expected status, finding IDs, byte result and encoding state. The CLI runs them through
`internal/interpret` (`internal/parity`), the page through `web/test`. Cases that only a page can
produce (hidden headers) are marked `"modes": ["browser"]`; where the two sides intentionally name a
finding differently, the case has `expect_browser`.

Known differences: numbers above 2^53-1 are `NUMBER_OUT_OF_RANGE` in the page (the CLI's limit is
2^63-1); the page does not compute the one-byte shift hint; ETags are compared as whole strings
without the CLI's entity-tag parsing; there are no `If-Match` preconditions.

## Run it locally

You need Go 1.27 or newer for the lab, or any static file server for the page alone.

```bash
go run ./lab/browser -write-reference /tmp/reference.bin
```

This serves the page at `http://localhost:18080` and the test files at `http://127.0.0.1:18081`,
two origins, and writes the 1 MiB reference file the routes serve (also at
`http://localhost:18080/reference.bin`). Open the page, choose the reference and try the routes:

| URL on `http://127.0.0.1:18081` | What the server does | Expected result |
| --- | --- | --- |
| `/ok` | correct bytes, every header exposed | PASS: bytes match, evidence complete |
| `/hidden-content-range` | correct bytes, `Content-Range` not exposed | INCOMPLETE: bytes match, evidence incomplete |
| `/no-cors` | correct bytes, no CORS headers | ERROR: `fetch()` rejected, cause not shown |
| `/wrong-bytes` | correct headers, bytes shifted by one | PROBLEM: bytes differ |
| `/range-ignored` | `200` with the whole file | RANGE IGNORED |
| `/range-ignored-large` | `200` with 256 MiB, paced | RANGE IGNORED; 64 KiB read per request, transfer cancelled |
| `/slow-headers` | headers stall for 20 s | timeout (use a short request timeout) |
| `/slow-body` | half the body, then a stall | timeout after a partial body |
| `/encoded` | `200`, whole file gzip-encoded | ERROR in Chrome: it sends no `Accept-Encoding` on a range request and rejects the coding |

For contrast, the CLI against the same routes passes `/ok`, `/hidden-content-range` and `/no-cors`
(CORS does not exist for it), reports `/wrong-bytes` as a problem and `/range-ignored` as range
ignored. The page can only see what the browser lets a page see.

`http://localhost:18080/data/<route>` serves the same routes same-origin and without CORS: all
headers are readable there, so `hidden-content-range` passes.

`http://127.0.0.1:18081/__stats` shows what the file server saw: requests, preflights, the `Range`
headers, and for `range-ignored-large` the bytes written and the transfers aborted
(`/__reset` clears it). `go run ./lab/browser -h` lists the options (ports, origins, sizes, delay).
The lab listens on loopback only and is not part of the CLI.

Things seen in Chromium 156 with the lab:

- A suffix range (`bytes=-N`) sent one preflight; ranges with a start offset sent none. By the
  Fetch rules a server that does not answer that preflight with
  `Access-Control-Allow-Headers: Range` should then fail only the suffix check; the lab has no route
  for that case, so it was not observed.
- A gzip-encoded response to a range request is rejected by `fetch()` (`ERR_CONTENT_DECODING_FAILED`,
  visible only in the console). Other browsers may decode instead; this was not tested.

### Static page alone

```bash
python3 -m http.server -d web 8000
```

then open `http://localhost:8000`. Opening `index.html` as a `file:` URL does not work: browsers
refuse ES modules from `file:`.

## Hosting the page

Copy the contents of `web/` to any static host. There is nothing to build and no server code.

- Serve `*.js` as `text/javascript`. `index.html` carries a Content-Security-Policy meta tag
  (`script-src 'self'`, `style-src 'self'`, `connect-src http: https:`), so no header is needed.
- Use HTTPS. A page served over HTTPS cannot fetch `http:` URLs except loopback addresses (mixed
  content); the page flags this as a possible cause when a fetch fails.
- A page on the public internet fetching `http://localhost` or a private address may be subject to
  the browser's private-network access rules.
- The target server must let the page's origin read the response, or the page can only report that
  `fetch()` failed:

  ```text
  Access-Control-Allow-Origin: https://your-page.example
  Access-Control-Expose-Headers: Content-Range, Accept-Ranges, ETag, Content-Encoding
  Access-Control-Allow-Headers: Range         (on the preflight answer; needed for bytes=-N)
  ```

Nothing is published by this repository. Deploying the page is a separate step.

## Tests

```bash
go test ./...                       # includes internal/parity and lab/browser
node --test web/test/*.test.js      # Node 20 or newer, no packages
```

The tests cover the shared planner and judging cases, the runner against a fake `fetch` (read limits,
cancelled streams, deadlines, cancellation, rejected fetch, a replaced file), redaction and the
report. The behaviours above that depend on a real browser (CORS, preflight, hidden headers, stream
cancellation, report download, narrow layout) were checked by hand against the lab; there is no
automated browser test in the repository, because it would need a browser-driver dependency.

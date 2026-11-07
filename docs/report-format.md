# Report format

`--json` writes one JSON document. It is versioned by `schema_version` (currently `1`). Within a
schema version fields may be added but never removed or reinterpreted; a breaking change raises the
version. Slices are never `null`; a few optional ones (`verified`, `limits` on a check, `redirects`) are omitted when empty. All URLs and paths are redacted unless `--no-redact` was given
(`run.params.redact_locations`). Header values are never recorded.

```text
schema_version   integer
tool             name, version, repository
run              mode ("reference"|"observe"), started_at, finished_at, duration_ms,
                 target, interrupted, params (all limits and options; user_header_names lists
                 header names only)
reference        name (redacted), size             (reference mode only)
endpoint         final_url, redirects[], varied_between_requests
representation   length (null if the server reported none), length_basis, etag (display form:
                 escaped, cut at 200 characters), etag_strength ("strong"|"weak"|"none";
                 "none" also for an unusable ETag), last_modified, accept_ranges, content_type,
                 stable, changes[]
summary          result ("pass"|"problem"|"range_ignored"|"incomplete"), exit_code, headline,
                 counts{status: n}, mismatch_pattern, key_checks_not_passed[],
                 optional_checks_skipped[]
checks[]         one per planned check (see below)
run_findings[]   findings not tied to one check
verified_claims[]  claims that held, prefixed with the check ID
unsupported[]    capabilities RangeProbe v0.1 does not cover
uncertainty[]    {source, id, text}: why conclusions are limited
assumptions[]    what the results depend on
budget           requests, max_requests, bytes_read, max_total_bytes
```

## Check

```text
id, title, key, claim
status           "pass"|"range_ignored"|"violation"|"byte_mismatch"|"inconclusive"|
                 "transport_error"|"skipped"
skip             {id, reason}                      (skipped checks)
request          method, url, range, headers[], description
                 description is a redacted, secret-free rendering suitable for bug reports
response         status, proto, final_url, redirects[], headers[], other_header_count,
                 content_length, chunked. Only well-known headers are listed.
body             bytes_read, read_limit, complete, end_state, sha256, declared_length,
                 reference_comparison
findings[]       see below
verified[]       claims that held (empty unless status is "pass")
limits[]         what a pass in this mode does not prove
duration_ms
```

`body.end_state` is one of `complete`, `truncated`, `excess`, `limit`, `error`, `prefix` (a full
`200` response read only up to the sanity limit), `discarded` (a `416` or error body read
briefly), `unread`.

`reference_comparison`: `compared_bytes`, `expected_first`, `expected_last`, `match`,
`first_mismatch_offset`, `mismatch_count`, `bytes_beyond_reference`, `shift_hint`,
`expected_sha256`, and, only with `--dump-mismatch`, `fragment`. No response bytes are stored
otherwise.

## Finding

```text
id           stable ID, see diagnostics.md
kind         "violation"|"byte_mismatch"|"range_ignored"|"inconclusive"|"transport_error"|"note"
message      what was observed
conditions[] facts that must hold for the diagnostic to apply
evidence[]   {key, value} from this exchange
limits[]     what the finding does not establish
```

The `status` of a check is the highest-priority kind among its non-note findings, in the order
`violation`, `byte_mismatch`, `transport_error`, `inconclusive`, `range_ignored`, `pass`.

## HTML

`--html` writes the same information as a single self-contained page: inline CSS with light and
dark themes, no scripts, no external resources, no links. It carries a restrictive
Content-Security-Policy meta tag. Everything from the network or the file system is escaped.

## Browser report

The page in `web/` (see [browser.md](browser.md)) writes its own document. It shares the finding
IDs, kinds and the check statuses with the CLI report but not its layout, because a page records
things the CLI cannot (what was readable) and cannot record others (raw requests, HTTP version).

```text
format           "rangeprobe-browser-report"
schema_version   integer (currently 1; fields may be added, never removed or reinterpreted)
tool             name, component ("browser-page"), version, repository
capture          origin ("browser"), api ("fetch"), page_origin, request_options (method, mode,
                 credentials "omit", cache, redirect, referrer_policy, request_headers,
                 accept_encoding), observation (what bytes, headers, errors and redirects mean
                 for a page)
run              started_at, finished_at, duration_ms, target, target_redacted, target_origin,
                 cross_origin, interrupted, stopped_by (null|"cancelled"|"run_timeout"),
                 params (limits), checks_run[], checks_omitted[]
reference        name, size                          (no content, no whole-file hash)
endpoint         final_url, varied_between_requests
representation   length, length_basis, etag, last_modified, accept_ranges, content_type, stable,
                 changes[], note. Only what the page could read; null may mean not exposed.
summary          result, headline, axes, counts, bytes{match,mismatch,not_compared},
                 evidence{complete,incomplete}, key_checks_not_passed[]
checks[]         see below
run_findings[]   findings not tied to one check
verified_claims[], unsupported[], uncertainty[], assumptions[], budget
```

`summary.result` is `pass`, `problem`, `range_ignored` or `incomplete`, derived as in the CLI.

A check:

```text
id, title, key, claim
status           "pass"|"range_ignored"|"violation"|"byte_mismatch"|"inconclusive"|
                 "transport_error"|"skipped"
skip             {id, reason}                       (skipped checks)
request          range
fetch            outcome ("response"|"rejected"|"timeout"|"cancelled"|"run_timeout"),
                 error {name, message}              (rejected only)
response         status, type ("basic" same-origin | "cors"), redirected, final_url,
                 headers[] (readable ones, from a fixed list), other_header_count, content_length
body             bytes_read, read_limit, complete, end_state, declared_length
bytes            outcome ("match"|"mismatch"|"not_compared"), reason, scope ("interval"|
                 "prefix_of_full_response"), compared_bytes, expected_first, expected_last,
                 first_mismatch_offset, mismatch_count, bytes_beyond_reference, sha256,
                 expected_sha256   (digests of the compared slices, absent without Web Crypto)
evidence         header_visibility, content_range / content_length / content_encoding
                 ("visible"|"absent"|"not_visible"|"not_applicable"), complete (true|false|null),
                 missing[]
representation   encoding ("identity"|"not_observable"|"encoded"), content_encoding
findings[]       as in the CLI report (id, kind, message, conditions, evidence, limits)
verified[]       claims that held (only for a passing check)
limits[], duration_ms
```

`bytes` and `evidence` are the two axes: whether the received bytes equal the reference, and
whether the page could see the headers it needed. `status` is derived from the findings, so a check
with matching bytes and a hidden `Content-Range` is `inconclusive`.

The report holds no response body and no part of the reference file. URLs lose user info and
fragments; with `target_redacted: true` query values in every URL and URL-like text are replaced by
`REDACTED` (names are kept). The page asks before exporting a URL that has a query.

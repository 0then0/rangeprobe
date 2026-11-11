# Diagnostics

<!-- Generated from internal/model/diagnostics.go. Do not edit by hand:
     RANGEPROBE_UPDATE_DOCS=1 go test ./internal/model -run TestDiagnosticsDoc -->

Every finding in a report carries a stable ID, the conditions that must hold for
it to apply, concrete evidence from the exchange, and the limits of what it
proves. IDs do not change within a major version; new IDs may be added.

A check's status is the most significant kind among its findings, in this order:
`violation`, `byte_mismatch`, `transport_error`, `inconclusive`, `range_ignored`, `pass`.
Notes never change a status. A skipped check carries a skip reason ID instead of a finding.

## Protocol-contract violations

The response contradicts RFC 9110 or contradicts itself. Exit code 1.

### `BODY_EXCESS`

Body is longer than the declared range.

Requires:

- status is 206
- the stream delivered at least one octet beyond the Content-Range length
- the extra octet fit in the remaining byte budget

### `BODY_TRUNCATED`

Body ended before the declared length.

Requires:

- status is 206 (or 200 with Content-Length)
- the peer closed the stream cleanly or the framing ended early before the declared octets arrived
- the read was not cut by a RangeProbe budget

### `CONTENT_LENGTH_RANGE_MISMATCH`

Content-Length disagrees with the Content-Range interval.

Requires:

- status is 206
- Content-Range is valid
- Content-Length is present and differs from last-pos - first-pos + 1

### `CONTENT_RANGE_INVALID`

Content-Range is malformed or self-contradictory.

Requires:

- status is 206 (or 416)
- value fails the RFC 9110 14.4 grammar, has last-pos < first-pos, complete-length <= last-pos, a unit other than bytes, or is repeated

### `CONTENT_RANGE_OUTSIDE_REQUEST`

Content-Range is not within the requested range.

Requires:

- status is 206
- Content-Range is valid
- the interval implied by the request and the response's own complete length does not contain the declared interval

### `IF_RANGE_FALSE_206`

206 despite a false If-Range condition.

Requires:

- If-Range reached the final request
- the sent strong tag differs from the current response strong ETag, or the sent tag is weak
- status is 206
- RFC 9110 13.1.5 requires ignoring Range when the condition is false

### `OVERLAP_INCONSISTENT`

Overlapping ranges disagree under one strong ETag.

Requires:

- two complete 206 bodies with overlapping intervals
- both responses carry the same strong ETag and no conflicting length or Last-Modified
- the overlapping octets differ

### `REREAD_INCONSISTENT`

Re-reading the same range returned different bytes under one strong ETag.

Requires:

- two complete 206 bodies for the same interval
- both responses carry the same strong ETag and no conflicting length or Last-Modified
- the octets differ

### `SATISFIABLE_GOT_416`

416 returned although the range is satisfiable under the length it reports.

Requires:

- status is 416 with Content-Range bytes */length
- the requested range is satisfiable for that length

### `STATUS_206_NO_CONTENT_RANGE`

206 response has no Content-Range.

Requires:

- status is 206
- Content-Type is not multipart/byteranges
- the response headers are fully visible (always for the CLI; in a browser only for a same-origin response)
- RFC 9110 15.3.7.1 requires Content-Range in a single-part 206

### `UNSATISFIABLE_GOT_206`

206 returned for a range that is unsatisfiable under the reported length.

Requires:

- status is 206 with a valid Content-Range carrying a complete length
- the request's first-pos is at or beyond that length

## Byte mismatch with the reference

An observation, not a diagnosis: the reference may be another file or version. Exit code 1.

### `BYTES_MISMATCH_REFERENCE`

Response bytes differ from the reference slice.

Requires:

- reference mode
- response is 206 (or a 200 prefix) and declares no content coding other than identity
- the reference file length equals the length the response reports, when it reports one
- its representation signals do not conflict with earlier responses

## Range ignored

Allowed by RFC 9110 section 14.2, but incompatible with random access. Not a violation. Exit code 2.

### `RANGE_IGNORED`

Server ignored the Range header and sent a full 200 response.

Requires:

- a single satisfiable or unsatisfiable range was requested
- status is 200
- RFC 9110 14.2 lets a server ignore Range, so this is not a violation

## Inconclusive

The evidence does not support a verdict. Exit code 3 unless a confirmed problem exists.

### `BODY_LIMIT_REACHED`

Reading stopped at a byte limit before the declared length.

Requires:

- the declared body is longer than the per-response limit or remaining byte budget

### `CONSISTENCY_UNATTRIBUTED`

Bytes differ but one representation is not established.

Requires:

- two complete bodies for overlapping or identical intervals differ
- no shared strong ETag proves they come from one representation

### `CONTENT_RANGE_NOT_VISIBLE`

Content-Range is not readable by the page.

Emitted only by the browser page, never by the CLI.

Requires:

- browser capture
- status is 206 or 416
- the response is cross-origin and no Content-Range is among the headers readable by the page
- the page cannot tell an absent header from one the server did not list in Access-Control-Expose-Headers

### `ENCODING_DECODED_BY_BROWSER`

The browser decodes a content coding before the page reads the body.

Emitted only by the browser page, never by the CLI.

Requires:

- browser capture
- the response declares a Content-Encoding other than identity in a header the page can read
- the page cannot request identity, so the bytes it receives are decoded
- bytes are not compared with the reference

### `ENCODING_UNSUPPORTED`

Response carries a content coding other than identity.

Requires:

- Accept-Encoding: identity was requested
- response has Content-Encoding other than identity
- RangeProbe does not compare encoded bytes with a reference

### `HTTP_STATUS_UNEXPECTED`

Status does not allow a range verdict.

Requires:

- status is not 200, 206 or 416 and is not a server error

### `IF_RANGE_PREMISE_UNKNOWN`

If-Range premise cannot be established.

Requires:

- the validator was removed on redirect, a usable current strong ETag is absent, or the generated mismatch tag matches the response

### `IF_RANGE_RESOURCE_CHANGED`

Final resource differs from baseline.

Requires:

- if-range mode
- the final response URL differs from the baseline URL
- ETags are scoped to a resource; cross-resource bytes are not compared

### `IF_RANGE_STATUS`

Status does not establish If-Range fallback.

Requires:

- if-range mode
- status is 416; no successful fallback is implied

### `MULTIPART_UNSUPPORTED`

Multipart/byteranges response to a single-range request.

Requires:

- status is 206
- Content-Type is multipart/byteranges
- multipart parsing is not supported in v0.1

### `NUMBER_OUT_OF_RANGE`

A number in the response exceeds the supported 63-bit range.

Requires:

- the numeral is syntactically valid
- it exceeds the largest value the tool represents exactly (9223372036854775807 in the CLI, 9007199254740991 in the browser page)

### `PRECONDITION_FAILED`

If-Match precondition failed (412).

Requires:

- --preconditions was set
- status is 412

### `REFERENCE_CHANGED`

Reference file changed while the run was in progress.

Requires:

- size or modification time of the reference differs between start and end of the run

### `REFERENCE_SIZE_MISMATCH`

Reference length differs from the length the server reports.

Requires:

- reference mode
- the server reported a complete length
- the reference file has a different length

### `RELATION_INPUT_UNAVAILABLE`

Bodies needed for a consistency comparison are unavailable.

Requires:

- one of the compared responses was not a complete verified 206 body

### `REPRESENTATION_CHANGED`

Representation signals changed between responses.

Requires:

- a strong or weak ETag, complete length, Last-Modified or content coding differs from an earlier response

### `UNEXPECTED_416`

416 without a Content-Range for a range that earlier responses suggest is satisfiable.

Requires:

- status is 416 without a usable complete length
- an earlier response reported a length for which the range is satisfiable

## Transport and infrastructure errors

The probe could not complete. Exit code 3 unless a confirmed problem exists.

### `BODY_READ_ERROR`

Reading the body failed.

Requires:

- a network error other than a clean early end of stream occurred

### `CANCELLED`

Run cancelled.

Requires:

- the process received an interrupt (CLI) or the user pressed Cancel (browser page)

### `FETCH_REJECTED`

Fetch rejected before a readable response.

Emitted only by the browser page, never by the CLI.

Requires:

- browser capture
- the Fetch API rejected the request with an error instead of a response
- the error names no cause: a CORS refusal, a rejected preflight, DNS, connection or TLS failure, mixed content, a blocking extension and an offline browser look alike to the page

### `HTTP_SERVER_ERROR`

Server or gateway error.

Requires:

- status is 5xx, 408 or 429

### `REDIRECT_LIMIT`

Too many redirects.

Requires:

- redirect count exceeded --max-redirects

### `REDIRECT_REFUSED`

Redirect refused by policy.

Requires:

- redirect target would downgrade HTTPS, use a non-HTTP scheme, or be malformed

### `REQUEST_FAILED`

Request failed before a response was received.

Requires:

- DNS, connection, TLS or protocol failure

### `REQUEST_TIMEOUT`

Request timed out.

Requires:

- the per-request or whole-run timeout expired

## Notes

Context that never changes a status.

### `ENCODING_NOT_OBSERVABLE`

The page cannot observe whether the browser decoded a content coding.

Emitted only by the browser page, never by the CLI.

Requires:

- browser capture
- the response is cross-origin and no Content-Encoding is among the headers readable by the page
- an absent header and one the server did not expose look alike

### `ENDPOINT_VARIED`

Final endpoint differed between requests.

Requires:

- redirects led to different hosts or paths for different probes

### `EXTRA_BYTE_CHECK_SKIPPED`

Excess-byte check not performed.

Requires:

- the remaining byte budget or body limit left no room to read one octet beyond the declared length

### `FULL_RESPONSE_CONTENT_RANGE`

Content-Range on a 200 response.

Requires:

- status is 200
- RFC 9110 14.4 gives Content-Range no meaning for 200

### `IF_RANGE_FALLBACK`

200 fallback observed.

Requires:

- If-Range reached the final request
- the condition is false
- status is 200
- body completeness is reported separately; an unread tail is not verified

### `IF_RANGE_WEAK_INPUT`

Deliberately invalid weak If-Range client input.

Requires:

- --weak-if-range selected
- clients MUST NOT generate weak If-Range; the server must use strong comparison (RFC 9110 13.1.5)

### `PARTIAL_RESPONSE`

206 covers a subset of the requested range.

Requires:

- declared interval lies strictly inside the requested interval
- RFC 9110 15.3.7 allows sending fewer bytes

### `RANGE_416_CONTENT_RANGE_MISSING`

416 without Content-Range.

Requires:

- status is 416
- RFC 9110 14.4 says a server SHOULD include Content-Range bytes */length

### `WEAK_VALIDATORS`

Only weak or no strong validators observed.

Requires:

- no strong ETag was seen (a repeated, malformed or oversize ETag does not count)

## Skip reasons

The check was not sent. A skipped key check prevents a complete PASS (exit code 3).

### `SKIP_BODY_LIMIT`

Expected response exceeds the per-response limit.

### `SKIP_BUDGET_BYTES`

Remaining byte budget too small for this check.

### `SKIP_BUDGET_REQUESTS`

Request budget exhausted.

### `SKIP_BUDGET_TIME`

Whole-run timeout reached.

### `SKIP_CANCELLED`

Run cancelled before this check.

### `SKIP_IF_RANGE_VALIDATOR`

Baseline validator unavailable.

### `SKIP_OVERFLOW`

Offsets would exceed the 63-bit range.

### `SKIP_REMOTE_SIZE`

The server did not report a representation length.

### `SKIP_SIZE_UNKNOWN`

Representation length is unknown.

### `SKIP_TOO_SMALL`

Representation or probe size too small for this check.

### `SKIP_ZERO_LENGTH`

Representation has zero length.


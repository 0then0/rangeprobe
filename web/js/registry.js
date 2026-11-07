// Generated from internal/model/diagnostics.go. Do not edit by hand:
//   RANGEPROBE_UPDATE_DOCS=1 go test ./internal/parity -run TestRegistryJS
export const REGISTRY = {
  "BODY_EXCESS": {
    "kind": "violation",
    "title": "body is longer than the declared range",
    "conditions": [
      "status is 206",
      "the stream delivered at least one octet beyond the Content-Range length",
      "the extra octet fit in the remaining byte budget"
    ]
  },
  "BODY_LIMIT_REACHED": {
    "kind": "inconclusive",
    "title": "reading stopped at a byte limit before the declared length",
    "conditions": [
      "the declared body is longer than the per-response limit or remaining byte budget"
    ]
  },
  "BODY_READ_ERROR": {
    "kind": "transport_error",
    "title": "reading the body failed",
    "conditions": [
      "a network error other than a clean early end of stream occurred"
    ]
  },
  "BODY_TRUNCATED": {
    "kind": "violation",
    "title": "body ended before the declared length",
    "conditions": [
      "status is 206 (or 200 with Content-Length)",
      "the peer closed the stream cleanly or the framing ended early before the declared octets arrived",
      "the read was not cut by a RangeProbe budget"
    ]
  },
  "BYTES_MISMATCH_REFERENCE": {
    "kind": "byte_mismatch",
    "title": "response bytes differ from the reference slice",
    "conditions": [
      "reference mode",
      "response is 206 (or a 200 prefix) and declares no content coding other than identity",
      "the reference file length equals the length the response reports, when it reports one",
      "its representation signals do not conflict with earlier responses"
    ]
  },
  "CANCELLED": {
    "kind": "transport_error",
    "title": "run cancelled",
    "conditions": [
      "the process received an interrupt (CLI) or the user pressed Cancel (browser page)"
    ]
  },
  "CONSISTENCY_UNATTRIBUTED": {
    "kind": "inconclusive",
    "title": "bytes differ but one representation is not established",
    "conditions": [
      "two complete bodies for overlapping or identical intervals differ",
      "no shared strong ETag proves they come from one representation"
    ]
  },
  "CONTENT_LENGTH_RANGE_MISMATCH": {
    "kind": "violation",
    "title": "Content-Length disagrees with the Content-Range interval",
    "conditions": [
      "status is 206",
      "Content-Range is valid",
      "Content-Length is present and differs from last-pos - first-pos + 1"
    ]
  },
  "CONTENT_RANGE_INVALID": {
    "kind": "violation",
    "title": "Content-Range is malformed or self-contradictory",
    "conditions": [
      "status is 206 (or 416)",
      "value fails the RFC 9110 14.4 grammar, has last-pos < first-pos, complete-length <= last-pos, a unit other than bytes, or is repeated"
    ]
  },
  "CONTENT_RANGE_NOT_VISIBLE": {
    "kind": "inconclusive",
    "title": "Content-Range is not readable by the page",
    "conditions": [
      "browser capture",
      "status is 206 or 416",
      "the response is cross-origin and no Content-Range is among the headers readable by the page",
      "the page cannot tell an absent header from one the server did not list in Access-Control-Expose-Headers"
    ],
    "browser_only": true
  },
  "CONTENT_RANGE_OUTSIDE_REQUEST": {
    "kind": "violation",
    "title": "Content-Range is not within the requested range",
    "conditions": [
      "status is 206",
      "Content-Range is valid",
      "the interval implied by the request and the response's own complete length does not contain the declared interval"
    ]
  },
  "ENCODING_DECODED_BY_BROWSER": {
    "kind": "inconclusive",
    "title": "the browser decodes a content coding before the page reads the body",
    "conditions": [
      "browser capture",
      "the response declares a Content-Encoding other than identity in a header the page can read",
      "the page cannot request identity, so the bytes it receives are decoded",
      "bytes are not compared with the reference"
    ],
    "browser_only": true
  },
  "ENCODING_NOT_OBSERVABLE": {
    "kind": "note",
    "title": "the page cannot observe whether the browser decoded a content coding",
    "conditions": [
      "browser capture",
      "the response is cross-origin and no Content-Encoding is among the headers readable by the page",
      "an absent header and one the server did not expose look alike"
    ],
    "browser_only": true
  },
  "ENCODING_UNSUPPORTED": {
    "kind": "inconclusive",
    "title": "response carries a content coding other than identity",
    "conditions": [
      "Accept-Encoding: identity was requested",
      "response has Content-Encoding other than identity",
      "RangeProbe does not compare encoded bytes with a reference"
    ]
  },
  "ENDPOINT_VARIED": {
    "kind": "note",
    "title": "final endpoint differed between requests",
    "conditions": [
      "redirects led to different hosts or paths for different probes"
    ]
  },
  "EXTRA_BYTE_CHECK_SKIPPED": {
    "kind": "note",
    "title": "excess-byte check not performed",
    "conditions": [
      "the remaining byte budget or body limit left no room to read one octet beyond the declared length"
    ]
  },
  "FETCH_REJECTED": {
    "kind": "transport_error",
    "title": "fetch rejected before a readable response",
    "conditions": [
      "browser capture",
      "the Fetch API rejected the request with an error instead of a response",
      "the error names no cause: a CORS refusal, a rejected preflight, DNS, connection or TLS failure, mixed content, a blocking extension and an offline browser look alike to the page"
    ],
    "browser_only": true
  },
  "FULL_RESPONSE_CONTENT_RANGE": {
    "kind": "note",
    "title": "Content-Range on a 200 response",
    "conditions": [
      "status is 200",
      "RFC 9110 14.4 gives Content-Range no meaning for 200"
    ]
  },
  "HTTP_SERVER_ERROR": {
    "kind": "transport_error",
    "title": "server or gateway error",
    "conditions": [
      "status is 5xx, 408 or 429"
    ]
  },
  "HTTP_STATUS_UNEXPECTED": {
    "kind": "inconclusive",
    "title": "status does not allow a range verdict",
    "conditions": [
      "status is not 200, 206 or 416 and is not a server error"
    ]
  },
  "MULTIPART_UNSUPPORTED": {
    "kind": "inconclusive",
    "title": "multipart/byteranges response to a single-range request",
    "conditions": [
      "status is 206",
      "Content-Type is multipart/byteranges",
      "multipart parsing is not supported in v0.1"
    ]
  },
  "NUMBER_OUT_OF_RANGE": {
    "kind": "inconclusive",
    "title": "a number in the response exceeds the supported 63-bit range",
    "conditions": [
      "the numeral is syntactically valid",
      "it exceeds the largest value the tool represents exactly (9223372036854775807 in the CLI, 9007199254740991 in the browser page)"
    ]
  },
  "OVERLAP_INCONSISTENT": {
    "kind": "violation",
    "title": "overlapping ranges disagree under one strong ETag",
    "conditions": [
      "two complete 206 bodies with overlapping intervals",
      "both responses carry the same strong ETag and no conflicting length or Last-Modified",
      "the overlapping octets differ"
    ]
  },
  "PARTIAL_RESPONSE": {
    "kind": "note",
    "title": "206 covers a subset of the requested range",
    "conditions": [
      "declared interval lies strictly inside the requested interval",
      "RFC 9110 15.3.7 allows sending fewer bytes"
    ]
  },
  "PRECONDITION_FAILED": {
    "kind": "inconclusive",
    "title": "If-Match precondition failed (412)",
    "conditions": [
      "--preconditions was set",
      "status is 412"
    ]
  },
  "RANGE_416_CONTENT_RANGE_MISSING": {
    "kind": "note",
    "title": "416 without Content-Range",
    "conditions": [
      "status is 416",
      "RFC 9110 14.4 says a server SHOULD include Content-Range bytes */length"
    ]
  },
  "RANGE_IGNORED": {
    "kind": "range_ignored",
    "title": "server ignored the Range header and sent a full 200 response",
    "conditions": [
      "a single satisfiable or unsatisfiable range was requested",
      "status is 200",
      "RFC 9110 14.2 lets a server ignore Range, so this is not a violation"
    ]
  },
  "REDIRECT_LIMIT": {
    "kind": "transport_error",
    "title": "too many redirects",
    "conditions": [
      "redirect count exceeded --max-redirects"
    ]
  },
  "REDIRECT_REFUSED": {
    "kind": "transport_error",
    "title": "redirect refused by policy",
    "conditions": [
      "redirect target would downgrade HTTPS, use a non-HTTP scheme, or be malformed"
    ]
  },
  "REFERENCE_CHANGED": {
    "kind": "inconclusive",
    "title": "reference file changed while the run was in progress",
    "conditions": [
      "size or modification time of the reference differs between start and end of the run"
    ]
  },
  "REFERENCE_SIZE_MISMATCH": {
    "kind": "inconclusive",
    "title": "reference length differs from the length the server reports",
    "conditions": [
      "reference mode",
      "the server reported a complete length",
      "the reference file has a different length"
    ]
  },
  "RELATION_INPUT_UNAVAILABLE": {
    "kind": "inconclusive",
    "title": "bodies needed for a consistency comparison are unavailable",
    "conditions": [
      "one of the compared responses was not a complete verified 206 body"
    ]
  },
  "REPRESENTATION_CHANGED": {
    "kind": "inconclusive",
    "title": "representation signals changed between responses",
    "conditions": [
      "a strong or weak ETag, complete length, Last-Modified or content coding differs from an earlier response"
    ]
  },
  "REQUEST_FAILED": {
    "kind": "transport_error",
    "title": "request failed before a response was received",
    "conditions": [
      "DNS, connection, TLS or protocol failure"
    ]
  },
  "REQUEST_TIMEOUT": {
    "kind": "transport_error",
    "title": "request timed out",
    "conditions": [
      "the per-request or whole-run timeout expired"
    ]
  },
  "REREAD_INCONSISTENT": {
    "kind": "violation",
    "title": "re-reading the same range returned different bytes under one strong ETag",
    "conditions": [
      "two complete 206 bodies for the same interval",
      "both responses carry the same strong ETag and no conflicting length or Last-Modified",
      "the octets differ"
    ]
  },
  "SATISFIABLE_GOT_416": {
    "kind": "violation",
    "title": "416 returned although the range is satisfiable under the length it reports",
    "conditions": [
      "status is 416 with Content-Range bytes */length",
      "the requested range is satisfiable for that length"
    ]
  },
  "SKIP_BODY_LIMIT": {
    "kind": "skipped",
    "title": "expected response exceeds the per-response limit",
    "conditions": []
  },
  "SKIP_BUDGET_BYTES": {
    "kind": "skipped",
    "title": "remaining byte budget too small for this check",
    "conditions": []
  },
  "SKIP_BUDGET_REQUESTS": {
    "kind": "skipped",
    "title": "request budget exhausted",
    "conditions": []
  },
  "SKIP_BUDGET_TIME": {
    "kind": "skipped",
    "title": "whole-run timeout reached",
    "conditions": []
  },
  "SKIP_CANCELLED": {
    "kind": "skipped",
    "title": "run cancelled before this check",
    "conditions": []
  },
  "SKIP_OVERFLOW": {
    "kind": "skipped",
    "title": "offsets would exceed the 63-bit range",
    "conditions": []
  },
  "SKIP_REMOTE_SIZE": {
    "kind": "skipped",
    "title": "the server did not report a representation length",
    "conditions": []
  },
  "SKIP_SIZE_UNKNOWN": {
    "kind": "skipped",
    "title": "representation length is unknown",
    "conditions": []
  },
  "SKIP_TOO_SMALL": {
    "kind": "skipped",
    "title": "representation or probe size too small for this check",
    "conditions": []
  },
  "SKIP_ZERO_LENGTH": {
    "kind": "skipped",
    "title": "representation has zero length",
    "conditions": []
  },
  "STATUS_206_NO_CONTENT_RANGE": {
    "kind": "violation",
    "title": "206 response has no Content-Range",
    "conditions": [
      "status is 206",
      "Content-Type is not multipart/byteranges",
      "the response headers are fully visible (always for the CLI; in a browser only for a same-origin response)",
      "RFC 9110 15.3.7.1 requires Content-Range in a single-part 206"
    ]
  },
  "UNEXPECTED_416": {
    "kind": "inconclusive",
    "title": "416 without a Content-Range for a range that earlier responses suggest is satisfiable",
    "conditions": [
      "status is 416 without a usable complete length",
      "an earlier response reported a length for which the range is satisfiable"
    ]
  },
  "UNSATISFIABLE_GOT_206": {
    "kind": "violation",
    "title": "206 returned for a range that is unsatisfiable under the reported length",
    "conditions": [
      "status is 206 with a valid Content-Range carrying a complete length",
      "the request's first-pos is at or beyond that length"
    ]
  },
  "WEAK_VALIDATORS": {
    "kind": "note",
    "title": "only weak or no strong validators observed",
    "conditions": [
      "no strong ETag was seen (a repeated, malformed or oversize ETag does not count)"
    ]
  }
};

// Turns one response into findings. A port of the CLI's internal/interpret
// for what a page can observe: the same rules and diagnostic IDs, plus the
// limits of a browser. testdata/shared/judge.json holds cases that both
// implementations must answer alike.
//
// What differs from the CLI, and why:
//  - Cross-origin responses show only CORS-readable headers. A missing
//    Content-Range might be absent or merely not exposed; the page cannot
//    tell, so it says CONTENT_RANGE_NOT_VISIBLE instead of claiming a violation.
//  - The browser decodes content codings and the page cannot ask for
//    identity. Rules that equate body length with a declared length are
//    downgraded where decoding cannot be ruled out; Content-Length is not
//    taken as the file length unless the encoding is known to be identity.
//  - Comparison needs the interval the bytes belong to: Content-Range, or,
//    where that is hidden, the requested interval, and only for a body of
//    exactly that length.

import * as rs from "./rangespec.js";
import { finding, withLimits, asIdentity, downgrade } from "./finding.js";
import { clean } from "./util.js";
import { DISCARD_LIMIT, IGNORED_PREFIX } from "./config.js";

const SERVER_ERRORS = new Set([408, 429, 500, 501, 502, 503, 504, 505, 506, 507, 508, 510, 511]);

const orNone = (v, vis) => (v === null || v === "" ? (vis === "full" ? "(absent)" : "(absent or not exposed)") : clean(v, 200));
const lengthStr = (n) => (n < 0 ? "(absent)" : String(n));
const ev = (k, v) => [k, v];

/**
 * p:    { spec, refSize, remote: {known, value} }
 * head: { status, headers (get(name) -> string|null), contentLength (-1 if
 *         absent), visibility: "full" | "cors" }
 * Returns the analysis; its mode says how the body is consumed:
 * none | discard | partial | partial-hidden | full.
 */
export function analyzeHead(p, head) {
  const h = head.headers;
  const encRaw = (h.get("content-encoding") ?? "").trim().toLowerCase();
  const a = {
    p,
    head,
    mode: "none",
    first: 0,
    last: 0,
    want: -1,
    findings: [],
    fp: { etag: h.get("etag"), lastModified: clean(h.get("last-modified") ?? "", 200), total: 0, totalKnown: false },
    refSizeMismatch: false,
    crRaw: "",
    // identity: known. not_observable: cross-origin and nothing says either way.
    // encoded: the page can read a Content-Encoding other than identity.
    encodingState:
      encRaw !== "" && encRaw !== "identity" ? "encoded" : head.visibility === "full" || encRaw === "identity" ? "identity" : "not_observable",
    encoding: encRaw === "" ? "identity" : encRaw,
  };
  switch (head.status) {
    case 206:
      analyze206(a);
      break;
    case 200:
      analyze200(a);
      break;
    case 416:
      analyze416(a);
      break;
    default:
      if (SERVER_ERRORS.has(head.status)) {
        a.findings.push(
          finding("HTTP_SERVER_ERROR", `server answered ${head.status}`,
            ev("status", head.status), ev("retry_after", orNone(h.get("retry-after"), head.visibility))),
        );
        a.mode = "discard";
      } else unexpected(a);
  }
  if (a.encodingState === "encoded" && (head.status === 200 || head.status === 206)) {
    a.findings.push(
      withLimits(
        finding("ENCODING_DECODED_BY_BROWSER",
          "the response declares a content coding; the browser decodes it before the page reads the body, so the bytes are not compared",
          ev("content_encoding", clean(a.encoding, 200))),
        "Byte equality with the reference is not evaluated. Headers are still checked against each other.",
      ),
    );
    if (a.mode !== "none") a.mode = "discard";
  }
  return a;
}

function unexpected(a) {
  const st = a.head.status;
  let lim;
  if (st === 401 || st === 403) lim = "Access was refused. This page sends no credentials (credentials: omit).";
  else if (st === 404 || st === 410) lim = "The URL did not resolve to a representation.";
  else lim = "Only 200, 206 and 416 are evaluated.";
  a.findings.push(
    withLimits(finding("HTTP_STATUS_UNEXPECTED", `status ${st} does not allow a range verdict`, ev("status", st)), lim),
  );
  a.mode = "discard";
}

function analyze206(a) {
  const { head } = a;
  const h = head.headers;
  const ct = (h.get("content-type") ?? "").split(";")[0].trim().toLowerCase();
  if (ct === "multipart/byteranges") {
    a.findings.push(
      withLimits(
        finding("MULTIPART_UNSUPPORTED", "single-range request was answered with multipart/byteranges; the body is not parsed",
          ev("content_type", clean(h.get("content-type"), 200))),
        "RangeProbe v0.1 parses only single-part 206 responses.",
      ),
    );
    return;
  }
  const raw = h.get("content-range");
  if (raw === null) {
    if (head.visibility === "full") {
      a.findings.push(
        finding("STATUS_206_NO_CONTENT_RANGE", "206 response without Content-Range",
          ev("status", 206), ev("content_type", clean(h.get("content-type") ?? "", 200))),
      );
      return;
    }
    a.findings.push(
      withLimits(
        finding("CONTENT_RANGE_NOT_VISIBLE", "206 response whose Content-Range this page cannot read",
          ev("status", 206), ev("request_range", rs.header(a.p.spec))),
        "A cross-origin page reads only headers the server lists in Access-Control-Expose-Headers. Absent and not exposed look the same, so no violation is claimed.",
        "The bytes can still be compared with the requested interval of the reference when the body has exactly that length.",
      ),
    );
    const r = rs.resolve(a.p.spec, a.p.refSize);
    if (r) {
      a.mode = "partial-hidden";
      a.first = r.first;
      a.last = r.last;
      a.want = r.last - r.first + 1;
    }
    return;
  }
  a.crRaw = raw;
  if (raw.includes(",")) {
    a.findings.push(finding("CONTENT_RANGE_INVALID", "Content-Range is repeated or lists several values", ev("values", clean(raw, 200))));
    return;
  }
  let cr;
  try {
    cr = rs.parseContentRange(raw);
  } catch (e) {
    return badCR(a, e, raw);
  }
  if (cr.unsatisfied) {
    a.findings.push(finding("CONTENT_RANGE_INVALID", "unsatisfied-range form in a 206 response", ev("content_range", clean(raw, 200))));
    return;
  }
  a.mode = "partial";
  a.first = cr.first;
  a.last = cr.last;
  a.want = rs.crLength(cr);
  if (cr.totalKnown) {
    a.fp.total = cr.total;
    a.fp.totalKnown = true;
    checkRefSize(a, cr.total);
  }
  const req = rs.header(a.p.spec);
  if (cr.totalKnown) {
    const r = rs.resolve(a.p.spec, cr.total);
    if (!r) {
      a.findings.push(
        finding("UNSATISFIABLE_GOT_206", "206 returned for a range that is unsatisfiable under the reported length",
          ev("request_range", req), ev("content_range", clean(raw, 200))),
      );
    } else if (cr.first < r.first || cr.last > r.last) {
      a.findings.push(
        finding("CONTENT_RANGE_OUTSIDE_REQUEST", "Content-Range is not inside the interval the request selects",
          ev("request_range", req), ev("content_range", clean(raw, 200)), ev("expected_interval", `${r.first}-${r.last}`)),
      );
    } else if (cr.first !== r.first || cr.last !== r.last) {
      a.findings.push(
        finding("PARTIAL_RESPONSE", "206 covers only part of the requested range",
          ev("request_range", req), ev("content_range", clean(raw, 200)), ev("expected_interval", `${r.first}-${r.last}`)),
      );
    }
  } else {
    const s = a.p.spec;
    const outside = (s.kind === "int" && (cr.first < s.first || cr.last > s.last)) || (s.kind === "open" && cr.first < s.first);
    if (outside) {
      a.findings.push(
        finding("CONTENT_RANGE_OUTSIDE_REQUEST", "Content-Range is not inside the requested range",
          ev("request_range", req), ev("content_range", clean(raw, 200))),
      );
    }
  }
  // Both are headers of the same response: comparing them needs no body.
  if (head.contentLength >= 0 && head.contentLength !== a.want) {
    a.findings.push(
      finding("CONTENT_LENGTH_RANGE_MISMATCH", "Content-Length differs from the Content-Range interval length",
        ev("content_length", head.contentLength), ev("content_range", clean(raw, 200)), ev("interval_length", a.want)),
    );
  }
}

function badCR(a, err, raw) {
  if (!(err instanceof rs.ContentRangeError)) throw err;
  if (err.kind === "number") {
    a.findings.push(
      withLimits(
        finding("NUMBER_OUT_OF_RANGE", `Content-Range contains a number above ${rs.MAX_EXACT}`, ev("content_range", clean(raw, 200))),
        "The value is syntactically valid; this page cannot compute with it, so no verdict is given.",
      ),
    );
  } else {
    a.findings.push(finding("CONTENT_RANGE_INVALID", `Content-Range is not valid: ${err.message}`, ev("content_range", clean(raw, 200))));
  }
}

function analyze200(a) {
  const { head } = a;
  const h = head.headers;
  a.findings.push(
    withLimits(
      finding("RANGE_IGNORED", "server returned the full representation instead of a partial response",
        ev("request_range", rs.header(a.p.spec)), ev("status", 200),
        ev("accept_ranges", orNone(h.get("accept-ranges"), head.visibility)),
        ev("content_length", lengthStr(head.contentLength))),
      "RFC 9110 14.2 allows servers to ignore Range. This only means random access is unavailable here.",
      "Behaviour for other ranges or conditions is not implied.",
    ),
  );
  a.mode = "full";
  if (h.get("content-range") !== null) {
    a.findings.push(finding("FULL_RESPONSE_CONTENT_RANGE", "Content-Range present on a 200 response", ev("content_range", clean(h.get("content-range"), 200))));
  }
  // Content-Length counts as the file length only when no coding can have changed it.
  if (head.contentLength >= 0 && a.encodingState === "identity") {
    a.want = head.contentLength;
    a.fp.total = head.contentLength;
    a.fp.totalKnown = true;
    checkRefSize(a, head.contentLength);
  }
}

function analyze416(a) {
  const { head } = a;
  a.mode = "discard";
  const raw = head.headers.get("content-range");
  if (raw === null) {
    if (head.visibility === "full") {
      a.findings.push(finding("RANGE_416_CONTENT_RANGE_MISSING", "416 without Content-Range", ev("status", 416)));
      unknown416(a);
    } else {
      a.findings.push(
        withLimits(
          finding("CONTENT_RANGE_NOT_VISIBLE", "416 response whose Content-Range this page cannot read", ev("status", 416), ev("request_range", rs.header(a.p.spec))),
          "Absent and not exposed look the same to a cross-origin page.",
        ),
      );
    }
    return;
  }
  if (raw.includes(",")) {
    a.findings.push(finding("CONTENT_RANGE_INVALID", "Content-Range is repeated or lists several values", ev("values", clean(raw, 200))));
    return;
  }
  let cr;
  try {
    cr = rs.parseContentRange(raw);
  } catch (e) {
    return badCR(a, e, raw);
  }
  if (!cr.unsatisfied) {
    a.findings.push(finding("CONTENT_RANGE_INVALID", "416 response carries a satisfied-range Content-Range", ev("content_range", clean(raw, 200))));
    return;
  }
  a.fp.total = cr.total;
  a.fp.totalKnown = true;
  checkRefSize(a, cr.total);
  if (rs.resolve(a.p.spec, cr.total)) {
    a.findings.push(
      finding("SATISFIABLE_GOT_416", "416 returned although the range is satisfiable under the length the response reports",
        ev("request_range", rs.header(a.p.spec)), ev("content_range", clean(raw, 200))),
    );
  }
}

function unknown416(a) {
  const r = a.p.remote;
  if (r?.known && rs.resolve(a.p.spec, r.value)) {
    a.findings.push(
      withLimits(
        finding("UNEXPECTED_416", "416 without Content-Range for a range that is satisfiable under the earlier reported length",
          ev("request_range", rs.header(a.p.spec)), ev("earlier_length", r.value)),
        "The representation may have shrunk since the length was observed.",
      ),
    );
  }
}

function checkRefSize(a, total) {
  if (a.p.refSize !== null && a.p.refSize !== undefined && a.p.refSize !== total) {
    a.refSizeMismatch = true;
    a.findings.push(
      withLimits(
        finding("REFERENCE_SIZE_MISMATCH", "the server reports a different length than the reference file",
          ev("server_length", total), ev("reference_length", a.p.refSize)),
        "The reference is probably a different file or version. Byte comparisons for this run cannot support conclusions about Range handling.",
      ),
    );
  }
}

/** Body bytes to read: how far, before stopping the stream. */
export function readLimit(a, { maxBody, remaining }) {
  switch (a.mode) {
    case "discard":
      return Math.min(DISCARD_LIMIT, maxBody, remaining);
    case "full":
      return Math.min(IGNORED_PREFIX, maxBody, remaining);
    case "partial":
    case "partial-hidden":
      return Math.min(a.want + 1, maxBody, remaining); // one more octet probes for excess
  }
  return 0;
}

/**
 * Which bytes of the body can be compared, and with which offset of the
 * reference, or null. ex: { read, eof, limit, bodyFail }.
 */
export function comparisonPlan(a, ex) {
  if (a.encodingState === "encoded") return null;
  switch (a.mode) {
    case "partial":
      return ex.read > 0 ? { start: a.first, len: Math.min(ex.read, a.want) } : null;
    case "full":
      return ex.read > 0 ? { start: 0, len: ex.read } : null;
    case "partial-hidden":
      // Without Content-Range only a body of exactly the requested length
      // is known to belong to the requested interval.
      return ex.read === a.want && !ex.bodyFail ? { start: a.first, len: a.want } : null;
  }
  return null;
}

/** Findings after the body has been read. cmp is compareBody's result or null. */
export function finish(a, ex, cmp) {
  const st = { complete: false, end: "unread", extraProbed: false };
  let fs = [...a.findings];
  fs = bodyFindings(a, ex, st, fs);
  if (cmp) fs = compareFindings(a, cmp, fs);
  return { findings: fs, state: st, bytes: bytesResult(a, ex, cmp) };
}

// A decoded body can be shorter or longer than the declared length, so a
// length rule holds as a violation only where the encoding is known.
function lengthRule(a, f) {
  return a.encodingState === "identity"
    ? f
    : downgrade(f, "The page cannot see whether the browser decoded a content coding; a decoded body can differ in length from the declared one.");
}

function truncated(a, ex) {
  const want = a.want < 0 ? "(unknown)" : String(a.want);
  return lengthRule(a,
    withLimits(
      finding("BODY_TRUNCATED", "the body ended before the declared length",
        ev("status", a.head.status), ev("declared_length", want), ev("bytes_read", ex.read),
        ev("content_length", lengthStr(a.head.contentLength)), ev("content_range", a.crRaw === "" ? "(absent)" : clean(a.crRaw, 200))),
      "A proxy, load balancer or network fault can end a stream early as well; repeat the run to see whether it is deterministic.",
    ));
}

function bodyFailure(bf, ex) {
  let id = "BODY_READ_ERROR";
  if (bf.kind === "timeout" || bf.kind === "run_timeout") id = "REQUEST_TIMEOUT";
  else if (bf.kind === "cancelled") id = "CANCELLED";
  let f = finding(id, `reading the body failed: ${bf.message}`, ev("bytes_read", ex.read));
  if (id === "BODY_READ_ERROR") {
    f = withLimits(f, "A page sees every read error alike: a reset connection, a framing error, a content-decoding failure and a body cut short all look the same.");
  }
  return f;
}

function bodyFindings(a, ex, st, fs) {
  switch (a.mode) {
    case "partial":
    case "partial-hidden":
    case "full":
      break;
    case "discard":
      st.end = "discarded";
      return fs;
    default:
      return fs;
  }
  if (ex.bodyFail) {
    st.end = "error";
    return [...fs, bodyFailure(ex.bodyFail, ex)];
  }
  if (a.mode === "full") {
    if (ex.eof && a.want >= 0 && ex.read < a.want) {
      st.end = "truncated";
      return [...fs, truncated(a, ex)];
    }
    if (ex.eof) {
      st.end = "complete";
      st.complete = true;
    } else st.end = "prefix";
    return fs;
  }
  const L = a.want;
  if (a.mode === "partial-hidden") {
    if (ex.read > L) st.end = "excess";
    else if (ex.eof && ex.read < L) st.end = "short";
    else if (ex.read === L) {
      st.end = "complete";
      st.complete = true;
      st.extraProbed = ex.eof;
    } else {
      st.end = "limit";
      fs = [...fs, limitReached(L, ex)];
    }
    return fs;
  }
  if (ex.read > L) {
    st.end = "excess";
    return [
      ...fs,
      lengthRule(a,
        withLimits(
          finding("BODY_EXCESS", "body continues beyond the Content-Range length",
            ev("declared_length", L), ev("received_at_least", ex.read), ev("content_range", clean(a.crRaw, 200))),
          "Only one octet beyond the declared length is read; the true surplus is unknown.",
        )),
    ];
  }
  if (ex.eof && ex.read < L) {
    st.end = "truncated";
    return [...fs, truncated(a, ex)];
  }
  if (ex.read === L && ex.eof) {
    st.end = "complete";
    st.complete = true;
    st.extraProbed = true;
  } else if (ex.read === L) {
    st.end = "complete";
    st.complete = true;
    fs = [...fs, finding("EXTRA_BYTE_CHECK_SKIPPED", "no budget to read one octet past the declared length", ev("declared_length", L), ev("read_limit", ex.limit))];
  } else {
    st.end = "limit";
    fs = [...fs, limitReached(L, ex)];
  }
  return fs;
}

function limitReached(L, ex) {
  return withLimits(
    finding("BODY_LIMIT_REACHED", "reading stopped at a limit before the declared length",
      ev("declared_length", L), ev("bytes_read", ex.read), ev("read_limit", ex.limit)),
    "The unread tail of the body is unverified.",
  );
}

function compareFindings(a, cmp, fs) {
  if (cmp.refErr) {
    return [...fs, finding("REFERENCE_CHANGED", `the reference file could not be read completely: ${clean(cmp.refErr, 200)}`)];
  }
  if (cmp.count === 0) return fs;
  const evd = [
    ev("first_mismatch_offset", cmp.first), ev("mismatching_bytes", cmp.count), ev("compared_bytes", cmp.compared),
  ];
  if (cmp.observedSha256) evd.push(ev("observed_sha256", cmp.observedSha256));
  if (cmp.expectedSha256) evd.push(ev("expected_sha256", cmp.expectedSha256));
  if (cmp.beyond > 0) evd.push(ev("bytes_beyond_reference", cmp.beyond));
  const msg = a.mode === "full" ? "the prefix of the full response differs from the reference" : "response bytes differ from the reference slice";
  const limits = [
    "This is an observed difference, not a diagnosis. The reference may be a different file or version than the published one.",
    "It does not by itself show that the server's Range handling is defective.",
  ];
  if (a.encodingState === "not_observable") {
    limits.push("The page sees the bytes after any automatic content decoding and cannot tell whether one was applied.");
  }
  let f = asIdentity(withLimits(finding("BYTES_MISMATCH_REFERENCE", msg, ...evd), ...limits));
  if (a.refSizeMismatch) {
    f = downgrade(f, "The reference length differs from the length the server reports, so the files are not known to match.");
  }
  return [...fs, f];
}

function bytesResult(a, ex, cmp) {
  if (!cmp) {
    let reason = "the response carries no comparable bytes";
    if (a.encodingState === "encoded") reason = "the browser decoded a content coding; decoded bytes cannot be compared with the reference slice";
    else if (a.mode === "partial-hidden") {
      reason = "Content-Range is not readable and the body does not have exactly the requested length, so the interval the bytes belong to is unknown";
    } else if ((a.mode === "partial" || a.mode === "full") && ex.read === 0) reason = "no body bytes were read";
    return { outcome: "not_compared", reason };
  }
  const first = a.mode === "full" ? 0 : a.first;
  const r = {
    outcome: "not_compared",
    scope: a.mode === "full" ? "prefix_of_full_response" : "interval",
    compared_bytes: cmp.compared,
    expected_first: first,
    expected_last: first + cmp.compared + cmp.beyond - 1,
  };
  if (cmp.refErr) r.reason = "the reference file could not be read completely";
  else if (cmp.count > 0) {
    r.outcome = "mismatch";
    r.first_mismatch_offset = cmp.first;
    r.mismatch_count = cmp.count;
    if (cmp.beyond > 0) r.bytes_beyond_reference = cmp.beyond;
  } else if (cmp.compared > 0) r.outcome = "match";
  else r.reason = "no body bytes were read";
  if (cmp.observedSha256) r.sha256 = cmp.observedSha256;
  if (cmp.expectedSha256) r.expected_sha256 = cmp.expectedSha256;
  return r;
}

/** Claims that held for a passing check. */
export function verified(a, cmp) {
  const out = [];
  if (a.head.status === 206 && a.mode === "partial") {
    out.push(
      `206 with Content-Range ${a.first}-${a.last} consistent with request ${rs.header(a.p.spec)}`,
      `body length equals the declared interval length (${a.last - a.first + 1} bytes), no excess octet seen`,
    );
    if (cmp && cmp.count === 0 && !cmp.refErr && cmp.compared > 0) {
      out.push(`bytes ${a.first}-${a.last} equal the reference file's bytes ${a.first}-${a.last} (${cmp.compared} bytes compared${cmp.observedSha256 ? ", sha256 " + cmp.observedSha256.slice(0, 16) + "…" : ""})`);
    }
  } else if (a.head.status === 416) {
    out.push(a.fp.totalKnown
      ? `416 with Content-Range bytes */${a.fp.total}, consistent with an unsatisfiable range ${rs.header(a.p.spec)}`
      : "416 for the unsatisfiable range (no usable Content-Range)");
  }
  return out;
}

/** What the page could and could not see of this response. */
export function evidenceOf(a) {
  const { head } = a;
  const h = head.headers;
  const vis = head.visibility;
  const crApplies = head.status === 206 || head.status === 416;
  let contentRange = "not_applicable";
  if (h.get("content-range") !== null) contentRange = "visible";
  else if (crApplies) contentRange = vis === "full" ? "absent" : "not_visible";
  const ceVisible = h.get("content-encoding") !== null;
  const missing = contentRange === "not_visible" ? ["Content-Range"] : [];
  return {
    header_visibility: vis === "full" ? "all headers (same-origin response)" : "only the CORS-readable headers (cross-origin response)",
    content_range: contentRange,
    content_length: head.contentLength >= 0 ? "visible" : "absent",
    content_encoding: ceVisible ? "visible" : vis === "full" ? "absent" : "not_visible",
    complete: crApplies ? missing.length === 0 : null,
    missing,
  };
}

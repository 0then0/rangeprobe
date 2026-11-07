// Runs the plan from the browser: sequential fetch() calls under hard limits.
// Every read is bounded; a server that ignores Range and starts sending the
// whole file is cut off after a small prefix and the stream is cancelled.
// This module draws no conclusions itself: judge.js does.

import * as plan from "./plan.js";
import * as rs from "./rangespec.js";
import { analyzeHead, readLimit, comparisonPlan, finish, verified, evidenceOf } from "./judge.js";
import { compareBody } from "./compare.js";
import { finding, withLimits, statusOf, downgrade, skipReason } from "./finding.js";
import { clean } from "./util.js";
import { MAX_BODY, MAX_BYTES, MAX_REQUESTS } from "./config.js";

const isLoopback = (h) => h === "localhost" || h === "[::1]" || /^127\./.test(h) || h.endsWith(".localhost");

/** Parses the target URL: http or https, no credentials (fetch refuses them). */
export function parseTarget(raw) {
  let u;
  try {
    u = new URL(raw.trim());
  } catch {
    return { error: "Not a valid URL." };
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") return { error: "Only http: and https: URLs can be fetched." };
  if (u.username || u.password) return { error: "fetch() refuses URLs that contain a user name or password." };
  return { url: u.href };
}

function fingerprintsConflict(a, b) {
  const why = [];
  if (a.totalKnown && b.totalKnown && a.total !== b.total) why.push(`complete length ${a.total} vs ${b.total}`);
  const opaque = (v) => (v == null || v.includes(",") || !/^(W\/)?"[^"]*"$/.test(v) ? null : v.replace(/^W\//, ""));
  const ea = opaque(a.etag);
  const eb = opaque(b.etag);
  if (ea && eb && ea !== eb) why.push(`ETag ${clean(a.etag, 80)} vs ${clean(b.etag, 80)}`);
  if (a.lastModified && b.lastModified && a.lastModified !== b.lastModified) {
    why.push(`Last-Modified ${clean(a.lastModified, 40)} vs ${clean(b.lastModified, 40)}`);
  }
  if (a.encoding && b.encoding && a.encoding !== b.encoding) why.push(`content coding ${clean(a.encoding, 40)} vs ${clean(b.encoding, 40)}`);
  return why;
}

function applyStability(fs, baseline, fp) {
  if (!baseline) return fs;
  const why = fingerprintsConflict(baseline, fp);
  if (why.length === 0) return fs;
  const out = fs.map((f) =>
    f.identity
      ? downgrade(f, `Representation signals changed during the run (${why.join("; ")}), so the reference or earlier answers may no longer describe this response.`)
      : f,
  );
  out.push(
    withLimits(
      finding("REPRESENTATION_CHANGED", "representation signals differ from the first response of this run", ["reasons", why.join("; ")]),
      "A changed ETag, length or Last-Modified is not a Range defect by itself; the file may have been replaced during the run.",
    ),
  );
  return out;
}

const SHOWN_HEADERS = [
  "Accept-Ranges", "Content-Range", "Content-Length", "Content-Type", "Content-Encoding", "ETag", "Last-Modified",
  "Date", "Server", "Age", "Via", "Cache-Control", "Vary", "Retry-After",
];

function readableHeaders(headers) {
  const shown = [];
  const names = new Set();
  for (const name of SHOWN_HEADERS) {
    const v = headers.get(name);
    if (v !== null) {
      shown.push({ key: name, value: clean(v, 200) });
      names.add(name.toLowerCase());
    }
  }
  let other = 0;
  for (const [k] of headers) if (!names.has(k.toLowerCase())) other++;
  return { shown, other };
}

/**
 * o: { url, ref: {name, size, slice}, settings: {probeSize, requestTimeoutS,
 *      runTimeoutS}, signal?, fetchFn?, pageOrigin, pageProtocol,
 *      onStart?(item, index, total), onCheck?(check) }
 * Returns the raw record of the run (URLs and messages not yet redacted).
 */
export async function runProbe(o) {
  const fetchFn = o.fetchFn ?? globalThis.fetch.bind(globalThis);
  const { ref } = o;
  const b = {
    maxRequests: MAX_REQUESTS,
    maxBytes: MAX_BYTES,
    maxBody: MAX_BODY,
    requestTimeoutMs: o.settings.requestTimeoutS * 1000,
    runTimeoutMs: o.settings.runTimeoutS * 1000,
  };
  const startedAt = new Date();
  const t0 = performance.now();
  const run = { reason: null, ctl: new AbortController() };
  const stopRun = (reason) => {
    if (!run.reason) {
      run.reason = reason;
      run.ctl.abort();
    }
  };
  const runTimer = setTimeout(() => stopRun("run_timeout"), b.runTimeoutMs);
  const onUser = () => stopRun("cancelled");
  o.signal?.addEventListener("abort", onUser);
  if (o.signal?.aborted) onUser();

  const target = new URL(o.url);
  const s = {
    reqs: 0,
    bytes: 0,
    remote: { known: false, value: 0, basis: "" },
    baseline: null,
    checks: [],
    changes: [],
    endpoints: new Set(),
    first: null,
    sawCors: false,
    stable: true,
  };

  const admit = (it) => {
    if (run.reason === "cancelled") return skipReason("SKIP_CANCELLED", "the run was cancelled before this check");
    if (run.reason === "run_timeout") return skipReason("SKIP_BUDGET_TIME", `the whole-run timeout of ${o.settings.runTimeoutS} s was reached`);
    if (it.skip) return it.skip;
    if (s.reqs >= b.maxRequests) return skipReason("SKIP_BUDGET_REQUESTS", `the budget of ${b.maxRequests} requests is used up`);
    if (it.expectBytes > b.maxBody) {
      return skipReason("SKIP_BODY_LIMIT", `a conforming response (${it.expectBytes} bytes) exceeds the per-response limit of ${b.maxBody} bytes`);
    }
    if (it.expectBytes > b.maxBytes - s.bytes) {
      return skipReason("SKIP_BUDGET_BYTES", `${it.expectBytes} bytes are needed but only ${b.maxBytes - s.bytes} of the ${b.maxBytes}-byte budget remain`);
    }
    return null;
  };

  async function execute(it) {
    const range = rs.header(it.spec ?? rs.int(0, 0));
    const chk = {
      id: it.id, title: it.title, key: it.key, claim: it.claim, status: "skipped",
      request: { range }, fetch: null, response: null, body: null, bytes: null, evidence: null, representation: null,
      findings: [], verified: [], limits: [], duration_ms: 0,
    };
    const sk = admit(it);
    if (sk) {
      chk.skip = sk;
      return chk;
    }
    s.reqs++;
    const t1 = performance.now();
    const rq = { ctl: new AbortController(), timedOut: false };
    const onRunAbort = () => rq.ctl.abort();
    run.ctl.signal.addEventListener("abort", onRunAbort);
    const reqTimer = setTimeout(() => {
      rq.timedOut = true;
      rq.ctl.abort();
    }, b.requestTimeoutMs);
    const kindOf = () => run.reason ?? (rq.timedOut ? "timeout" : "error");
    let findings = [];
    try {
      let resp;
      try {
        resp = await fetchFn(o.url, {
          method: "GET",
          headers: { Range: range },
          mode: "cors",
          credentials: "omit",
          cache: "no-store",
          redirect: "follow",
          referrerPolicy: "no-referrer",
          signal: rq.ctl.signal,
        });
      } catch (e) {
        const kind = kindOf();
        chk.fetch = { outcome: kind === "error" ? "rejected" : kind };
        if (kind === "error") {
          const name = e?.name ?? "Error";
          const message = clean(e?.message ?? String(e), 200);
          chk.fetch.error = { name, message };
          const crossOrigin = target.origin !== o.pageOrigin;
          const mixed = o.pageProtocol === "https:" && target.protocol === "http:" && !isLoopback(target.hostname);
          findings.push(
            withLimits(
              finding("FETCH_REJECTED", `fetch() rejected before a readable response: ${name}: ${message}`,
                ["error_name", name], ["error_message", message], ["request_range", range],
                ["page_origin", o.pageOrigin], ["target_origin", target.origin],
                ["cross_origin", crossOrigin], ["mixed_content_possible", mixed]),
              "The Fetch API reports a CORS refusal, a rejected preflight, a DNS, connection or TLS failure, mixed content, a blocking extension and an offline browser all the same way. The page cannot tell them apart.",
              crossOrigin
                ? "The target is cross-origin, so a CORS refusal is one possible cause, not an established one. A suffix range such as bytes=-N needs a preflight that allows the Range header; the other ranges may not."
                : "The target is same-origin, so CORS does not apply.",
              "The browser's developer console usually names the cause; a page cannot read it.",
            ),
          );
        } else {
          findings.push(failureFinding(kind, "the request did not complete"));
        }
        return finalizeCheck(chk, findings, null, t1);
      }

      chk.fetch = { outcome: "response" };
      const visibility = resp.type === "basic" ? "full" : "cors";
      if (visibility === "cors") s.sawCors = true;
      const cl = resp.headers.get("content-length");
      const head = {
        status: resp.status,
        headers: resp.headers,
        contentLength: cl !== null && /^\d+$/.test(cl.trim()) ? Number(cl) : -1,
        visibility,
      };
      const a = analyzeHead({ spec: it.spec, refSize: ref.size, remote: s.remote }, head);
      const limit = readLimit(a, { maxBody: b.maxBody, remaining: b.maxBytes - s.bytes });
      const ex = { read: 0, eof: false, limit, bodyFail: null };
      let body = new Uint8Array(0);
      if (limit > 0 && resp.body) {
        const reader = resp.body.getReader();
        const chunks = [];
        try {
          while (ex.read < limit) {
            const { done, value } = await reader.read();
            if (done) {
              ex.eof = true;
              break;
            }
            const take = Math.min(value.length, limit - ex.read);
            chunks.push(value.subarray(0, take));
            ex.read += take;
          }
        } catch (e) {
          const kind = kindOf();
          ex.bodyFail = { kind, message: kind === "error" ? clean(`${e?.name ?? "Error"}: ${e?.message ?? e}`, 200) : kind };
        }
        // Stop the transfer: a server that sent more than we read must not keep sending.
        if (!ex.eof) await reader.cancel().catch(() => {});
        body = new Uint8Array(ex.read);
        let off = 0;
        for (const c of chunks) {
          body.set(c, off);
          off += c.length;
        }
      } else if (resp.body) {
        await resp.body.cancel().catch(() => {});
      }
      s.bytes += ex.read;

      const cp = comparisonPlan(a, ex);
      const cmp = cp ? await compareBody(ref, cp.start, body.subarray(0, cp.len)) : null;
      const r = finish(a, ex, cmp);
      const fp = { ...a.fp, encoding: a.encoding };
      const counted = resp.status === 200 || resp.status === 206 || resp.status === 416;
      findings = counted ? applyStability(r.findings, s.baseline, fp) : r.findings;
      if (counted) observe(it, a, fp, resp, cl);

      const rh = readableHeaders(resp.headers);
      chk.response = {
        status: resp.status,
        type: resp.type,
        redirected: resp.redirected,
        final_url: resp.url || o.url,
        headers: rh.shown,
        other_header_count: rh.other,
        content_length: head.contentLength >= 0 ? head.contentLength : null,
      };
      chk.body = {
        bytes_read: ex.read,
        read_limit: limit,
        complete: r.state.complete,
        end_state: r.state.end,
        ...(a.want >= 0 ? { declared_length: a.want } : {}),
      };
      chk.bytes = r.bytes;
      chk.evidence = evidenceOf(a);
      chk.representation = {
        encoding: a.encodingState,
        content_encoding: resp.headers.get("content-encoding"),
      };
      return finalizeCheck(chk, findings, () => verified(a, cmp), t1);
    } finally {
      clearTimeout(reqTimer);
      run.ctl.signal.removeEventListener("abort", onRunAbort);
    }
  }

  function failureFinding(kind, msg) {
    const id = kind === "cancelled" ? "CANCELLED" : "REQUEST_TIMEOUT";
    const text = kind === "run_timeout" ? "whole-run timeout reached" : kind === "cancelled" ? "run cancelled" : "request timeout exceeded";
    return finding(id, `${msg}: ${text}`);
  }

  function finalizeCheck(chk, findings, verifiedFn, t1) {
    chk.findings = findings;
    chk.status = statusOf(findings, null);
    chk.duration_ms = Math.round(performance.now() - t1);
    if (chk.status === "pass") {
      chk.verified = verifiedFn ? verifiedFn() : [];
      if (chk.verified.length === 0) chk.verified = ["no inconsistency found for this request"];
    }
    chk.limits = [
      "Assumes the reference file is byte-identical to the currently published representation.",
      "Seen through this browser's fetch(): the bytes after any automatic content decoding, and only the headers the response's CORS policy lets the page read.",
    ];
    return chk;
  }

  function observe(it, a, fp, resp, clRaw) {
    if (s.baseline) {
      const why = fingerprintsConflict(s.baseline, fp);
      if (why.length > 0) {
        s.changes.push(`${it.id}: ${why.join("; ")}`);
        s.stable = false;
      }
    }
    if (!s.baseline && (fp.etag || fp.totalKnown || fp.lastModified)) s.baseline = { ...fp };
    if (!s.remote.known && fp.totalKnown) {
      s.remote = { known: true, value: fp.total, basis: resp.status === 200 ? "content-length-200" : "content-range" };
    }
    if (!s.first) {
      s.first = {
        etag: resp.headers.get("etag"),
        lastModified: fp.lastModified,
        acceptRanges: resp.headers.get("accept-ranges"),
        contentType: resp.headers.get("content-type"),
      };
    }
    try {
      const u = new URL(resp.url || o.url);
      s.endpoints.add(u.origin + u.pathname);
    } catch {
      /* no URL to record */
    }
  }

  try {
    const items = [plan.firstByte()];
    const total = 5;
    const record = (it) => async () => {
      o.onStart?.(it, s.checks.length, total);
      const chk = await execute(it);
      s.checks.push(chk);
      o.onCheck?.(chk, s.checks.length, total);
    };
    await record(items[0])();
    const rest = plan.build(o.settings.probeSize, plan.sizing(ref.size, s.remote));
    for (const it of rest) await record(it)();
  } finally {
    clearTimeout(runTimer);
    o.signal?.removeEventListener("abort", onUser);
  }

  return {
    startedAt: startedAt.toISOString(),
    finishedAt: new Date().toISOString(),
    durationMs: Math.round(performance.now() - t0),
    url: o.url,
    pageOrigin: o.pageOrigin,
    interrupted: run.reason === "cancelled",
    stoppedBy: run.reason,
    settings: {
      probe_size: o.settings.probeSize,
      request_timeout_ms: b.requestTimeoutMs,
      run_timeout_ms: b.runTimeoutMs,
      max_requests: b.maxRequests,
      max_total_bytes: b.maxBytes,
      max_response_bytes: b.maxBody,
    },
    reference: { name: ref.name, size: ref.size },
    checks: s.checks,
    budget: { requests: s.reqs, max_requests: b.maxRequests, bytes_read: s.bytes, max_total_bytes: b.maxBytes },
    remote: s.remote,
    first: s.first,
    changes: s.changes,
    stable: s.stable,
    endpoints: [...s.endpoints],
    sawCors: s.sawCors,
  };
}

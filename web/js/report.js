// The JSON report of a browser run. It holds the URL (redacted on request),
// the origin of the page, ranges, statuses, readable headers, byte counts and
// comparison results. It never holds response bodies or any part of the
// reference file; digests of the compared slices are recorded as in the CLI.

import { FORMAT, SCHEMA_VERSION, VERSION, REPOSITORY, REQUEST_OPTIONS } from "./config.js";
import { OMITTED_CHECKS } from "./plan.js";
import { finding, withLimits } from "./finding.js";
import { urlSecrets, redactUrl, plainUrl, redactText } from "./util.js";

/** Every URL in the record: the target and where redirects ended. */
function urlsOf(record) {
  const all = [record.url];
  for (const c of record.checks) if (c.response?.final_url) all.push(c.response.final_url);
  return [...new Set(all)];
}

/** What in the record's URLs may be secret: query names, user info, fragments. */
export function secretsIn(record) {
  const names = new Set();
  let userinfo = false;
  let fragment = false;
  for (const u of urlsOf(record)) {
    const s = urlSecrets(u);
    s.queryNames.forEach((n) => names.add(n));
    userinfo ||= s.userinfo;
    fragment ||= s.fragment;
  }
  return { queryNames: [...names], userinfo, fragment, any: names.size > 0 || userinfo || fragment };
}

function mapStrings(v, fn) {
  if (typeof v === "string") return fn(v);
  if (Array.isArray(v)) return v.map((x) => mapStrings(x, fn));
  if (v && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, mapStrings(x, fn)]));
  return v;
}

/** The overall result, derived like the CLI's Summarize, with the two axes counted apart. */
export function summarize(checks, runFindings) {
  const counts = {};
  let problem = false;
  let ignored = false;
  let incomplete = false;
  const notPassed = [];
  const bytes = { match: 0, mismatch: 0, not_compared: 0 };
  const evidence = { complete: 0, incomplete: 0 };
  for (const c of checks) {
    counts[c.status] = (counts[c.status] ?? 0) + 1;
    if (c.status === "violation" || c.status === "byte_mismatch") problem = true;
    else if (c.status === "range_ignored") ignored = true;
    else if (c.status === "inconclusive" || c.status === "transport_error") incomplete = true;
    else if (c.status === "skipped" && c.key) incomplete = true;
    if (c.status !== "pass" && c.key) notPassed.push(c.id);
    if (c.bytes) bytes[c.bytes.outcome]++;
    if (c.evidence?.complete === true) evidence.complete++;
    else if (c.evidence?.complete === false) evidence.incomplete++;
  }
  for (const f of runFindings) if (f.kind === "inconclusive" || f.kind === "transport_error") incomplete = true;
  const result = problem ? "problem" : ignored ? "range_ignored" : incomplete || notPassed.length ? "incomplete" : "pass";
  const counted = Object.keys(counts).sort().map((k) => `${counts[k]} ${k.replaceAll("_", " ")}`).join(", ");
  const axes = `Bytes compared with the reference: ${bytes.match} match, ${bytes.mismatch} differ, ${bytes.not_compared} not compared. ${evidence.complete + evidence.incomplete === 0 ? "Protocol evidence: not applicable (no 206 or 416 response was read)." : `Protocol evidence: complete for ${evidence.complete}, incomplete for ${evidence.incomplete}.`}`;
  let headline;
  switch (result) {
    case "pass":
      headline = `All key checks passed (${counted}). Identity with an unseen original is not proven, and the page saw bytes after any automatic content decoding.`;
      break;
    case "problem":
      headline = `A confirmed problem was found (${counted}).`;
      break;
    case "range_ignored":
      headline = `The server ignored Range; random access is not available here (${counted}). This is not an RFC violation.`;
      break;
    default:
      headline = `Verification is incomplete (${counted}); no confirmed problem, but not a PASS.`;
  }
  return { result, headline, axes, counts, bytes, evidence, key_checks_not_passed: notPassed };
}

export function runFindingsOf(record) {
  const out = [];
  const hidden = record.checks.some((c) => c.representation?.encoding === "not_observable");
  if (record.sawCors && hidden) {
    out.push(
      withLimits(
        finding("ENCODING_NOT_OBSERVABLE", "cross-origin responses showed no Content-Encoding; the page cannot tell whether the browser decoded a body"),
        "Compared bytes are the bytes the page received. They equal the bytes on the wire only when no coding was applied.",
      ),
    );
  }
  if (record.endpoints.length > 1) {
    out.push(finding("ENDPOINT_VARIED", "redirects led to different endpoints for different probes", ["distinct_endpoints", record.endpoints.length]));
  }
  return out;
}

function strip(f) {
  const { identity: _identity, ...rest } = f;
  return rest;
}

/**
 * Builds the report object. redact: replace query values and drop user info
 * and fragments from every URL and URL-like text; without it only user info
 * and fragments are dropped.
 */
export function buildReport(record, { redact }) {
  const urls = urlsOf(record);
  const showUrl = redact ? redactUrl : plainUrl;
  const checks = record.checks.map((c) => {
    const x = { ...c, findings: c.findings.map(strip) };
    if (x.response) x.response = { ...x.response, final_url: showUrl(x.response.final_url) };
    return x;
  });
  const runFindings = runFindingsOf(record);
  const summary = summarize(checks, runFindings);

  const verifiedClaims = [];
  const uncertainty = [];
  for (const c of checks) {
    for (const v of c.verified) verifiedClaims.push(`${c.id}: ${v}`);
    if (c.skip) uncertainty.push({ source: c.id, id: c.skip.id, text: `not run: ${c.skip.reason}` });
    for (const f of c.findings) {
      if (f.kind === "inconclusive" || f.kind === "transport_error") uncertainty.push({ source: c.id, id: f.id, text: f.message });
    }
  }
  for (const f of runFindings) if (f.kind === "inconclusive") uncertainty.push({ source: "run", id: f.id, text: f.message });
  uncertainty.push({
    source: "run",
    text: `Browser mode runs the five key checks only; ${OMITTED_CHECKS.join(", ")} are not run.`,
  });

  const target = new URL(record.url);
  const report = {
    format: FORMAT,
    schema_version: SCHEMA_VERSION,
    tool: { name: "rangeprobe", component: "browser-page", version: VERSION, repository: REPOSITORY },
    capture: {
      origin: "browser",
      api: "fetch",
      page_origin: record.pageOrigin,
      request_options: REQUEST_OPTIONS,
      observation: {
        bytes: "the bytes the page receives, after any content decoding the browser applies automatically; raw network bytes are not observable",
        headers: "all response headers for a same-origin response; for a cross-origin response only CORS-safelisted headers and those listed in Access-Control-Expose-Headers",
        errors: "a rejected fetch() names no cause; CORS, DNS, TLS, mixed content and offline are indistinguishable",
        redirects: "followed by the browser; only the final URL is visible",
      },
    },
    run: {
      started_at: record.startedAt,
      finished_at: record.finishedAt,
      duration_ms: record.durationMs,
      target: showUrl(record.url),
      target_redacted: Boolean(redact),
      target_origin: target.origin,
      cross_origin: target.origin !== record.pageOrigin,
      interrupted: record.interrupted,
      stopped_by: record.stoppedBy,
      params: record.settings,
      checks_run: checks.map((c) => c.id),
      checks_omitted: OMITTED_CHECKS,
    },
    reference: record.reference,
    endpoint: { final_url: checks.find((c) => c.response)?.response.final_url ?? null, varied_between_requests: record.endpoints.length > 1 },
    representation: {
      length: record.remote.known ? record.remote.value : null,
      length_basis: record.remote.known ? record.remote.basis : null,
      etag: record.first?.etag ?? null,
      last_modified: record.first?.lastModified || null,
      accept_ranges: record.first?.acceptRanges ?? null,
      content_type: record.first?.contentType ?? null,
      stable: record.stable,
      changes: record.changes,
      note: "Only headers the page could read; a null may mean absent or not exposed.",
    },
    summary,
    checks,
    run_findings: runFindings.map(strip),
    verified_claims: verifiedClaims,
    unsupported: [
      "multipart/byteranges responses (multi-range requests) are not requested or parsed",
      "raw network bytes, content codings other than identity and the Accept-Encoding header: the browser sets and decodes them",
      "request headers other than Range, methods other than GET, credentials, cookies and custom headers",
      "the redirect chain, the HTTP version and headers that are not exposed to the page",
      "If-Range conformance and controlled version switching",
    ],
    uncertainty,
    assumptions: [
      "Requests are sent sequentially and never retried; each probe is independent.",
      "Only body bytes count toward the byte budget; headers do not.",
      "The reference file is assumed to be byte-identical to the currently published representation; RangeProbe cannot verify this.",
      "A byte mismatch is an observation. It does not prove a defect in the server's Range handling: the reference may be another file or version.",
      "The length that places offsets is the one the server reported where the page could read it, else the length of the reference file.",
    ],
    budget: record.budget,
  };
  return redact ? mapStrings(report, (s) => redactText(s, urls)) : report;
}

export function serialize(report) {
  return JSON.stringify(report, null, 2) + "\n";
}

export function reportFileName(d = new Date()) {
  const p = (n) => String(n).padStart(2, "0");
  return `rangeprobe-browser-${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}.json`;
}

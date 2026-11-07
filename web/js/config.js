// Constants of the browser page. The rules (plan, diagnostics) are shared
// with the CLI; limits that differ from the CLI's defaults say so.

/** Must equal internal/version/version.go; scripts/check-release.sh checks it. */
export const VERSION = "0.2.0";

export const FORMAT = "rangeprobe-browser-report";
export const SCHEMA_VERSION = 1;

export const REPOSITORY = "https://github.com/0then0/rangeprobe";

/** Body limits, the same as the CLI's defaults. */
export const MAX_BODY = 2 << 20; // one response
export const MAX_BYTES = 8 << 20; // the whole run
/** A 200 to a range request: read this much for a sanity comparison, then stop. */
export const IGNORED_PREFIX = 64 << 10;
/** Bodies of 416 and error responses are read only this far. */
export const DISCARD_LIMIT = 4 << 10;
/** The plan has five requests; this is a hard stop on top of it. */
export const MAX_REQUESTS = 8;

/** Settings the user may change, with their hard bounds. */
export const SETTINGS = {
  probeSize: { def: 4096, min: 1, max: 1 << 20, label: "Probe size (bytes)" },
  requestTimeoutS: { def: 30, min: 1, max: 120, label: "Time per request (seconds)" },
  runTimeoutS: { def: 120, min: 1, max: 600, label: "Time for the whole run (seconds)" },
};

/** The request options of every probe, recorded in the report. */
export const REQUEST_OPTIONS = {
  method: "GET",
  mode: "cors",
  credentials: "omit",
  cache: "no-store",
  redirect: "follow",
  referrer_policy: "no-referrer",
  request_headers: ["Range"],
  accept_encoding: "set by the browser; the page cannot control it",
};

import { test } from "node:test";
import assert from "node:assert/strict";

import { runProbe } from "../js/probe.js";
import { buildReport, secretsIn, serialize, summarize } from "../js/report.js";
import { clean, redactUrl, plainUrl, redactText, urlSecrets } from "../js/util.js";
import { REGISTRY } from "../js/registry.js";

const refByte = (i) => (167 * i + 61 * (i >> 8) + 13) & 0xff;
const SIZE = 5000;
const ref = { name: "ref.bin", size: SIZE, slice: async (a, b) => Uint8Array.from({ length: Math.min(b, SIZE) - a }, (_, i) => refByte(a + i)) };

async function record(url, tamper = (b) => b) {
  return runProbe({
    url, ref, settings: { probeSize: 100, requestTimeoutS: 5, runTimeoutS: 20 },
    pageOrigin: "http://page.example", pageProtocol: "http:",
    fetchFn: async (u, init) => {
      const m = /^bytes=(\d*)-(\d*)$/.exec(init.headers.Range);
      const a = m[1] === "" ? SIZE - Number(m[2]) : Number(m[1]);
      const b = m[1] === "" || m[2] === "" ? SIZE - 1 : Number(m[2]);
      const body = tamper(Uint8Array.from({ length: b - a + 1 }, (_, i) => refByte(a + i)));
      return new Response(body, { status: 206, headers: { "Content-Range": `bytes ${a}-${b}/${SIZE}`, "Content-Length": String(body.length) } });
    },
  });
}

test("the report carries the format, capture origin, page origin, ranges, statuses, headers and counts", async () => {
  const r = buildReport(await record("http://files.example/f.bin"), { redact: false });
  assert.equal(r.format, "rangeprobe-browser-report");
  assert.equal(r.schema_version, 1);
  assert.equal(r.capture.origin, "browser");
  assert.equal(r.capture.page_origin, "http://page.example");
  assert.equal(r.capture.request_options.credentials, "omit");
  assert.equal(r.run.cross_origin, true);
  assert.deepEqual(r.checks.map((c) => c.request.range), ["bytes=0-0", "bytes=0-99", "bytes=2450-2549", "bytes=4900-4999", "bytes=-100"]);
  const c = r.checks[1];
  assert.equal(c.response.status, 206);
  assert.ok(c.response.headers.some((h) => h.key === "Content-Range"));
  assert.equal(c.body.bytes_read, 100);
  assert.equal(c.bytes.outcome, "match");
  assert.equal(r.reference.name, "ref.bin");
  assert.equal(r.summary.result, "pass");
  for (const f of r.checks.flatMap((c) => c.findings).concat(r.run_findings)) {
    assert.ok(REGISTRY[f.id], f.id);
    assert.ok(!("identity" in f));
  }
});

test("the report holds no body bytes and no reference bytes", async () => {
  const text = serialize(buildReport(await record("http://files.example/f.bin", (b) => (b[3] ^= 0xff, b)), { redact: true }));
  const j = JSON.parse(text);
  assert.ok(j.checks.some((c) => c.bytes.outcome === "mismatch"));
  // Nothing in it is an array of numbers or a long hex/base64 blob other than the two digests.
  assert.ok(!/\[\s*\d+\s*,\s*\d+\s*,\s*\d+\s*,\s*\d+/.test(text.replace(/"(first|last|expected_first|expected_last)"[^\n]*/g, "")));
  const long = text.match(/[A-Za-z0-9+/=]{90,}/g) ?? [];
  assert.deepEqual(long, []);
  assert.ok(!JSON.stringify(j).includes("fragment"), "no hex fragment");
});

test("redaction removes query values and user info from every URL and message", async () => {
  const url = "http://files.example/f.bin?token=SECRET&X-Amz-Signature=SIG";
  const rec = await record(url);
  rec.checks[0].findings.push({ id: "ENDPOINT_VARIED", kind: "note", message: `see ${url}`, conditions: [], evidence: [{ key: "u", value: url }], limits: [] });
  assert.deepEqual(secretsIn(rec).queryNames, ["token", "X-Amz-Signature"]);
  const red = serialize(buildReport(rec, { redact: true }));
  assert.ok(!/SECRET|SIG\b/.test(red), "no secret value survives");
  assert.ok(red.includes("token=REDACTED&X-Amz-Signature=REDACTED"));
  assert.equal(JSON.parse(red).run.target_redacted, true);
  const full = serialize(buildReport(rec, { redact: false }));
  assert.ok(full.includes("token=SECRET"));
  assert.equal(JSON.parse(full).run.target_redacted, false);
});

test("a URL without a query needs no warning", async () => {
  assert.equal(secretsIn(await record("http://files.example/f.bin")).queryNames.length, 0);
});

test("the summary keeps bytes and protocol evidence apart", () => {
  const chk = (status, outcome, complete) => ({ id: status, key: true, status, bytes: { outcome }, evidence: { complete } });
  const s = summarize([chk("inconclusive", "match", false), chk("inconclusive", "match", false)], []);
  assert.equal(s.result, "incomplete");
  assert.deepEqual(s.bytes, { match: 2, mismatch: 0, not_compared: 0 });
  assert.deepEqual(s.evidence, { complete: 0, incomplete: 2 });
  assert.match(s.axes, /2 match/);
  assert.match(s.axes, /incomplete for 2/);
});

test("clean makes control and bidi characters visible", () => {
  assert.equal(clean("a‮b\u0007c\tD"), "a\\u202eb\\u0007c D");
  assert.equal(clean("x".repeat(10), 4), "xxxx…(+6 characters)");
});

test("URL helpers", () => {
  assert.equal(redactUrl("https://u:p@h.example:8443/a/b?token=1&x=2#frag"), "https://h.example:8443/a/b?token=REDACTED&x=REDACTED");
  assert.equal(plainUrl("https://u:p@h.example/a?q=1#f"), "https://h.example/a?q=1");
  assert.equal(redactUrl("http://localhost:18080"), "http://localhost:18080");
  assert.deepEqual(urlSecrets("https://h.example/a?b=1&b=2&c").queryNames, ["b", "c"]);
  assert.equal(redactText("failed: https://h.example/a?token=zzz.", ["https://h.example/a?token=zzz"]), "failed: https://h.example/a?token=REDACTED.");
});

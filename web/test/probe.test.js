// The runner against a fake fetch: read limits, deadlines, cancellation and
// the exact request the page sends.
import { test } from "node:test";
import assert from "node:assert/strict";

import { runProbe, parseTarget } from "../js/probe.js";
import { MAX_BODY } from "../js/config.js";

const refByte = (i) => (167 * i + 61 * (i >> 8) + 13) & 0xff;
const SIZE = 100_000;
const ref = {
  name: "ref.bin",
  size: SIZE,
  slice: async (a, b) => Uint8Array.from({ length: Math.min(b, SIZE) - a }, (_, i) => refByte(a + i)),
};
const settings = { probeSize: 1000, requestTimeoutS: 5, runTimeoutS: 20 };
const base = { url: "http://files.example/data.bin", ref, settings, pageOrigin: "http://page.example", pageProtocol: "http:" };

/** A correct 206 for the Range header of the request. */
function correct(url, init) {
  const m = /^bytes=(\d*)-(\d*)$/.exec(init.headers.Range);
  let a = m[1] === "" ? Math.max(0, SIZE - Number(m[2])) : Number(m[1]);
  let b = m[1] === "" || m[2] === "" ? SIZE - 1 : Math.min(Number(m[2]), SIZE - 1);
  const body = Uint8Array.from({ length: b - a + 1 }, (_, i) => refByte(a + i));
  return new Response(body, {
    status: 206,
    headers: { "Content-Range": `bytes ${a}-${b}/${SIZE}`, "Content-Length": String(body.length) },
  });
}

test("every request is a credential-free, uncached, referrer-free GET with only a Range header", async () => {
  const seen = [];
  const rec = await runProbe({ ...base, fetchFn: async (u, init) => (seen.push({ u, init }), correct(u, init)) });
  assert.equal(seen.length, 5);
  for (const { u, init } of seen) {
    assert.equal(u, base.url);
    assert.equal(init.method, "GET");
    assert.equal(init.credentials, "omit");
    assert.equal(init.mode, "cors");
    assert.equal(init.cache, "no-store");
    assert.equal(init.referrerPolicy, "no-referrer");
    assert.deepEqual(Object.keys(init.headers), ["Range"]);
    assert.ok(init.signal instanceof AbortSignal);
  }
  assert.deepEqual(seen.map((s) => s.init.headers.Range), ["bytes=0-0", "bytes=0-999", "bytes=49500-50499", "bytes=99000-99999", "bytes=-1000"]);
  assert.equal(rec.budget.requests, 5);
  assert.equal(rec.budget.bytes_read, 1 + 4 * 1000);
});

test("a server that ignores Range is cut off after the prefix and its stream is cancelled", async () => {
  let produced = 0;
  let cancelled = 0;
  const fetchFn = async () => {
    let offset = 0;
    const stream = new ReadableStream({
      pull(c) {
        const chunk = new Uint8Array(16 << 10);
        for (let i = 0; i < chunk.length; i++) chunk[i] = refByte(offset + i);
        offset += chunk.length;
        produced += chunk.length;
        c.enqueue(chunk); // never ends: a huge file
      },
      cancel() {
        cancelled++;
      },
    });
    return new Response(stream, { status: 200, headers: { "Content-Length": String(1 << 40) } });
  };
  const rec = await runProbe({ ...base, fetchFn });
  assert.equal(cancelled, 5, "every transfer is stopped");
  for (const c of rec.checks) {
    assert.equal(c.status, "range_ignored");
    assert.equal(c.body.bytes_read, 64 << 10);
    assert.equal(c.body.end_state, "prefix");
    assert.equal(c.bytes.outcome, "match");
  }
  assert.ok(produced < 5 * (64 << 10) + 5 * (256 << 10), `only ${produced} bytes were pulled from the stream`);
});

test("a 206 that claims more than the per-response limit stops at the limit", async () => {
  const big = { ...settings, probeSize: 1 << 20 };
  const fetchFn = async (u, init) => {
    if (init.headers.Range === "bytes=0-0") return correct(u, init);
    return new Response(new ReadableStream({ pull: (c) => c.enqueue(new Uint8Array(64 << 10)) }), {
      status: 206,
      headers: { "Content-Range": `bytes 0-${(1 << 20) - 1}/${SIZE}` },
    });
  };
  const rec = await runProbe({ ...base, ref: { ...ref, size: 4 << 20 }, settings: big, fetchFn });
  const head = rec.checks.find((c) => c.id === "head");
  assert.ok(head.body.bytes_read <= MAX_BODY);
  assert.ok(rec.budget.bytes_read <= 8 << 20);
});

test("a probe larger than the per-response limit is skipped, not sent", async () => {
  let n = 0;
  const rec = await runProbe({
    ...base,
    ref: { ...ref, size: 8 << 20 },
    settings: { ...settings, probeSize: 3 << 20 },
    fetchFn: async () => (n++, new Response(new Uint8Array(1), { status: 206, headers: { "Content-Range": `bytes 0-0/${8 << 20}` } })),
  });
  const skipped = rec.checks.filter((c) => c.skip?.id === "SKIP_BODY_LIMIT").map((c) => c.id);
  assert.deepEqual(skipped, ["head", "middle", "tail", "suffix"]);
  assert.equal(n, 1);
});

test("an empty reference sends only the discovery request", async () => {
  let n = 0;
  const rec = await runProbe({
    ...base,
    ref: { name: "e", size: 0, slice: async () => new Uint8Array(0) },
    fetchFn: async () => (n++, new Response(null, { status: 416, headers: { "Content-Range": "bytes */0" } })),
  });
  assert.equal(n, 1);
  assert.deepEqual(rec.checks.map((c) => c.skip?.id ?? c.status), ["pass", "SKIP_ZERO_LENGTH", "SKIP_ZERO_LENGTH", "SKIP_ZERO_LENGTH", "SKIP_ZERO_LENGTH"]);
});

test("a request that outlives its deadline is aborted and reported as a timeout", async () => {
  const fetchFn = (u, init) =>
    new Promise((_, reject) => init.signal.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError"))));
  const t0 = performance.now();
  const rec = await runProbe({ ...base, settings: { ...settings, requestTimeoutS: 0.05 }, fetchFn });
  assert.ok(performance.now() - t0 < 2000);
  assert.deepEqual(rec.checks.map((c) => c.findings[0]?.id), Array(5).fill("REQUEST_TIMEOUT"));
  assert.equal(rec.interrupted, false);
});

test("the run deadline stops the run and skips what is left", async () => {
  const fetchFn = (u, init) =>
    new Promise((_, reject) => init.signal.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError"))));
  const rec = await runProbe({ ...base, settings: { ...settings, runTimeoutS: 0.05 }, fetchFn });
  assert.equal(rec.checks[0].findings[0].id, "REQUEST_TIMEOUT");
  assert.deepEqual(rec.checks.slice(1).map((c) => c.skip?.id), Array(4).fill("SKIP_BUDGET_TIME"));
  assert.equal(rec.stoppedBy, "run_timeout");
});

test("cancelling aborts the open request and skips the rest", async () => {
  const ctl = new AbortController();
  const fetchFn = (u, init) =>
    new Promise((_, reject) => init.signal.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError"))));
  setTimeout(() => ctl.abort(), 30);
  const rec = await runProbe({ ...base, fetchFn, signal: ctl.signal });
  assert.equal(rec.checks[0].findings[0].id, "CANCELLED");
  assert.deepEqual(rec.checks.slice(1).map((c) => c.skip?.id), Array(4).fill("SKIP_CANCELLED"));
  assert.equal(rec.interrupted, true);
});

test("cancelling while a body is being read ends that read as cancelled", async () => {
  const ctl = new AbortController();
  const fetchFn = async (u, init) => {
    const stream = new ReadableStream({
      start(c) {
        c.enqueue(new Uint8Array([refByte(0)]));
        init.signal.addEventListener("abort", () => c.error(new DOMException("aborted", "AbortError")));
      },
    });
    setTimeout(() => ctl.abort(), 20);
    return new Response(stream, { status: 206, headers: { "Content-Range": `bytes 0-0/${SIZE}`, "Content-Length": "1" } });
  };
  const rec = await runProbe({ ...base, fetchFn, signal: ctl.signal });
  assert.equal(rec.checks[0].findings.map((f) => f.id).join(), "CANCELLED");
  assert.equal(rec.checks[0].body.bytes_read, 1);
});

test("a rejected fetch names what the page saw and does not claim CORS", async () => {
  const rec = await runProbe({ ...base, fetchFn: async () => Promise.reject(new TypeError("Failed to fetch")) });
  const f = rec.checks[0].findings[0];
  assert.equal(f.id, "FETCH_REJECTED");
  assert.equal(rec.checks[0].status, "transport_error");
  assert.deepEqual(rec.checks[0].fetch, { outcome: "rejected", error: { name: "TypeError", message: "Failed to fetch" } });
  const ev = Object.fromEntries(f.evidence.map((e) => [e.key, e.value]));
  assert.equal(ev.cross_origin, "true");
  assert.equal(ev.error_message, "Failed to fetch");
  assert.ok(f.limits.some((l) => /one possible cause, not an established one/.test(l)));
  assert.ok(!/is blocked by CORS|because of CORS/i.test(JSON.stringify(f)));
});

test("a rejected same-origin fetch says CORS does not apply", async () => {
  const rec = await runProbe({ ...base, pageOrigin: "http://files.example", fetchFn: async () => Promise.reject(new TypeError("x")) });
  assert.ok(rec.checks[0].findings[0].limits.some((l) => /same-origin, so CORS does not apply/.test(l)));
});

test("mixed content is flagged as possible, not as the cause", async () => {
  const rec = await runProbe({ ...base, pageProtocol: "https:", pageOrigin: "https://page.example", fetchFn: async () => Promise.reject(new TypeError("x")) });
  const ev = Object.fromEntries(rec.checks[0].findings[0].evidence.map((e) => [e.key, e.value]));
  assert.equal(ev.mixed_content_possible, "true");
});

test("the file changing between slices is reported, not hidden", async () => {
  let calls = 0;
  const flaky = { ...ref, slice: async (a, b) => { if (++calls === 2) throw new DOMException("changed", "NotReadableError"); return ref.slice(a, b); } };
  const rec = await runProbe({ ...base, ref: flaky, fetchFn: async (u, i) => correct(u, i) });
  const changed = rec.checks.filter((c) => c.findings.some((f) => f.id === "REFERENCE_CHANGED"));
  assert.equal(changed.length, 1);
  assert.equal(changed[0].status, "inconclusive");
});

test("a replaced file during the run turns a mismatch into inconclusive", async () => {
  let n = 0;
  const fetchFn = async (u, init) => {
    const r = correct(u, init);
    const headers = new Headers(r.headers);
    headers.set("ETag", n++ === 0 ? '"v1"' : '"v2"');
    const body = new Uint8Array(await r.arrayBuffer());
    if (n > 1) body[0] ^= 0xff;
    return new Response(body, { status: 206, headers });
  };
  const rec = await runProbe({ ...base, fetchFn });
  const head = rec.checks.find((c) => c.id === "head");
  assert.equal(head.status, "inconclusive");
  assert.deepEqual(head.findings.map((f) => f.id).sort(), ["BYTES_MISMATCH_REFERENCE", "REPRESENTATION_CHANGED"]);
  assert.equal(head.bytes.outcome, "mismatch");
});

test("parseTarget accepts http(s) without credentials only", () => {
  assert.ok(parseTarget("https://h.example/a?b=1").url);
  assert.ok(parseTarget("ftp://h.example/a").error);
  assert.ok(parseTarget("https://u:p@h.example/a").error);
  assert.ok(parseTarget("not a url").error);
});

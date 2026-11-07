// Runs the cases in testdata/shared against the page's planner and judge.
// The CLI runs the same files in internal/parity.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import * as plan from "../js/plan.js";
import * as rs from "../js/rangespec.js";
import { analyzeHead, readLimit, comparisonPlan, finish } from "../js/judge.js";
import { compareBody } from "../js/compare.js";
import { statusOf } from "../js/finding.js";
import { REGISTRY } from "../js/registry.js";

const shared = (name) =>
  JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "..", "testdata", "shared", name), "utf8"));

// Reference byte i, as documented in judge.json.
const refByte = (i) => (167 * i + 61 * (i >> 8) + 13) & 0xff;
const refBytes = (a, b) => {
  const out = [];
  for (let i = a; i <= b; i++) out.push(refByte(i));
  return out;
};

test("planner: every case of plan.json", () => {
  const { cases } = shared("plan.json");
  assert.ok(cases.length > 5);
  for (const c of cases) {
    const items = [plan.firstByte(), ...plan.build(c.probe_size, { length: c.length, known: true, remote: c.remote })];
    const got = {};
    const skips = {};
    for (const it of items) {
      if (it.skip) skips[it.id] = it.skip.id;
      else got[it.id] = rs.header(it.spec);
    }
    assert.deepEqual(got, c.ranges, c.name);
    assert.deepEqual(skips, c.skips ?? {}, c.name);
  }
});

test("planner: the length comes from the server when it reported one", () => {
  assert.deepEqual(plan.sizing(1000, { known: true, value: 2000 }), { length: 2000, known: true, remote: true });
  assert.deepEqual(plan.sizing(1000, { known: false, value: 0 }), { length: 1000, known: true, remote: false });
  assert.deepEqual(plan.sizing(1000, null), { length: 1000, known: true, remote: false });
});

test("planner: the page omits exactly the CLI checks that are not key checks", () => {
  const ids = [plan.firstByte(), ...plan.build(4096, { length: 100000, known: true, remote: true })].map((i) => i.id);
  assert.deepEqual(ids, ["first-byte", "head", "middle", "tail", "suffix"]);
  assert.deepEqual(plan.OMITTED_CHECKS, ["open-ended", "past-eof", "unsatisfiable", "overlap", "reread"]);
});

function buildBody(v) {
  let b = refBytes(v.body.ref[0] + (v.body.shift ?? 0), v.body.ref[1] + (v.body.shift ?? 0));
  for (const k of v.body.flip ?? []) b[k] ^= 0xff;
  if (v.body.cut != null && v.body.cut < b.length) b = b.slice(0, v.body.cut);
  return Uint8Array.from([...b, ...Array(v.body.extra ?? 0).fill(0xaa)]);
}

async function judgeVector(v) {
  const headers = new Headers();
  for (const [k, val] of Object.entries(v.response.headers)) {
    for (const one of Array.isArray(val) ? val : [val]) headers.append(k, one);
  }
  const cl = headers.get("content-length");
  const head = {
    status: v.response.status,
    headers,
    contentLength: cl === null ? -1 : Number(cl),
    visibility: v.visibility ?? "full",
  };
  const ref = {
    size: v.ref_size,
    slice: async (a, b) => Uint8Array.from({ length: Math.max(0, Math.min(b, v.ref_size) - a) }, (_, i) => refByte(a + i)),
  };
  const maxBody = v.max_body ?? 2 << 20;
  const a = analyzeHead({ spec: rs.parseHeader(v.request), refSize: v.ref_size, remote: { known: false, value: 0 } }, head);
  const limit = readLimit(a, { maxBody, remaining: 8 << 20 });
  const ex = { read: 0, eof: false, limit, bodyFail: null };
  let got = new Uint8Array(0);
  if (limit > 0) {
    const body = buildBody(v);
    got = body.subarray(0, Math.min(body.length, limit));
    ex.read = got.length;
    ex.eof = body.length < limit && !v.body.error;
    const kind = { error: "error", timeout: "timeout", cancelled: "cancelled" }[v.body.error];
    if (kind) ex.bodyFail = { kind, message: kind };
  }
  const cp = comparisonPlan(a, ex);
  const cmp = cp ? await compareBody(ref, cp.start, got.subarray(0, cp.len)) : null;
  const r = finish(a, ex, cmp);
  return {
    status: statusOf(r.findings, null),
    findings: r.findings.map((f) => f.id).sort(),
    bytes: r.bytes.outcome,
    encoding: a.encodingState,
  };
}

test("judge: every case of judge.json", async () => {
  const { vectors } = shared("judge.json");
  assert.ok(vectors.length > 20);
  for (const v of vectors) {
    if (v.modes && !v.modes.includes("browser")) continue;
    const want = { ...v.expect, ...(v.expect_browser ?? {}) };
    const got = await judgeVector(v);
    assert.deepEqual(got, want, v.name);
  }
});

test("judge: the cases use only registered IDs, and the CLI's expectation avoids browser-only ones", () => {
  for (const v of shared("judge.json").vectors) {
    for (const [i, e] of [v.expect, v.expect_browser].filter(Boolean).entries()) {
      for (const id of e.findings) {
        assert.ok(REGISTRY[id], `${v.name}: ${id}`);
        if (i === 0 && (!v.modes || v.modes.includes("cli"))) assert.ok(!REGISTRY[id].browser_only, `${v.name}: ${id}`);
      }
    }
  }
});

test("judge: a wrong expectation fails (the harness is not vacuous)", async () => {
  const v = shared("judge.json").vectors.find((x) => x.name === "206 with one wrong byte");
  const got = await judgeVector(v);
  assert.equal(got.status, "byte_mismatch");
  assert.notDeepEqual(got, { ...v.expect, status: "pass" });
});

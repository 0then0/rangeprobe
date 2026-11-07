// Findings and statuses. Kinds, titles and conditions come from the CLI's
// registry (generated into registry.js), so both sides name things alike.

import { REGISTRY } from "./registry.js";

const PRIORITY = {
  violation: 7,
  byte_mismatch: 6,
  transport_error: 5,
  inconclusive: 4,
  range_ignored: 3,
  skipped: 2,
  pass: 1,
};

export const worse = (a, b) => ((PRIORITY[b] ?? 0) > (PRIORITY[a] ?? 0) ? b : a);

/** A finding with evidence given as [key, value] pairs. Unknown IDs throw. */
export function finding(id, message, ...evidence) {
  const info = REGISTRY[id];
  if (!info) throw new Error(`unregistered diagnostic ${id}`);
  return {
    id,
    kind: info.kind,
    message,
    conditions: info.conditions,
    evidence: evidence.map(([key, value]) => ({ key, value: String(value) })),
    limits: [],
    identity: false, // not exported: depends on the reference describing the response
  };
}

export const withLimits = (f, ...limits) => ({ ...f, limits: [...f.limits, ...limits] });
export const asIdentity = (f) => ({ ...f, identity: true });

export function downgrade(f, reason) {
  return { ...f, kind: "inconclusive", limits: [...f.limits, reason], identity: false };
}

/** A check's status: the most significant non-note finding. */
export function statusOf(findings, skip) {
  if (skip) return "skipped";
  let st = "pass";
  for (const f of findings) if (f.kind !== "note") st = worse(st, f.kind);
  return st;
}

export function skipReason(id, reason) {
  if (!REGISTRY[id]) throw new Error(`unregistered skip ${id}`);
  return { id, reason };
}

// Byte comparison of a response body with the matching slice of the
// reference file. Mirrors internal/capture without streaming: bodies are
// bounded by the read limits (at most 2 MiB), so one slice is read.

import { sha256Hex } from "./util.js";

/**
 * ref is { size, slice(start, end) -> Promise<Uint8Array> } (end exclusive).
 * Returns the comparison of body (whose first byte sits at offset start of
 * the representation) with the reference.
 */
export async function compareBody(ref, start, body) {
  const avail = Math.max(0, Math.min(body.length, ref.size - start));
  let expected = new Uint8Array(0);
  let refErr = null;
  try {
    if (avail > 0) expected = await ref.slice(start, start + avail);
    if (expected.length < avail) throw new Error("short read");
  } catch (e) {
    refErr = `${e?.name ?? "Error"}: ${e?.message ?? e}`;
    expected = expected.subarray(0, Math.min(expected.length, avail));
  }
  const n = Math.min(avail, expected.length);
  let first = -1;
  let count = 0;
  for (let i = 0; i < n; i++) {
    if (expected[i] !== body[i]) {
      count++;
      if (first < 0) first = start + i;
    }
  }
  // Bytes past the end of the reference can never match.
  const beyond = Math.max(0, body.length - avail);
  if (beyond > 0) {
    count += beyond;
    if (first < 0) first = start + avail;
  }
  return {
    compared: n,
    first,
    count,
    beyond,
    refErr,
    observedSha256: await sha256Hex(body),
    expectedSha256: await sha256Hex(expected.subarray(0, n)),
  };
}

/** A reference backed by a File (or Blob): reads only the slices asked for. */
export function fileReference(file) {
  return {
    name: file.name,
    size: file.size,
    async slice(start, end) {
      return new Uint8Array(await file.slice(start, end).arrayBuffer());
    },
  };
}

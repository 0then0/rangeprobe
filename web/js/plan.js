// Which requests the page sends. The CLI's planner (internal/plan) places
// ten checks; the page sends its key checks, the ones random-access readers
// depend on: first-byte, head, middle, tail and suffix. Same offsets, same
// skip reasons; testdata/shared/plan.json holds the cases both must satisfy.

import * as rs from "./rangespec.js";
import { skipReason } from "./finding.js";

/** Checks of the CLI plan the page does not run. */
export const OMITTED_CHECKS = ["open-ended", "past-eof", "unsatisfiable", "overlap", "reread"];

export function firstByte() {
  return {
    id: "first-byte",
    title: "First byte",
    key: true,
    spec: rs.int(0, 0),
    claim: "bytes=0-0 returns exactly the first byte with a consistent Content-Range",
    expectBytes: 1,
    skip: null,
  };
}

/**
 * The checks that follow the discovery request. sz is { length, known,
 * remote }: the length used to place offsets, whether there is one, and
 * whether the server reported it (as opposed to the reference file).
 */
export function build(probe, sz) {
  const n = Math.max(probe, 1);
  const mk = (id, title, claim) => ({ id, title, key: true, claim, spec: null, expectBytes: 0, skip: null });
  const items = {
    head: mk("head", "Range at the start", "a small range at the start returns the requested bytes"),
    middle: mk("middle", "Range in the middle", "a range in the middle of the file returns the requested bytes"),
    tail: mk("tail", "Range at the end", "the last bytes, requested by explicit offsets, are returned"),
    suffix: mk("suffix", "Suffix range", "a suffix range returns the last N bytes"),
  };
  const set = (id, spec, expect) => Object.assign(items[id], { spec, expectBytes: expect });
  const skipAll = (sk, ...ids) => ids.forEach((id) => (items[id].skip = sk));
  const list = () => [items.head, items.middle, items.tail, items.suffix];

  set("head", rs.int(0, n - 1), n);
  set("suffix", rs.suffix(n), n);

  if (sz.known && sz.length === 0) {
    skipAll(
      skipReason("SKIP_ZERO_LENGTH", "the representation is empty, so no range can select bytes"),
      "head", "middle", "tail", "suffix",
    );
    return list();
  }
  if (!sz.known) {
    skipAll(
      skipReason("SKIP_SIZE_UNKNOWN", "no length from the server or the reference file; offsets cannot be placed safely"),
      "middle", "tail",
    );
    return list();
  }
  const S = sz.length;
  const m = Math.min(n, S);
  const mStart = Math.max(0, Math.floor(S / 2) - Math.floor(m / 2));
  set("head", rs.int(0, m - 1), m);
  set("suffix", rs.suffix(m), m);
  set("middle", rs.int(mStart, mStart + m - 1), m);
  set("tail", rs.int(S - m, S - 1), m);
  return list();
}

/** The length used to place offsets: the server's when known, else the reference's. */
export function sizing(refSize, remote) {
  return remote?.known
    ? { length: remote.value, known: true, remote: true }
    : { length: refSize, known: true, remote: false };
}

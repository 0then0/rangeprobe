// Single byte-range specifiers and Content-Range parsing (RFC 9110 14.1.2,
// 14.4). Mirrors internal/rangespec. Numbers are JavaScript numbers: anything
// above 2^53-1 is reported as out of range instead of being rounded.

export const MAX_EXACT = Number.MAX_SAFE_INTEGER;

export const int = (first, last) => ({ kind: "int", first, last });
export const open = (first) => ({ kind: "open", first });
export const suffix = (n) => ({ kind: "suffix", suffix: n });

export function valid(s) {
  switch (s.kind) {
    case "int":
      return s.first >= 0 && s.last >= s.first;
    case "open":
      return s.first >= 0;
    case "suffix":
      return s.suffix > 0;
  }
  return false;
}

export function header(s) {
  switch (s.kind) {
    case "int":
      return `bytes=${s.first}-${s.last}`;
    case "open":
      return `bytes=${s.first}-`;
    case "suffix":
      return `bytes=-${s.suffix}`;
  }
  return "";
}

/** Parses "bytes=a-b", "bytes=a-" or "bytes=-n". */
export function parseHeader(h) {
  const m = /^bytes=(\d*)-(\d*)$/.exec(h);
  if (!m || (m[1] === "" && m[2] === "")) throw new Error(`unsupported Range ${h}`);
  if (m[1] === "") return suffix(Number(m[2]));
  if (m[2] === "") return open(Number(m[1]));
  return int(Number(m[1]), Number(m[2]));
}

/**
 * The inclusive interval a server selects for a representation of the given
 * length, or null when the range is unsatisfiable. A last-pos beyond the end
 * is clamped.
 */
export function resolve(s, size) {
  if (size <= 0 || !valid(s)) return null;
  switch (s.kind) {
    case "int":
      return s.first >= size ? null : { first: s.first, last: Math.min(s.last, size - 1) };
    case "open":
      return s.first >= size ? null : { first: s.first, last: size - 1 };
    default:
      return { first: Math.max(0, size - s.suffix), last: size - 1 };
  }
}

/** kind: "syntax" | "number" | "invalid" | "unit" */
export class ContentRangeError extends Error {
  constructor(kind, message) {
    super(message);
    this.kind = kind;
  }
}

const E = {
  syntax: () => new ContentRangeError("syntax", "malformed Content-Range"),
  number: () => new ContentRangeError("number", "Content-Range number exceeds the exact range"),
  invalid: () => new ContentRangeError("invalid", "invalid Content-Range"),
  unit: () => new ContentRangeError("unit", "Content-Range unit is not bytes"),
};

function parseNum(s) {
  if (s === "" || !/^[0-9]+$/.test(s)) throw E.syntax();
  const n = Number(s);
  if (!Number.isSafeInteger(n)) throw E.number();
  return n;
}

/** Parses a Content-Range value of the bytes unit; throws ContentRangeError. */
export function parseContentRange(v) {
  v = v.replace(/^[ \t]+|[ \t]+$/g, "");
  const sp = v.indexOf(" ");
  const unit = sp < 0 ? "" : v.slice(0, sp);
  const rest = sp < 0 ? "" : v.slice(sp + 1);
  if (sp < 0 || unit === "" || rest === "" || /[ \t]/.test(rest)) throw E.syntax();
  if (unit.toLowerCase() !== "bytes") throw E.unit();
  const slash = rest.indexOf("/");
  if (slash < 0) throw E.syntax();
  const spec = rest.slice(0, slash);
  const length = rest.slice(slash + 1);
  const cr = { unsatisfied: false, first: 0, last: 0, total: 0, totalKnown: false };
  if (length !== "*") {
    cr.total = parseNum(length);
    cr.totalKnown = true;
  }
  if (spec === "*") {
    if (!cr.totalKnown) throw E.syntax();
    cr.unsatisfied = true;
    return cr;
  }
  const dash = spec.indexOf("-");
  if (dash < 0) throw E.syntax();
  cr.first = parseNum(spec.slice(0, dash));
  cr.last = parseNum(spec.slice(dash + 1));
  if (cr.last < cr.first || (cr.totalKnown && cr.total <= cr.last)) throw E.invalid();
  return cr;
}

export const crLength = (cr) => (cr.unsatisfied ? 0 : cr.last - cr.first + 1);

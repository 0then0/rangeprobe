// Text safety, URL redaction and hashing. Mirrors internal/redact.

/** Marks a removed value, as in the CLI's reports. */
export const PLACEHOLDER = "REDACTED";

const UNSAFE = /[\p{Cc}\p{Cf}\u2028\u2029]/u;

/**
 * Makes untrusted text safe to show: control, format and bidi characters
 * become visible \uXXXX escapes, lone surrogates too, and the result is cut
 * to max characters (max <= 0: no limit). Mirrors redact.Clean.
 */
export function clean(s, max = 0) {
  s = String(s);
  let out = "";
  let n = 0;
  const chars = Array.from(s); // code points
  for (let i = 0; i < chars.length; i++) {
    if (max > 0 && n >= max) {
      out += `…(+${chars.length - i} characters)`;
      break;
    }
    const ch = chars[i];
    const cp = ch.codePointAt(0);
    if (ch === "\t") out += " ";
    else if (cp >= 0xd800 && cp <= 0xdfff) out += "\\u" + cp.toString(16).padStart(4, "0");
    else if (UNSAFE.test(ch)) {
      out += cp > 0xffff ? "\\U" + cp.toString(16).padStart(8, "0") : "\\u" + cp.toString(16).padStart(4, "0");
    } else out += ch;
    n++;
  }
  return out;
}

// URL always reports "/" for an empty path; keep the text as it was written.
const pathOf = (u, raw) => (u.pathname === "/" && !/^[a-z][a-z0-9+.-]*:\/\/[^/?#]*\//i.test(raw.trim()) ? "" : u.pathname);

/** What in a URL may be secret. */
export function urlSecrets(raw) {
  let u;
  try {
    u = new URL(raw);
  } catch {
    return { queryNames: [], userinfo: false, fragment: false, any: false };
  }
  const queryNames = u.search
    ? u.search
        .slice(1)
        .split("&")
        .map((p) => p.split("=")[0])
        .filter((k, i, all) => all.indexOf(k) === i)
        .map((k) => safeDecode(k))
    : [];
  const userinfo = u.username !== "" || u.password !== "";
  const fragment = u.hash !== "" && u.hash !== "#";
  return { queryNames, userinfo, fragment, any: queryNames.length > 0 || userinfo || fragment };
}

function safeDecode(s) {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

/**
 * A publishable form of raw: no user info, no fragment, query values
 * replaced by REDACTED (names are kept for diagnosis). Mirrors Redactor.URL.
 */
export function redactUrl(raw) {
  let u;
  try {
    u = new URL(raw);
  } catch {
    return clean("<unparseable URL>", 64);
  }
  let q = "";
  if (u.search.length > 1) {
    q =
      "?" +
      u.search
        .slice(1)
        .split("&")
        .map((p) => {
          const k = p.split("=")[0];
          return k === "" ? PLACEHOLDER : `${k}=${PLACEHOLDER}`;
        })
        .join("&");
  }
  return clean(`${u.protocol}//${u.host}${pathOf(u, raw)}${q}`, 2048);
}

/** The URL without user info and fragment, nothing else removed. */
export function plainUrl(raw) {
  try {
    const u = new URL(raw);
    return clean(`${u.protocol}//${u.host}${pathOf(u, raw)}${u.search}`, 2048);
  } catch {
    return clean("<unparseable URL>", 64);
  }
}

const URL_IN_TEXT = /https?:\/\/[^\s"'<>]+/g;

/** Free text with URLs redacted: the given raw URLs verbatim, then any other. */
export function redactText(s, rawUrls = []) {
  s = String(s);
  for (const raw of [...rawUrls].sort((a, b) => b.length - a.length)) {
    if (raw) s = s.split(raw).join(redactUrl(raw));
  }
  s = s.replace(URL_IN_TEXT, (m) => {
    const trimmed = m.replace(/[.,;:)]+$/, "");
    return redactUrl(trimmed) + m.slice(trimmed.length);
  });
  return clean(s, 1024);
}

/** Hex SHA-256 of bytes, or null where Web Crypto is unavailable (insecure context). */
export async function sha256Hex(bytes) {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) return null;
  const d = new Uint8Array(await subtle.digest("SHA-256", bytes));
  return Array.from(d, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function formatBytes(n) {
  return `${Number(n).toLocaleString("en-US")} B`;
}

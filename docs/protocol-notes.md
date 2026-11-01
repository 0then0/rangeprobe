# Protocol notes

The decisions behind RangeProbe's checks. Section numbers refer to
[RFC 9110](https://www.rfc-editor.org/rfc/rfc9110) unless stated. The design rule throughout: do
not require a single behaviour where the RFC allows several, and do not claim more than the
evidence supports.

## What servers may do

| Behaviour | Basis | RangeProbe |
| --- | --- | --- |
| Ignore `Range` and send `200` | 14.2: "A server MAY ignore the Range header field"; 15.5.17 note | `RANGE_IGNORED`, exit code 2. Not a violation. Reported separately because it defeats random access. |
| Send `200` instead of `416` | 15.5.17 note | `RANGE_IGNORED` on the `unsatisfiable` check. |
| Send fewer bytes than requested | 14.2, 15.3.7: "a server might want to send only a subset" | `PARTIAL_RESPONSE` note. The interval the response *declares* is what gets verified. |
| Omit `Accept-Ranges` | 14.3: a client MAY send ranges regardless | Every run probes. The header is recorded, never used as a gate. |
| Send `Accept-Ranges: bytes` and still ignore ranges | 14.3: a client MUST NOT assume ranges will be honoured | Reported as `RANGE_IGNORED`; the header is shown as evidence. |
| Clamp a last-pos beyond EOF | 14.1.2: replaced by length - 1 | The `past-eof` check expects exactly that interval, or a subset of it. |
| Omit `Content-Length` | Message framing is chunked or close-delimited | Body is read to the declared range length plus one octet. |
| Use `*` as complete length | 14.4 | Allowed. Checks that need a length are limited, and the limit is recorded. |
| Omit `Content-Range` on `416` | 14.4, 15.5.17: SHOULD, not MUST | `RANGE_416_CONTENT_RANGE_MISSING` note only. |

## What servers must do

| Requirement | Basis | Diagnostic |
| --- | --- | --- |
| A single-part `206` has `Content-Range` | 15.3.7.1 | `STATUS_206_NO_CONTENT_RANGE` |
| `Content-Range` grammar, `last >= first`, `length > last`, `bytes` unit, not repeated | 14.4 | `CONTENT_RANGE_INVALID` |
| The declared interval lies inside what the request selects, evaluated with the response's own complete length | 14.1.2, 14.2 | `CONTENT_RANGE_OUTSIDE_REQUEST`, `UNSATISFIABLE_GOT_206` |
| `Content-Length` equals the interval length | 15.3.7 | `CONTENT_LENGTH_RANGE_MISMATCH` |
| The body has the declared number of octets | 15.3.7, RFC 9112 section 8 (an early close makes the message incomplete) | `BODY_TRUNCATED`, `BODY_EXCESS` |
| A satisfiable range is not refused, judged by the length that the `416` itself reports | 14.1.2, 14.2 | `SATISFIABLE_GOT_416` |

A truncated body is classified as a violation when the stream ends early without a transport error
(clean close, or framing that ends before the declared length). Resets, timeouts and TLS errors
are `BODY_READ_ERROR` or `REQUEST_TIMEOUT`, which are infrastructure errors. A cleanly closed short
stream can still come from a proxy, so the finding states that limit and suggests repeating.

## Offsets and numbers

Byte positions are inclusive and zero-based (14.1.2). RangeProbe holds them as `int64`.
Section 14.1.2 says recipients MUST prevent integer overflow: every numeral is parsed from digits
only, values above 9223372036854775807 become `NUMBER_OUT_OF_RANGE` (inconclusive), and offsets
the plan would compute near that limit use saturating arithmetic. If the end offset of a probe
would overflow, the probe is skipped with `SKIP_OVERFLOW`. The `unsatisfiable` check uses an
open-ended range (`bytes=LENGTH-`) so it is representable for every length.

## Content codings

Range offsets address the representation data *after* content coding, "the encoded sequence of
bytes" (14.1.2). RangeProbe sends `Accept-Encoding: identity` and turns off Go's transparent
decompression (`http.Transport.DisableCompression`), so it sees the bytes the server sent. If a
response still carries `Content-Encoding` other than identity, the structure (`Content-Range`,
lengths) is still evaluated, but bytes are not compared with the reference and the check is
`ENCODING_UNSUPPORTED` (inconclusive). Comparing decoded bytes as if they were the original would
be wrong in both directions.

## Validators and representation changes

A strong ETag identifies a representation byte for byte (8.8.1, 8.8.3.2). A weak ETag does not,
so it is never used to confirm identity and never sent in `If-Match` (13.1.1 requires the strong
comparison there). Last-Modified is only a weak hint.

Every response yields a fingerprint: ETag with its strength, complete length (from `Content-Range`
or from `Content-Length` of a `200`), Last-Modified and content coding. Comparing two fingerprints
gives:

- **conflict**: a length, ETag, Last-Modified or coding differs. The representation changed or is
  unstable. Comparisons that rely on it become `inconclusive` (`REPRESENTATION_CHANGED`), including
  a would-be `byte_mismatch`. A changed file is not a defect of Range handling.
- **strong**: both carry the same strong ETag and nothing conflicts. Different bytes for the same
  octets are then a violation (`OVERLAP_INCONSISTENT`, `REREAD_INCONSISTENT`), under the assumption
  that the server's ETag is honest.
- **weak**: nothing conflicts but no strong ETag is shared. Equal bytes are reported as consistent,
  with `WEAK_VALIDATORS`. Different bytes are `CONSISTENCY_UNATTRIBUTED` (inconclusive).

Equal Last-Modified values, or an absence of header changes, never raise a comparison above weak.
Nothing requires reading the whole file to establish a version.

`--preconditions` sends `If-Match` with the first strong ETag. Per 14.2 the Range header is
evaluated after preconditions, so a replaced file yields `412` (`PRECONDITION_FAILED`,
inconclusive) rather than a `206` with new bytes. It is optional because some servers evaluate
`If-Match` on `GET` unreliably. `If-Range` conformance and controlled version switching are out of
scope for v0.1.

## Size knowledge

A probe plan needs the representation length. It comes from, in order:

1. what the server reported (`Content-Range` of a `206` or `416`, or `Content-Length` of a `200`
   whose first probe `bytes=0-0` was the discovery request);
2. otherwise the reference file's length, in reference mode only.

The reference length places offsets but is not evidence about the remote file. The `unsatisfiable`
check needs a server-reported length and is skipped (`SKIP_REMOTE_SIZE`) without one. If the
server's length differs from the reference's, `REFERENCE_SIZE_MISMATCH` is recorded and every byte
comparison in the run is downgraded to inconclusive.

## Not requested: `HEAD`, multipart

`HEAD` is never used. Range semantics are defined for `GET` only (14.2) and many stores handle
`HEAD` differently. A response may arrive without `Content-Length`.

Only one range per request is sent. If a server answers one range with `multipart/byteranges`
(14.6), RangeProbe records `MULTIPART_UNSUPPORTED` and does not read the body.

## Go net/http details

- `http.Client` copies request headers on redirect before `CheckRedirect` runs and forwards
  `Authorization` and `Cookie` to the same domain and subdomains. It also adds `Referer`. RangeProbe's
  policy is stricter and applied in `CheckRedirect`: user headers and `If-Match` are kept only for
  the exact origin (scheme, host, port) of the URL given, `Referer` is always removed.
- `Transport.DisableKeepAlives` is on so that an unfinished body never leaves a reusable
  connection behind. Closing an unread `Body` makes the HTTP/1 transport close the connection
  instead of draining it, which is what makes the byte limit effective.
- `io.ErrUnexpectedEOF` from the body reader marks a stream that ended before its framing
  completed. That is what separates `BODY_TRUNCATED` from other read errors.
- Proxy settings come from the environment (`ProxyFromEnvironment`), as with other Go tools.

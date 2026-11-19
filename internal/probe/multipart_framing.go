package probe

import (
	"bufio"
	"bytes"
	"net/textproto"

	"github.com/0then0/rangeprobe/internal/model"
)

const (
	maxMultipartParts       = 16
	maxMultipartHeaderBytes = 64 << 10
)

// mimeDelimiter marks the end of the previous part and the beginning of the
// next. The separator newline belongs to the delimiter, not to the payload.
type mimeDelimiter struct {
	begin, after  int
	closing       bool
	bareLF        bool
	endsWithLF    bool // without a preceding CR
	invalidPrefix bool
}

// verifyParts splits only on real boundary lines. mime/multipart accepts
// LF-delimited messages and NextPart can decode payloads. Here line endings are
// evidence in their own right, and the MIME header parser sees only a bounded
// header block. Comparisons always use the original part octets.
func (v *multipartVerifier) verifyParts(body []byte, boundary string) {
	r := v.report
	r.MultipartFraming = "incomplete"
	if v.stopVerification() {
		return
	}
	line := []byte("\n--" + boundary)
	current, ok := findMIMEDelimiter(body, line, 0, r.BodyComplete, true)
	if !ok {
		if r.BodyComplete {
			v.badFraming("no delimiter matches the declared multipart boundary")
		}
		return
	}
	if current.bareLF {
		v.badFraming("multipart delimiter uses LF instead of CRLF")
	}
	if current.closing {
		r.ClosingBoundary = true
		v.badFraming("closing delimiter appeared before the first MIME part")
		return
	}

	// A bare LF followed by a boundary lookalike can be ordinary binary
	// data in CRLF framing. Accept bare LF prefixes only in LF framing.
	allowLF := current.endsWithLF
	headerBudget := maxMultipartHeaderBytes
	for count := 0; ; count++ {
		if v.stopVerification() {
			return
		}
		if count == maxMultipartParts {
			v.mimeLimit("part_limit", "MIME part count exceeds the probe limit", maxMultipartParts)
			return
		}
		next, delimited := findMIMEDelimiter(body, line, current.after, r.BodyComplete, allowLF)
		if next.invalidPrefix {
			v.badFraming("multipart boundary prefix appears at the start of a line inside a part")
		}
		end := len(body)
		if delimited {
			end = next.begin
			if next.bareLF {
				v.badFraming("multipart delimiter uses LF instead of CRLF")
			}
		}
		section := body[current.after:end]
		headerEnd, bareLF, capped := mimeHeaderEnd(section, headerBudget)
		if bareLF {
			v.badFraming("MIME part header uses LF instead of CRLF")
		}
		if capped {
			v.mimeLimit("part_header_limit", "total MIME part header bytes exceed the probe limit", maxMultipartHeaderBytes)
			return
		}
		if headerEnd == 0 && delimited {
			v.badFraming("MIME part header block has no terminating empty line")
		} else if headerEnd != 0 {
			headerBudget -= headerEnd
			headers, err := textproto.NewReader(bufio.NewReader(bytes.NewReader(section[:headerEnd]))).ReadMIMEHeader()
			if err != nil {
				v.badFraming("MIME part headers are malformed")
			} else {
				// An undelimited tail can include a partial delimiter. Record
				// its parsed headers and leave the payload unverified.
				var payload []byte
				if delimited {
					payload = section[headerEnd:]
				}
				r.Parts = append(r.Parts, v.verifyPart(headers.Values("Content-Range"), payload, delimited, true, len(boundary)))
			}
		}
		if !delimited {
			if r.BodyComplete {
				v.badFraming("multipart body ended without a closing delimiter")
			}
			return
		}
		if next.closing {
			r.ClosingBoundary = true
			if r.MultipartFraming != "invalid" {
				r.MultipartFraming = "valid"
			}
			return
		}
		current = next
	}
}

func (v *multipartVerifier) badFraming(reason string) {
	r := v.report
	for _, finding := range r.Findings {
		if finding.ID == "MULTIPART_FRAMING" && finding.Message == reason {
			return
		}
	}
	r.MultipartFraming = "invalid"
	v.add("MULTIPART_FRAMING", reason)
}

func (v *multipartVerifier) mimeLimit(issue, message string, limit int) {
	if v.report.ObservationIssue == "" {
		v.report.ObservationIssue = issue
	}
	v.add("MULTIPART_PARSE_LIMIT", message, model.Ev("limit", limit))
}

// findMIMEDelimiter accepts complete LF lines for inspection and flags them.
// A closing line can also end at HTTP EOF (RFC 2046 section 5.1.1).
func findMIMEDelimiter(body, line []byte, from int, complete, allowLF bool) (mimeDelimiter, bool) {
	insidePart := from != 0
	invalidPrefix := false
	if from == 0 && bytes.HasPrefix(body, line[1:]) {
		if d, ok := parseMIMEDelimiter(body, len(line)-1, complete); ok {
			return d, true
		}
	}
	for from < len(body) {
		i := bytes.Index(body[from:], line)
		if i < 0 {
			break
		}
		start := from + i
		from = start + len(line)
		crlf := start > 0 && body[start-1] == '\r'
		if !crlf && !allowLF {
			continue
		}
		if d, ok := parseMIMEDelimiter(body, from, complete); ok {
			d.begin = start
			d.invalidPrefix = invalidPrefix
			if crlf {
				d.begin--
			} else {
				d.bareLF = true
			}
			return d, true
		}
		// RFC 2046 prohibits a delimiter prefix on any line inside a
		// part. A cut-off candidate could still be a valid delimiter.
		if insidePart && crlf && (complete || bytes.IndexByte(body[from:], '\n') >= 0) {
			invalidPrefix = true
		}
	}
	return mimeDelimiter{invalidPrefix: invalidPrefix}, false
}

func parseMIMEDelimiter(body []byte, pos int, complete bool) (mimeDelimiter, bool) {
	d := mimeDelimiter{closing: bytes.HasPrefix(body[pos:], []byte("--"))}
	if d.closing {
		pos += 2
	}
	for pos < len(body) && (body[pos] == ' ' || body[pos] == '\t') {
		pos++
	}
	switch {
	case bytes.HasPrefix(body[pos:], []byte("\r\n")):
		d.after = pos + 2
	case bytes.HasPrefix(body[pos:], []byte("\n")):
		d.after, d.bareLF, d.endsWithLF = pos+1, true, true
	case pos == len(body) && d.closing && complete:
		d.after = pos
	default:
		return mimeDelimiter{}, false
	}
	return d, true
}

// mimeHeaderEnd finds the empty line within the remaining cumulative budget.
// It inspects only header lines, so payload newlines are never framing evidence.
func mimeHeaderEnd(part []byte, budget int) (end int, bareLF, capped bool) {
	for offset := 0; offset < min(budget, len(part)); {
		n := bytes.IndexByte(part[offset:min(budget, len(part))], '\n')
		if n == -1 {
			break
		}
		n += offset
		crlf := n > offset && part[n-1] == '\r'
		bareLF = bareLF || !crlf
		if n == offset || (crlf && n == offset+1) {
			return n + 1, bareLF, false
		}
		offset = n + 1
	}
	return 0, bareLF, len(part) > budget
}

// Package parity holds tests that tie the CLI's rules to the browser page's.
// Both implementations read the same cases from testdata/shared: the CLI
// through internal/plan and internal/interpret here, the page through
// web/test. A rule that changes on one side without the other fails a test.
package parity

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/0then0/rangeprobe/internal/capture"
	"github.com/0then0/rangeprobe/internal/interpret"
	"github.com/0then0/rangeprobe/internal/model"
	"github.com/0then0/rangeprobe/internal/plan"
	"github.com/0then0/rangeprobe/internal/rangespec"
	"github.com/0then0/rangeprobe/internal/transport"
)

func load(t *testing.T, name string, v any) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "shared", name))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
}

// refByte is the content formula documented in judge.json.
func refByte(i int64) byte { return byte(167*i + 61*(i>>8) + 13) }

func refBytes(a, b int64) []byte {
	var out []byte
	for i := a; i <= b; i++ {
		out = append(out, refByte(i))
	}
	return out
}

type bytesRef struct{ size int64 }

func (r bytesRef) Size() int64 { return r.size }
func (r bytesRef) ReadAt(p []byte, off int64) (int, error) {
	n := 0
	for i := range p {
		if off+int64(i) >= r.size {
			break
		}
		p[i] = refByte(off + int64(i))
		n++
	}
	if n < len(p) {
		return n, fmt.Errorf("EOF")
	}
	return n, nil
}

func parseSpec(t *testing.T, h string) rangespec.Spec {
	t.Helper()
	rest, ok := strings.CutPrefix(h, "bytes=")
	if !ok {
		t.Fatalf("bad range %q", h)
	}
	a, b, _ := strings.Cut(rest, "-")
	num := func(s string) int64 {
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			t.Fatalf("bad range %q", h)
		}
		return n
	}
	switch {
	case a == "":
		return rangespec.Suffix(num(b))
	case b == "":
		return rangespec.Open(num(a))
	}
	return rangespec.Int(num(a), num(b))
}

func TestPlanCases(t *testing.T) {
	var f struct {
		Cases []struct {
			Name      string            `json:"name"`
			ProbeSize int64             `json:"probe_size"`
			Length    int64             `json:"length"`
			Remote    bool              `json:"remote"`
			Ranges    map[string]string `json:"ranges"`
			Skips     map[string]string `json:"skips"`
		} `json:"cases"`
	}
	load(t, "plan.json", &f)
	if len(f.Cases) == 0 {
		t.Fatal("no cases")
	}
	for _, c := range f.Cases {
		items := append([]plan.Item{plan.FirstByte()},
			plan.Build(c.ProbeSize, plan.Sizing{Length: c.Length, Known: true, Remote: c.Remote})...)
		got := map[string]string{}
		skips := map[string]string{}
		for _, it := range items {
			if !it.Key {
				continue // the page runs the key checks only
			}
			if it.Skip != nil {
				skips[it.ID] = it.Skip.ID
				continue
			}
			got[it.ID] = it.Spec.Header()
		}
		for id, want := range c.Ranges {
			if got[id] != want {
				t.Errorf("%s: %s is %q, want %q", c.Name, id, got[id], want)
			}
		}
		for id, want := range c.Skips {
			if skips[id] != want {
				t.Errorf("%s: %s skip is %q, want %q", c.Name, id, skips[id], want)
			}
		}
		if len(skips) != len(c.Skips) {
			t.Errorf("%s: skips %v, want %v", c.Name, skips, c.Skips)
		}
		if len(got) != len(c.Ranges) {
			t.Errorf("%s: planned %v, want exactly %v", c.Name, got, c.Ranges)
		}
	}
}

type expectation struct {
	Status   string   `json:"status"`
	Findings []string `json:"findings"`
	Bytes    string   `json:"bytes"`
	Encoding string   `json:"encoding"`
}

type vector struct {
	Name       string   `json:"name"`
	Modes      []string `json:"modes"`
	Visibility string   `json:"visibility"`
	RefSize    int64    `json:"ref_size"`
	Request    string   `json:"request"`
	MaxBody    int64    `json:"max_body"`
	Response   struct {
		Status  int                        `json:"status"`
		Headers map[string]json.RawMessage `json:"headers"`
	} `json:"response"`
	Body struct {
		Ref   [2]int64 `json:"ref"`
		Shift int64    `json:"shift"`
		Flip  []int    `json:"flip"`
		Cut   *int     `json:"cut"`
		Extra int      `json:"extra"`
		Error string   `json:"error"`
	} `json:"body"`
	Expect        expectation  `json:"expect"`
	ExpectBrowser *expectation `json:"expect_browser"`
}

func (v vector) runsInCLI() bool {
	return len(v.Modes) == 0 || slices.Contains(v.Modes, "cli")
}

func (v vector) body() []byte {
	b := refBytes(v.Body.Ref[0]+v.Body.Shift, v.Body.Ref[1]+v.Body.Shift)
	for _, k := range v.Body.Flip {
		b[k] ^= 0xff
	}
	if v.Body.Cut != nil && *v.Body.Cut < len(b) {
		b = b[:*v.Body.Cut]
	}
	return append(b, bytes.Repeat([]byte{0xAA}, v.Body.Extra)...)
}

func (v vector) header(t *testing.T) http.Header {
	h := http.Header{}
	for name, raw := range v.Response.Headers {
		var one string
		var many []string
		switch {
		case json.Unmarshal(raw, &one) == nil:
			h.Add(name, one)
		case json.Unmarshal(raw, &many) == nil:
			for _, s := range many {
				h.Add(name, s)
			}
		default:
			t.Fatalf("%s: header %s", v.Name, name)
		}
	}
	return h
}

// judge mirrors what probe.execute does with one response: AnalyzeHead,
// the same read limits, a capture sink against the reference, Finish.
func judge(t *testing.T, v vector) (model.Check, string) {
	t.Helper()
	maxBody := v.MaxBody
	if maxBody == 0 {
		maxBody = 2 << 20
	}
	const maxTotal, ignoredPrefix, discardLimit = 8 << 20, 64 << 10, 4 << 10
	h := v.header(t)
	head := &transport.Head{Status: v.Response.Status, Proto: "HTTP/1.1", Header: h, ContentLength: -1}
	if cl := h.Get("Content-Length"); cl != "" {
		head.ContentLength, _ = strconv.ParseInt(cl, 10, 64)
	}
	size := v.RefSize
	an := interpret.AnalyzeHead(interpret.Params{Spec: parseSpec(t, v.Request), RefSize: &size}, head)

	var sink *capture.Sink
	var limit int64
	var w func([]byte)
	switch an.Mode {
	case interpret.BodyDiscard:
		limit = min(discardLimit, maxBody, maxTotal)
		sink = capture.New(capture.Config{})
		w = func(p []byte) { sink.Write(p) }
	case interpret.BodyFull:
		limit = min(ignoredPrefix, maxBody, maxTotal)
		sink = capture.New(capture.Config{Ref: bytesRef{size}})
		w = func(p []byte) { sink.Write(p) }
	case interpret.BodyPartial:
		L := an.Declared()
		limit = min(L+1, maxBody, maxTotal)
		sink = capture.New(capture.Config{Start: an.First, Ref: bytesRef{size}})
		n := int64(0)
		w = func(p []byte) { // probe.capSink: the excess probe is never compared
			if room := L - n; room > 0 {
				sink.Write(p[:min(int64(len(p)), room)])
			}
			n += int64(len(p))
		}
	}
	ex := &transport.Exchange{Head: head, Limit: limit}
	if limit > 0 {
		body := v.body()
		got := body[:min(int64(len(body)), limit)]
		w(got)
		ex.Read = int64(len(got))
		ex.EOF = int64(len(body)) < limit && v.Body.Error == ""
		switch v.Body.Error {
		case "error":
			ex.BodyFail = &transport.Failure{Kind: transport.FailNetwork, Message: "network error"}
		case "timeout":
			ex.BodyFail = &transport.Failure{Kind: transport.FailTimeout, Message: "request timeout exceeded"}
		case "cancelled":
			ex.BodyFail = &transport.Failure{Kind: transport.FailCancelled, Message: "run cancelled"}
		}
	}
	fs, _ := an.Finish(ex, sink, true)
	chk := model.Check{Findings: fs}
	chk.Finalize()

	bytesOutcome := "not_compared"
	if sink != nil && sink.Comparing() && an.EncodingOK && (an.Mode == interpret.BodyPartial || an.Mode == interpret.BodyFull) {
		r := sink.Result()
		switch {
		case r.MismatchCount > 0:
			bytesOutcome = "mismatch"
		case r.Compared > 0:
			bytesOutcome = "match"
		}
	}
	return chk, bytesOutcome
}

func TestJudgeCases(t *testing.T) {
	var f struct {
		Vectors []vector `json:"vectors"`
	}
	load(t, "judge.json", &f)
	if len(f.Vectors) < 20 {
		t.Fatalf("only %d vectors", len(f.Vectors))
	}
	ran := 0
	for _, v := range f.Vectors {
		if !v.runsInCLI() {
			continue
		}
		ran++
		want := v.Expect
		chk, bytesOutcome := judge(t, v)
		var ids []string
		for _, fd := range chk.Findings {
			ids = append(ids, fd.ID)
			if _, ok := model.Registry[fd.ID]; !ok {
				t.Errorf("%s: unregistered %s", v.Name, fd.ID)
			}
		}
		slices.Sort(ids)
		if string(chk.Status) != want.Status {
			t.Errorf("%s: status %s, want %s (%v)", v.Name, chk.Status, want.Status, ids)
		}
		if !slices.Equal(ids, want.Findings) && !(len(ids) == 0 && len(want.Findings) == 0) {
			t.Errorf("%s: findings %v, want %v", v.Name, ids, want.Findings)
		}
		if bytesOutcome != want.Bytes {
			t.Errorf("%s: bytes %s, want %s", v.Name, bytesOutcome, want.Bytes)
		}
	}
	if ran == 0 {
		t.Fatal("no CLI vectors ran")
	}
}

// Every ID a case expects must be registered. The CLI's expectation may not
// name a diagnostic that only the page emits.
func TestCasesUseRegisteredIDs(t *testing.T) {
	var f struct {
		Vectors []vector `json:"vectors"`
	}
	load(t, "judge.json", &f)
	for _, v := range f.Vectors {
		exps := []expectation{v.Expect}
		if v.ExpectBrowser != nil {
			exps = append(exps, *v.ExpectBrowser)
		}
		for i, e := range exps {
			for _, id := range e.Findings {
				if _, ok := model.Registry[id]; !ok {
					t.Errorf("%s: %s is not in the registry", v.Name, id)
				}
				if i == 0 && v.runsInCLI() && model.BrowserOnly[id] {
					t.Errorf("%s: the CLI cannot emit browser-only %s", v.Name, id)
				}
			}
		}
	}
}

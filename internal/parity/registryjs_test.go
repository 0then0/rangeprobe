package parity

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/0then0/rangeprobe/internal/model"
)

// generatedRegistryJS renders web/js/registry.js, the page's copy of the
// diagnostics registry, so IDs, kinds and conditions cannot drift. Regenerate
// with
//
//	RANGEPROBE_UPDATE_DOCS=1 go test ./internal/parity -run TestRegistryJS
func generatedRegistryJS(t *testing.T) []byte {
	type entry struct {
		Kind        model.Kind `json:"kind"`
		Title       string     `json:"title"`
		Conditions  []string   `json:"conditions"`
		BrowserOnly bool       `json:"browser_only,omitempty"`
	}
	reg := map[string]entry{}
	for id, info := range model.Registry {
		c := info.Conditions
		if c == nil {
			c = []string{}
		}
		reg[id] = entry{info.Kind, info.Title, c, model.BrowserOnly[id]}
	}
	var js bytes.Buffer
	enc := json.NewEncoder(&js)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(reg); err != nil { // map keys are sorted
		t.Fatal(err)
	}
	var out bytes.Buffer
	out.WriteString(`// Generated from internal/model/diagnostics.go. Do not edit by hand:
//   RANGEPROBE_UPDATE_DOCS=1 go test ./internal/parity -run TestRegistryJS
export const REGISTRY = `)
	out.Write(bytes.TrimRight(js.Bytes(), "\n"))
	out.WriteString(";\n")
	return out.Bytes()
}

func TestRegistryJS(t *testing.T) {
	path := filepath.Join("..", "..", "web", "js", "registry.js")
	want := generatedRegistryJS(t)
	if os.Getenv("RANGEPROBE_UPDATE_DOCS") != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, want, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Error("web/js/registry.js is out of date; run: RANGEPROBE_UPDATE_DOCS=1 go test ./internal/parity -run TestRegistryJS")
	}
}

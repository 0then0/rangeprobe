package redact

import (
	"strings"
	"testing"
)

func TestURL(t *testing.T) {
	r := New(true)
	got := r.URL("https://user:pw@host.example:9000/a/b.parquet?X-Amz-Signature=abc&token=s3cr3t&flag#frag")
	want := "https://host.example:9000/a/b.parquet?X-Amz-Signature=REDACTED&token=REDACTED&flag=REDACTED"
	if got != want {
		t.Errorf("got %q\nwant %q", got, want)
	}
	if strings.Contains(got, "pw") || strings.Contains(got, "s3cr3t") {
		t.Error("secret leaked")
	}
	if got := New(false).URL("https://u:p@h/x?a=1#f"); got != "https://h/x?a=1" {
		t.Errorf("unredacted locations must still drop userinfo: %q", got)
	}
}

func TestPath(t *testing.T) {
	if got := New(true).Path("/home/alice/secret/data.parquet"); got != "data.parquet" {
		t.Errorf("got %q", got)
	}
	if got := New(true).Path(`C:\Users\bob\data.bin`); got != "data.bin" {
		t.Errorf("got %q", got)
	}
	if got := New(false).Path("/x/y.bin"); got != "/x/y.bin" {
		t.Errorf("got %q", got)
	}
}

func TestTextRemovesSecretsAndURLs(t *testing.T) {
	r := New(true)
	r.AddSecret("Bearer topsecret")
	r.AddURL("https://h/x?sig=abc")
	got := r.Text(`Get "https://h/x?sig=abc": dial tcp: refused; hdr Bearer topsecret; see https://other/y?k=v.`)
	for _, bad := range []string{"abc", "topsecret", "k=v"} {
		if strings.Contains(got, bad) {
			t.Errorf("%q leaked in %q", bad, got)
		}
	}
	if !strings.Contains(got, "sig=REDACTED") {
		t.Errorf("expected key to remain: %q", got)
	}
}

func TestCleanNeutralisesUntrustedText(t *testing.T) {
	in := "a\x00b\x1b[31m\u202eevil\u200b\xff<script>"
	got := Clean(in, 0)
	for _, bad := range []string{"\x00", "\x1b", "\u202e", "\u200b", "\xff"} {
		if strings.Contains(got, bad) {
			t.Errorf("control %q survived: %q", bad, got)
		}
	}
	if !strings.Contains(got, `\u202e`) || !strings.Contains(got, `\xff`) {
		t.Errorf("escapes missing: %q", got)
	}
	if long := Clean(strings.Repeat("x", 100), 10); !strings.HasPrefix(long, "xxxxxxxxxx…") {
		t.Errorf("truncation: %q", long)
	}
}

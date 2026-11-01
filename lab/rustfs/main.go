// Command rustfslab is a minimal lab adapter for the RustFS case in
// docs/lab/rustfs-2506.md. It is deliberately not part of the RangeProbe
// module: RangeProbe needs no S3 client, the lab needs only three operations
// against a disposable local RustFS container:
//
//	gen      write a deterministic pseudo-random file
//	put      create a bucket and upload one object (SigV4, single PUT)
//	presign  print a presigned GET URL for the object
//
// Credentials come from RUSTFS_ACCESS_KEY and RUSTFS_SECRET_KEY. Only
// loopback endpoints are accepted.
package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

const region, service = "us-east-1", "s3"

func main() {
	if len(os.Args) < 2 {
		fatal("usage: rustfslab gen|put|presign [flags]")
	}
	switch os.Args[1] {
	case "gen":
		gen(os.Args[2:])
	case "put":
		put(os.Args[2:])
	case "presign":
		presign(os.Args[2:])
	default:
		fatal("unknown command %q", os.Args[1])
	}
}

func fatal(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "rustfslab: "+f+"\n", a...)
	os.Exit(1)
}

func gen(args []string) {
	fs := flag.NewFlagSet("gen", flag.ExitOnError)
	out := fs.String("out", "", "output file")
	size := fs.Int64("size", 24<<20, "size in bytes")
	seed := fs.Uint64("seed", 2506, "PRNG seed")
	fs.Parse(args)
	if *out == "" {
		fatal("gen: -out is required")
	}
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		fatal("%v", err)
	}
	w := bufio.NewWriter(f)
	r := rand.New(rand.NewPCG(*seed, *seed^0x9e3779b97f4a7c15))
	buf := make([]byte, 1<<16)
	for left := *size; left > 0; {
		n := int(min(int64(len(buf)), left))
		for i := 0; i < n; i += 8 {
			v := r.Uint64()
			for j := 0; j < 8 && i+j < n; j++ {
				buf[i+j] = byte(v >> (8 * j))
			}
		}
		w.Write(buf[:n])
		left -= int64(n)
	}
	if err := w.Flush(); err != nil {
		fatal("%v", err)
	}
	if err := f.Close(); err != nil {
		fatal("%v", err)
	}
}

type target struct {
	endpoint     *url.URL
	bucket, key  string
	access, secr string
}

func commonFlags(fs *flag.FlagSet) (*string, *string, *string) {
	return fs.String("endpoint", "http://127.0.0.1:9000", "loopback RustFS endpoint"),
		fs.String("bucket", "rangeprobe-lab", "bucket"),
		fs.String("key", "object.bin", "object key")
}

func newTarget(endpoint, bucket, key string) target {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "http" {
		fatal("endpoint must be a plain http URL on loopback")
	}
	host, _, _ := net.SplitHostPort(u.Host)
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		fatal("refusing non-loopback endpoint %q: the lab only talks to disposable local containers", u.Host)
	}
	a, s := os.Getenv("RUSTFS_ACCESS_KEY"), os.Getenv("RUSTFS_SECRET_KEY")
	if a == "" || s == "" {
		fatal("set RUSTFS_ACCESS_KEY and RUSTFS_SECRET_KEY")
	}
	return target{endpoint: u, bucket: bucket, key: key, access: a, secr: s}
}

func put(args []string) {
	fs := flag.NewFlagSet("put", flag.ExitOnError)
	ep, bucket, key := commonFlags(fs)
	file := fs.String("file", "", "file to upload")
	fs.Parse(args)
	t := newTarget(*ep, *bucket, *key)
	if *file == "" {
		fatal("put: -file is required")
	}
	// Bucket first; 200 or 409 (already owned) are both fine.
	code := t.do("PUT", "/"+t.bucket, nil, 0, sha256Hex(nil))
	if code != 200 && code != 409 {
		fatal("create bucket: HTTP %d", code)
	}
	f, err := os.Open(*file)
	if err != nil {
		fatal("%v", err)
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		fatal("%v", err)
	}
	f.Seek(0, io.SeekStart)
	if code := t.do("PUT", "/"+t.bucket+"/"+t.key, f, n, hex.EncodeToString(h.Sum(nil))); code != 200 {
		fatal("put object: HTTP %d", code)
	}
	fmt.Printf("uploaded %d bytes sha256=%x\n", n, h.Sum(nil))
}

func (t target) do(method, path string, body io.Reader, size int64, payloadHash string) int {
	now := time.Now().UTC()
	amz := now.Format("20060102T150405Z")
	req, _ := http.NewRequest(method, t.endpoint.String()+path, body)
	req.ContentLength = size
	req.Header.Set("x-amz-date", amz)
	req.Header.Set("x-amz-content-sha256", payloadHash)
	signed := "host;x-amz-content-sha256;x-amz-date"
	canonHeaders := "host:" + req.URL.Host + "\nx-amz-content-sha256:" + payloadHash + "\nx-amz-date:" + amz + "\n"
	canon := strings.Join([]string{method, uriEncode(path, false), "", canonHeaders, signed, payloadHash}, "\n")
	sig := t.sign(now, canon, amz)
	req.Header.Set("Authorization", fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		t.access, scope(now), signed, sig))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fatal("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	if resp.StatusCode >= 300 && resp.StatusCode != 409 {
		fmt.Fprintf(os.Stderr, "server said: %s\n", strings.TrimSpace(string(b)))
	}
	return resp.StatusCode
}

func presign(args []string) {
	fs := flag.NewFlagSet("presign", flag.ExitOnError)
	ep, bucket, key := commonFlags(fs)
	expires := fs.Int("expires", 900, "validity in seconds")
	fs.Parse(args)
	t := newTarget(*ep, *bucket, *key)
	now := time.Now().UTC()
	amz := now.Format("20060102T150405Z")
	q := map[string]string{
		"X-Amz-Algorithm":     "AWS4-HMAC-SHA256",
		"X-Amz-Credential":    t.access + "/" + scope(now),
		"X-Amz-Date":          amz,
		"X-Amz-Expires":       fmt.Sprint(*expires),
		"X-Amz-SignedHeaders": "host",
	}
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		parts = append(parts, uriEncode(k, true)+"="+uriEncode(q[k], true))
	}
	cq := strings.Join(parts, "&")
	path := "/" + t.bucket + "/" + t.key
	// Range is not a signed header, so one presigned URL serves every range.
	canon := strings.Join([]string{"GET", uriEncode(path, false), cq, "host:" + t.endpoint.Host + "\n", "host", "UNSIGNED-PAYLOAD"}, "\n")
	fmt.Printf("%s%s?%s&X-Amz-Signature=%s\n", t.endpoint, path, cq, t.sign(now, canon, amz))
}

func scope(t time.Time) string {
	return t.Format("20060102") + "/" + region + "/" + service + "/aws4_request"
}

func (t target) sign(now time.Time, canonical, amz string) string {
	sts := "AWS4-HMAC-SHA256\n" + amz + "\n" + scope(now) + "\n" + sha256Hex([]byte(canonical))
	k := hmacSHA([]byte("AWS4"+t.secr), now.Format("20060102"))
	k = hmacSHA(k, region)
	k = hmacSHA(k, service)
	k = hmacSHA(k, "aws4_request")
	return hex.EncodeToString(hmacSHA(k, sts))
}

func hmacSHA(key []byte, msg string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(msg))
	return m.Sum(nil)
}

func sha256Hex(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func uriEncode(s string, encodeSlash bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		case c == '/' && !encodeSlash:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

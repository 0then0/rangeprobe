// Command browser is the local test stand of the RangeProbe browser page. It
// serves the page on one origin and a file with reproducible behaviours on
// another, so that CORS, hidden headers and the page's read limits can be
// tried in a real browser. It is not part of the CLI and serves only
// loopback addresses by default.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/0then0/rangeprobe/internal/testsrv"
)

func main() {
	var (
		pageAddr   = flag.String("page-addr", "127.0.0.1:18080", "listen address of the page origin")
		dataAddr   = flag.String("data-addr", "127.0.0.1:18081", "listen address of the file origin")
		pageOrigin = flag.String("page-origin", "http://localhost:18080", "origin the browser uses for the page (must differ from the file origin)")
		dataOrigin = flag.String("data-origin", "http://127.0.0.1:18081", "origin the browser uses for the files")
		web        = flag.String("web", "web", "directory of the static page")
		size       = flag.Int("size", 1<<20, "length of the reference file in bytes")
		large      = flag.Int64("large-size", 256<<20, "length of the full response of range-ignored-large")
		slow       = flag.Duration("slow", 20*time.Second, "how long the slow routes stall")
		refOut     = flag.String("write-reference", "", "also write the reference file to this path")
	)
	flag.Parse()
	if *pageOrigin == *dataOrigin {
		log.Fatal("the page origin and the file origin must differ")
	}
	if *size < 0 || *large < 1 {
		log.Fatal("invalid size")
	}
	if _, err := os.Stat(*web + "/index.html"); err != nil {
		log.Fatalf("no page in -web %q: %v", *web, err)
	}
	l := newLab(config{PageOrigin: *pageOrigin, DataOrigin: *dataOrigin, WebDir: *web, Size: *size, LargeSize: *large, Slow: *slow})
	if *refOut != "" {
		if err := os.WriteFile(*refOut, testsrv.Content(*size), 0o644); err != nil {
			log.Fatal(err)
		}
	}

	servers := []*http.Server{
		{Addr: *pageAddr, Handler: l.pageHandler(), ReadHeaderTimeout: 10 * time.Second},
		{Addr: *dataAddr, Handler: l.dataHandler(), ReadHeaderTimeout: 10 * time.Second},
	}
	for _, s := range servers {
		go func() {
			if err := s.ListenAndServe(); err != http.ErrServerClosed {
				log.Fatal(err)
			}
		}()
	}
	fmt.Printf("page:  %s\nfiles: %s\n\n%s", *pageOrigin, *dataOrigin, l.index())

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for _, s := range servers {
		s.Shutdown(ctx)
	}
}

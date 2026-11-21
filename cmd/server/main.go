// Command server runs the OPRF HTTP server.
package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/andresgomez2310/OPRF---BloomFilter/internal/oprfserver"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "server:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	f := flag.NewFlagSet("server", flag.ContinueOnError)
	addr := f.String("addr", ":8080", "listen address")
	seedPath := f.String("seed-file", "", "OPRF seed file as hex")
	filterDir := f.String("filter-dir", "", "published filter directory")
	keyInfo := f.String("key-info", "", "OPRF DeriveKey info (must match admin)")
	if err := f.Parse(args); err != nil {
		return err
	}

	srv, err := oprfserver.New(oprfserver.Config{
		SeedPath:  *seedPath,
		KeyInfo:   []byte(*keyInfo),
		FilterDir: *filterDir,
	})
	if err != nil {
		return err
	}

	httpServer := &http.Server{
		Addr:              *addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	fmt.Fprintln(os.Stderr, "server listening on", *addr)
	return httpServer.ListenAndServe()
}
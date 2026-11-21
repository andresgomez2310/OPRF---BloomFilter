// Command cliente reads one password from stdin and prints a verdict.
// It sends only a blinded element to the OPRF server. It does not read skS.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/andresgomez2310/OPRF---BloomFilter/internal/client"
)

func main() {
	info, err := os.Stdin.Stat()
	interactive := err == nil && info.Mode()&os.ModeCharDevice != 0
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, interactive); err != nil {
		fmt.Fprintln(os.Stderr, "cliente:", err)
		os.Exit(1)
	}
}

func run(args []string, in io.Reader, out, errOut io.Writer, interactive bool) error {
	flags := flag.NewFlagSet("cliente", flag.ContinueOnError)
	flags.SetOutput(errOut)
	server := flags.String("server", os.Getenv("SERVER_URL"), "OPRF server base URL")
	cache := flags.String("cache", os.Getenv("CACHE_DIR"), "directory for the epoch's manifest and bloom.bin")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("the password is read from stdin, not from arguments")
	}
	if *server == "" || *cache == "" {
		return fmt.Errorf("server and cache are required")
	}

	password, err := client.ReadPassword(in, errOut, interactive)
	if err != nil {
		return err
	}
	outcome, err := client.Consult(password, client.Config{
		ServerURL: *server,
		CacheDir:  *cache,
	})
	if err != nil {
		return err
	}
	_, err = io.WriteString(out, outcome.Format())
	return err
}

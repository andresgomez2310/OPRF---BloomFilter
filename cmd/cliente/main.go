// Command cliente reads one password from stdin and prints a verdict.
// It sends only a blinded element to the OPRF server. It does not read skS.
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

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
	publicKeyPath := flags.String("signing-public-file", os.Getenv("SIGNING_PUBLIC_FILE"), "institutional Ed25519 public key (hex file)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("the password is read from stdin, not from arguments")
	}
	if *server == "" || *cache == "" || *publicKeyPath == "" {
		return fmt.Errorf("server, cache and institutional public key are required")
	}
	keyHex, err := os.ReadFile(*publicKeyPath)
	if err != nil {
		return fmt.Errorf("read public key: %w", err)
	}
	publicKey, err := hex.DecodeString(strings.TrimSpace(string(keyHex)))
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid institutional public key: expected 32 bytes in hex")
	}

	password, err := client.ReadPassword(in, errOut, interactive)
	if err != nil {
		return err
	}
	outcome, err := client.Consult(password, client.Config{
		ServerURL:         *server,
		CacheDir:          *cache,
		TrustedSigningKey: ed25519.PublicKey(publicKey),
	})
	if err != nil {
		return err
	}
	_, err = io.WriteString(out, outcome.Format())
	return err
}

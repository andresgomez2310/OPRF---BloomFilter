// Command cliente reads one password from stdin and prints a verdict.
// It evaluates the blinded element in-process with the same server key that
// built the published filter. It does not open an HTTP listener.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/andresgomez2310/OPRF---BloomFilter/internal/adminbuild"
	"github.com/andresgomez2310/OPRF---BloomFilter/internal/client"
	"github.com/andresgomez2310/OPRF---BloomFilter/internal/oprfcore"
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
	seedPath := flags.String("seed-file", "", "32-byte OPRF key derivation seed as hex")
	keyInfo := flags.String("key-info", "", "OPRF DeriveKey info string used to build the filter")
	epoch := flags.String("epoch", "", "epoch of the server key used for evaluation")
	published := flags.String("published", "", "directory with manifest.json and bloom.bin")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("the password is read from stdin, not from arguments")
	}
	if *seedPath == "" || *epoch == "" || *published == "" {
		return fmt.Errorf("seed-file, epoch and published are required")
	}

	password, err := client.ReadPassword(in, errOut, interactive)
	if err != nil {
		return err
	}
	seed, err := adminbuild.ReadHexFile(*seedPath, 32)
	if err != nil {
		return err
	}
	key, err := oprfcore.DeriveServerKey(seed, []byte(*keyInfo))
	if err != nil {
		return err
	}
	outcome, err := client.Consult(password, key, *epoch, *published)
	if err != nil {
		return err
	}
	_, err = io.WriteString(out, outcome.Format())
	return err
}

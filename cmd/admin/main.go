// Command admin builds and publishes signed Bloom artifacts; it never starts an HTTP listener.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/andresgomez2310/OPRF---BloomFilter/internal/adminbuild"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "admin:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: admin init-test-keys|build-filter|publish [options]")
	}
	switch args[0] {
	case "init-test-keys":
		f := flag.NewFlagSet("init-test-keys", flag.ContinueOnError)
		dir := f.String("dir", "", "directory outside git repository for test keys")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if *dir == "" {
			return fmt.Errorf("dir is required")
		}
		if err := os.MkdirAll(*dir, 0700); err != nil {
			return err
		}
		seed := make([]byte, 32)
		if _, err := rand.Read(seed); err != nil {
			return err
		}
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		files := []struct {
			name string
			data []byte
			mode os.FileMode
		}{
			{"oprf-seed.hex", seed, 0600},
			{"signing-seed.hex", priv.Seed(), 0600},
			{"signing-public.hex", pub, 0644},
		}
		for _, file := range files {
			dest := filepath.Join(*dir, file.name)
			f, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, file.mode)
			if err != nil {
				return fmt.Errorf("refusing to overwrite %s: %w", dest, err)
			}
			_, writeErr := f.WriteString(hex.EncodeToString(file.data) + "\n")
			closeErr := f.Close()
			if writeErr != nil {
				return writeErr
			}
			if closeErr != nil {
				return closeErr
			}
		}
		fmt.Println("test keys created outside repository in", *dir)
		return nil
	case "build-filter":
		f := flag.NewFlagSet("build-filter", flag.ContinueOnError)
		corpus := f.String("corpus", "", "text corpus: one password per line")
		seed := f.String("seed-file", "", "32-byte OPRF key derivation seed as hex")
		keyInfo := f.String("key-info", "", "optional OPRF DeriveKey info string (must match server)")
		sign := f.String("signing-seed-file", "", "institutional Ed25519 seed as hex")
		epoch := f.String("epoch", "", "current server key epoch")
		fpp := f.Float64("fpp", adminbuild.DefaultFPP, "target false-positive probability")
		out := f.String("out", "", "output directory")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		m, err := adminbuild.Build(adminbuild.BuildConfig{CorpusPath: *corpus, SeedPath: *seed, KeyInfo: []byte(*keyInfo), SigningKeyPath: *sign, KeyEpoch: *epoch, TargetFPP: *fpp, OutputDir: *out, Now: time.Now().UTC()})
		if err != nil {
			return err
		}
		result, err := json.MarshalIndent(m, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(result))
		return nil
	case "publish":
		f := flag.NewFlagSet("publish", flag.ContinueOnError)
		source := f.String("from", "", "signed artifact directory")
		to := f.String("to", "", "server's shared filter directory")
		public := f.String("public-key-file", "", "institutional Ed25519 public key as hex")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		key, err := adminbuild.ReadHexFile(*public, ed25519.PublicKeySize)
		if err != nil {
			return err
		}
		if err := adminbuild.Publish(*source, *to, ed25519.PublicKey(key)); err != nil {
			return err
		}
		fmt.Println("published manifest.json and bloom.bin in", *to)
		return nil
	default:
		return fmt.Errorf("unknown command %q: use build-filter or publish", args[0])
	}
}

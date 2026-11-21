package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/andresgomez2310/OPRF---BloomFilter/internal/adminbuild"
	"github.com/andresgomez2310/OPRF---BloomFilter/internal/client"
	"github.com/andresgomez2310/OPRF---BloomFilter/internal/oprfserver"
)

func TestCLIReadsPasswordFromStdin(t *testing.T) {
	const (
		epoch    = "2026-11-13T16:00:00Z"
		password = "clave-presente"
	)
	dir := t.TempDir()
	seed := bytes.Repeat([]byte{0x12}, 32)
	signingSeed := bytes.Repeat([]byte{0x45}, 32)
	seedPath := filepath.Join(dir, "oprf.hex")
	if err := os.WriteFile(seedPath, []byte(hex.EncodeToString(seed)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "signing.hex"), []byte(hex.EncodeToString(signingSeed)), 0600); err != nil {
		t.Fatal(err)
	}
	corpusPath := filepath.Join(dir, "corpus.txt")
	if err := os.WriteFile(corpusPath, []byte(password+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	published := filepath.Join(dir, "published")
	if _, err := adminbuild.Build(adminbuild.BuildConfig{
		CorpusPath:     corpusPath,
		SeedPath:       seedPath,
		SigningKeyPath: filepath.Join(dir, "signing.hex"),
		KeyEpoch:       epoch,
		TargetFPP:      1e-12,
		OutputDir:      published,
		Now:            time.Date(2026, 11, 13, 16, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatal(err)
	}
	server, err := oprfserver.New(oprfserver.Config{SeedPath: seedPath, FilterDir: published})
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(server.Handler())
	t.Cleanup(httpServer.Close)

	cache := filepath.Join(dir, "cache")
	publicKeyFile := filepath.Join(dir, "signing-public.hex")
	publicKey := ed25519.NewKeyFromSeed(signingSeed).Public().(ed25519.PublicKey)
	if err := os.WriteFile(publicKeyFile, []byte(hex.EncodeToString(publicKey)), 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"-server", httpServer.URL, "-cache", cache, "-signing-public-file", publicKeyFile}
	for _, arg := range args {
		if strings.Contains(arg, password) || strings.Contains(arg, "oprf.hex") {
			t.Fatal("password or server key was passed to the client")
		}
	}

	var stdout, stderr bytes.Buffer
	err = run(args, strings.NewReader(password+"\n"), &stdout, &stderr, false)
	if err != nil {
		t.Fatal(err)
	}
	want := client.VerdictCompromised + "\n" + client.NoteFalsePositive + "\n"
	if stdout.String() != want {
		t.Fatalf("stdout %q", stdout.String())
	}
	if strings.Contains(stdout.String(), password) {
		t.Fatal("stdout contains the password")
	}

	stdout.Reset()
	err = run(append(args, password), strings.NewReader(password+"\n"), &stdout, &stderr, false)
	if err == nil || stdout.Len() != 0 {
		t.Fatalf("argument password produced err=%v stdout=%q", err, stdout.String())
	}
}

package adminbuild

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/andresgomez2310/OPRF---BloomFilter/internal/bloom"
	"github.com/andresgomez2310/OPRF---BloomFilter/internal/canonical"
	"github.com/andresgomez2310/OPRF---BloomFilter/internal/oprfcore"
)

func fixture(t *testing.T, corpus string) (BuildConfig, ed25519.PublicKey) {
	t.Helper()
	dir := t.TempDir()
	seed := bytes.Repeat([]byte{0x12}, 32)
	signingSeed := bytes.Repeat([]byte{0x45}, 32)
	for name, value := range map[string][]byte{"oprf.hex": seed, "signing.hex": signingSeed} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(hex.EncodeToString(value)), 0600); err != nil {
			t.Fatal(err)
		}
	}
	corpusPath := filepath.Join(dir, "corpus.txt")
	if err := os.WriteFile(corpusPath, []byte(corpus), 0600); err != nil {
		t.Fatal(err)
	}
	return BuildConfig{
		CorpusPath: corpusPath, SeedPath: filepath.Join(dir, "oprf.hex"), SigningKeyPath: filepath.Join(dir, "signing.hex"),
		KeyEpoch: "2026-11-12T20:00:00Z", TargetFPP: DefaultFPP, OutputDir: filepath.Join(dir, "out"),
		Now: time.Date(2026, 11, 12, 20, 0, 0, 0, time.UTC),
	}, ed25519.NewKeyFromSeed(signingSeed).Public().(ed25519.PublicKey)
}
func TestBuildSignDigestAndCanonical(t *testing.T) {
	cfg, pub := fixture(t, "café\ncafe\u0301\n ")
	m, err := Build(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if m.Parameters.NElements != 3 {
		t.Fatalf("n=%d", m.Parameters.NElements)
	}
	raw, err := os.ReadFile(filepath.Join(cfg.OutputDir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	vector, err := os.ReadFile(filepath.Join(cfg.OutputDir, "bloom.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(raw), `{"version":"1.0.0","key_epoch":`) {
		t.Fatalf("unexpected field order: %s", raw)
	}
	got, err := Verify(raw, vector, pub)
	if err != nil {
		t.Fatal(err)
	}
	if got.Signature != m.Signature {
		t.Fatal("signature roundtrip")
	}
	sum := sha256.Sum256(vector)
	if m.BloomBinDigest != hex.EncodeToString(sum[:]) {
		t.Fatal("digest mismatch")
	}
	key, err := oprfcore.DeriveServerKey(bytes.Repeat([]byte{0x12}, 32), nil)
	if err != nil {
		t.Fatal(err)
	}
	f, err := bloom.FromBytes(m.Parameters.MBits, m.Parameters.KHashes, vector)
	if err != nil {
		t.Fatal(err)
	}
	for _, password := range []string{"café", "cafe\u0301", " "} {
		input, err := canonical.PasswordBytes(password)
		if err != nil {
			t.Fatal(err)
		}
		output, err := oprfcore.Evaluate(key, input)
		if err != nil {
			t.Fatal(err)
		}
		ok, err := f.Contains(output)
		if err != nil || !ok {
			t.Fatalf("missing %q: %v", password, err)
		}
	}
	if bytes.Contains(raw, []byte("café")) {
		t.Fatal("plaintext leaked into manifest")
	}
}
func TestTamperingRejected(t *testing.T) {
	cfg, pub := fixture(t, "abc\ndef\n")
	_, err := Build(cfg)
	if err != nil {
		t.Fatal(err)
	}
	signed, _ := os.ReadFile(filepath.Join(cfg.OutputDir, "manifest.json"))
	bloomBytes, _ := os.ReadFile(filepath.Join(cfg.OutputDir, "bloom.bin"))
	changed := append([]byte(nil), bloomBytes...)
	changed[0] ^= 0x80
	if _, err := Verify(signed, changed, pub); err == nil {
		t.Fatal("tampered bloom accepted")
	}
	var m Manifest
	if err := json.Unmarshal(signed, &m); err != nil {
		t.Fatal(err)
	}
	m.KeyEpoch = "wrong"
	edited, _ := json.Marshal(m)
	if _, err := Verify(edited, bloomBytes, pub); err == nil {
		t.Fatal("tampered signature accepted")
	}
	if err := Publish(cfg.OutputDir, filepath.Join(t.TempDir(), "published"), pub); err != nil {
		t.Fatal(err)
	}
}
func TestPublishCopiesExactBytes(t *testing.T) {
	cfg, pub := fixture(t, "alpha\nbeta\n")
	if _, err := Build(cfg); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "published")
	if err := Publish(cfg.OutputDir, dest, pub); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"manifest.json", "bloom.bin"} {
		a, err := os.ReadFile(filepath.Join(cfg.OutputDir, name))
		if err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(filepath.Join(dest, name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(a, b) {
			t.Fatalf("published %s differs", name)
		}
	}
}
func TestInvalidInputs(t *testing.T) {
	cfg, _ := fixture(t, "")
	if _, err := Build(cfg); err == nil {
		t.Fatal("empty corpus accepted")
	}
	cfg, _ = fixture(t, "abc\n")
	cfg.TargetFPP = 1.1
	if _, err := Build(cfg); err == nil {
		t.Fatal("bad FPP accepted")
	}
	cfg, _ = fixture(t, "abc\n")
	if err := os.WriteFile(cfg.SigningKeyPath, []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Build(cfg); err == nil {
		t.Fatal("bad key accepted")
	}
}
func TestOneThousandEntries(t *testing.T) {
	var lines strings.Builder
	for i := 0; i < 1000; i++ {
		lines.WriteString("password-")
		lines.WriteString(strings.Repeat("a", i%40))
		lines.WriteByte('\n')
	}
	cfg, pub := fixture(t, lines.String())
	m, err := Build(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if m.Parameters.NElements != 1000 {
		t.Fatal(m.Parameters.NElements)
	}
	signed, _ := os.ReadFile(filepath.Join(cfg.OutputDir, "manifest.json"))
	vector, _ := os.ReadFile(filepath.Join(cfg.OutputDir, "bloom.bin"))
	if _, err := Verify(signed, vector, pub); err != nil {
		t.Fatal(err)
	}
}

func TestOneHundredThousandEntries(t *testing.T) {
	if testing.Short() {
		t.Skip("100,000-entry workload")
	}
	var corpus strings.Builder
	for i := 0; i < 100000; i++ {
		fmt.Fprintf(&corpus, "test-%06d\n", i)
	}
	cfg, pub := fixture(t, corpus.String())
	m, err := Build(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if m.Parameters.NElements != 100000 || m.Parameters.MBits != 958506 || m.Parameters.KHashes != 7 {
		t.Fatalf("unexpected parameters: %+v", m.Parameters)
	}
	manifest, err := os.ReadFile(filepath.Join(cfg.OutputDir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(cfg.OutputDir, "bloom.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(manifest, data, pub); err != nil {
		t.Fatal(err)
	}
}

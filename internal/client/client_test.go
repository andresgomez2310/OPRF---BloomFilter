package client_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/andresgomez2310/OPRF---BloomFilter/internal/adminbuild"
	"github.com/andresgomez2310/OPRF---BloomFilter/internal/bloom"
	"github.com/andresgomez2310/OPRF---BloomFilter/internal/canonical"
	"github.com/andresgomez2310/OPRF---BloomFilter/internal/client"
	"github.com/andresgomez2310/OPRF---BloomFilter/internal/oprfcore"
)

func publish(t *testing.T, corpus, epoch string, fpp float64) (*oprfcore.ServerKey, string) {
	t.Helper()
	dir := t.TempDir()
	seed := bytes.Repeat([]byte{0x12}, 32)
	signingSeed := bytes.Repeat([]byte{0x45}, 32)
	if err := os.WriteFile(filepath.Join(dir, "oprf.hex"), []byte(hex.EncodeToString(seed)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "signing.hex"), []byte(hex.EncodeToString(signingSeed)), 0600); err != nil {
		t.Fatal(err)
	}
	corpusPath := filepath.Join(dir, "corpus.txt")
	if err := os.WriteFile(corpusPath, []byte(corpus), 0600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "published")
	_, err := adminbuild.Build(adminbuild.BuildConfig{
		CorpusPath:     corpusPath,
		SeedPath:       filepath.Join(dir, "oprf.hex"),
		KeyInfo:        []byte("epoca-prueba"),
		SigningKeyPath: filepath.Join(dir, "signing.hex"),
		KeyEpoch:       epoch,
		TargetFPP:      fpp,
		OutputDir:      out,
		Now:            time.Date(2026, 11, 13, 16, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	key, err := oprfcore.DeriveServerKey(seed, []byte("epoca-prueba"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(out, "manifest.json")); err != nil {
		t.Fatal(err)
	}
	return key, out
}

func TestPresentPasswordIsCompromised(t *testing.T) {
	const (
		epoch    = "2026-11-13T16:00:00Z"
		password = "clave-presente"
	)
	key, dir := publish(t, password+"\n", epoch, 1e-12)
	got, err := client.Consult(password, key, epoch, dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.Verdict != client.VerdictCompromised {
		t.Fatalf("verdict %q", got.Verdict)
	}
	if !strings.Contains(got.Note, "falso positivo") {
		t.Fatalf("note does not mention a false positive: %q", got.Note)
	}
	input, err := canonical.PasswordBytes(password)
	if err != nil {
		t.Fatal(err)
	}
	direct, err := oprfcore.Evaluate(key, input)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Output, direct) {
		t.Fatalf("lookup output does not match Evaluate\ngot:  %x\nwant: %x", got.Output, direct)
	}
}

func TestAbsentPasswordIsNotInThePublishedSet(t *testing.T) {
	const epoch = "2026-11-13T16:00:00Z"
	key, dir := publish(t, "clave-presente\n", epoch, 1e-12)
	got, err := client.Consult("clave-ausente", key, epoch, dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.Verdict != client.VerdictNotFound {
		t.Fatalf("verdict %q", got.Verdict)
	}
	if !strings.Contains(got.Note, "conjunto publicado") {
		t.Fatalf("note does not limit the result to the published set: %q", got.Note)
	}
	lower := strings.ToLower(got.Verdict + " " + got.Note)
	if strings.Contains(lower, "segura") || strings.Contains(lower, "fuerte") {
		t.Fatalf("absence verdict judges strength: %q", got.Format())
	}
}

func TestRepeatedQueryKeepsVerdictAndChangesBlind(t *testing.T) {
	const (
		epoch    = "2026-11-13T16:00:00Z"
		password = "clave-presente"
	)
	key, dir := publish(t, password+"\n", epoch, 1e-12)
	first, err := client.Consult(password, key, epoch, dir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := client.Consult(password, key, epoch, dir)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first.BlindedElement, second.BlindedElement) {
		t.Fatal("repeated queries reused the blinded element")
	}
	if first.Verdict != client.VerdictCompromised || second.Verdict != first.Verdict {
		t.Fatalf("verdicts %q and %q", first.Verdict, second.Verdict)
	}
	if !bytes.Equal(first.Output, second.Output) {
		t.Fatal("repeated queries changed the OPRF output")
	}
}

func TestEpochMismatchEmitsNoVerdict(t *testing.T) {
	key, dir := publish(t, "clave-presente\n", "2026-11-13T16:00:00Z", 1e-12)
	got, err := client.Consult("clave-presente", key, "2026-11-13T17:00:00Z", dir)
	if !errors.Is(err, client.ErrEpochMismatch) {
		t.Fatalf("got %v", err)
	}
	if got.Verdict != "" || got.Format() != "" {
		t.Fatalf("epoch mismatch produced a verdict: %#v", got)
	}
}

func TestInvalidEvaluatedElementEmitsNoVerdict(t *testing.T) {
	input, err := canonical.PasswordBytes("clave-presente")
	if err != nil {
		t.Fatal(err)
	}
	query, err := oprfcore.Blind(input)
	if err != nil {
		t.Fatal(err)
	}
	filter, err := bloom.New(1, 1e-12)
	if err != nil {
		t.Fatal(err)
	}
	got, err := client.Complete(query, []byte{0x01, 0x02}, filter)
	if err == nil {
		t.Fatal("invalid evaluated element was accepted")
	}
	if got.Verdict != "" || got.Output != nil {
		t.Fatalf("invalid element produced a verdict: %#v", got)
	}
}

func TestReadPasswordFromStdinKeepsSpaces(t *testing.T) {
	var prompt bytes.Buffer
	got, err := client.ReadPassword(strings.NewReader(" clave \n"), &prompt, true)
	if err != nil {
		t.Fatal(err)
	}
	if got != " clave " {
		t.Fatalf("password changed: %q", got)
	}
	if prompt.String() != "Contraseña: " {
		t.Fatalf("prompt %q", prompt.String())
	}
	if _, err := client.ReadPassword(strings.NewReader(""), io.Discard, false); err == nil {
		t.Fatal("empty stdin produced a password")
	}
}

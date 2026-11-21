package client_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/andresgomez2310/OPRF---BloomFilter/internal/adminbuild"
	"github.com/andresgomez2310/OPRF---BloomFilter/internal/bloom"
	"github.com/andresgomez2310/OPRF---BloomFilter/internal/canonical"
	"github.com/andresgomez2310/OPRF---BloomFilter/internal/client"
	"github.com/andresgomez2310/OPRF---BloomFilter/internal/oprfcore"
	"github.com/andresgomez2310/OPRF---BloomFilter/internal/oprfserver"
)

// published runs the OPRF server with skS. The client config only receives the URL and a cache directory.
type published struct {
	cfg       client.Config
	dir       string
	filterDir string
	seedPath  string
	signPath  string
	corpus    string
	epoch     string
	key       *oprfcore.ServerKey
	bloomGets int
	failBloom bool
	mu        sync.Mutex
}

func publish(t *testing.T, corpus, epoch string, fpp float64) *published {
	t.Helper()
	dir := t.TempDir()
	seed := bytes.Repeat([]byte{0x12}, 32)
	signingSeed := bytes.Repeat([]byte{0x45}, 32)
	seedPath := filepath.Join(dir, "oprf.hex")
	signPath := filepath.Join(dir, "signing.hex")
	if err := os.WriteFile(seedPath, []byte(hex.EncodeToString(seed)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(signPath, []byte(hex.EncodeToString(signingSeed)), 0600); err != nil {
		t.Fatal(err)
	}
	corpusPath := filepath.Join(dir, "corpus.txt")
	if err := os.WriteFile(corpusPath, []byte(corpus), 0600); err != nil {
		t.Fatal(err)
	}
	filterDir := filepath.Join(dir, "published")
	if _, err := adminbuild.Build(adminbuild.BuildConfig{
		CorpusPath:     corpusPath,
		SeedPath:       seedPath,
		SigningKeyPath: signPath,
		KeyEpoch:       epoch,
		TargetFPP:      fpp,
		OutputDir:      filterDir,
		Now:            time.Date(2026, 11, 13, 16, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatal(err)
	}
	key, err := oprfcore.DeriveServerKey(seed, nil)
	if err != nil {
		t.Fatal(err)
	}
	server, err := oprfserver.New(oprfserver.Config{SeedPath: seedPath, FilterDir: filterDir})
	if err != nil {
		t.Fatal(err)
	}
	p := &published{
		dir: dir, filterDir: filterDir, seedPath: seedPath, signPath: signPath,
		corpus: corpusPath, epoch: epoch, key: key,
	}
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/filter/bloom" {
			p.mu.Lock()
			p.bloomGets++
			fail := p.failBloom
			p.mu.Unlock()
			if fail {
				http.Error(w, "bloom unavailable", http.StatusServiceUnavailable)
				return
			}
		}
		server.Handler().ServeHTTP(w, r)
	}))
	t.Cleanup(httpServer.Close)
	p.cfg = client.Config{ServerURL: httpServer.URL, CacheDir: filepath.Join(dir, "cache"), TrustedSigningKey: ed25519.NewKeyFromSeed(signingSeed).Public().(ed25519.PublicKey)}
	return p
}

func (p *published) bloomDownloads() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.bloomGets
}

func TestTicket08RejectsTamperedManifestAndWrongKey(t *testing.T) {
	p := publish(t, "presente\n", "2026-11-13T16:00:00Z", .01)
	manifestPath := filepath.Join(p.filterDir, "manifest.json")
	original, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var manifest adminbuild.Manifest
	if err := json.Unmarshal(original, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.Signature = strings.Repeat("0", len(manifest.Signature))
	tampered, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, tampered, 0600); err != nil {
		t.Fatal(err)
	}
	if result, err := client.Consult("presente", p.cfg); err == nil || result.Verdict != "" {
		t.Fatal("accepted a forged manifest")
	}
	if err := os.WriteFile(manifestPath, original, 0600); err != nil {
		t.Fatal(err)
	}
	p.cfg.TrustedSigningKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x99}, 32)).Public().(ed25519.PublicKey)
	if result, err := client.Consult("presente", p.cfg); err == nil || result.Verdict != "" {
		t.Fatal("accepted a different signing key")
	}
}

func TestTicket08RejectsTamperedFilterAndCache(t *testing.T) {
	p := publish(t, "presente\n", "2026-11-13T16:00:00Z", .01)
	path := filepath.Join(p.filterDir, "bloom.bin")
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), original...)
	tampered[0] ^= 0x80
	if err := os.WriteFile(path, tampered, 0600); err != nil {
		t.Fatal(err)
	}
	if result, err := client.Consult("presente", p.cfg); err == nil || result.Verdict != "" {
		t.Fatal("accepted modified bloom")
	}
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Consult("presente", p.cfg); err != nil {
		t.Fatal(err)
	}
	cacheManifest := filepath.Join(p.cfg.CacheDir, "manifest.json")
	if err := os.WriteFile(cacheManifest, []byte(`{"key_epoch":"2026-11-13T16:00:00Z"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if result, err := client.Consult("presente", p.cfg); err != nil || result.Verdict != client.VerdictCompromised {
		t.Fatalf("failed to refresh invalid cache: %v", err)
	}
	if p.bloomDownloads() < 3 {
		t.Fatal("tampered cache was reused without redownload")
	}
}

func TestPresentPasswordIsCompromised(t *testing.T) {
	const (
		epoch    = "2026-11-13T16:00:00Z"
		password = "clave-presente"
	)
	p := publish(t, password+"\n", epoch, 1e-12)
	got, err := client.Consult(password, p.cfg)
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
	direct, err := oprfcore.Evaluate(p.key, input)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Output, direct) {
		t.Fatalf("lookup output does not match Evaluate\ngot:  %x\nwant: %x", got.Output, direct)
	}
}

func TestAbsentPasswordIsNotInThePublishedSet(t *testing.T) {
	const epoch = "2026-11-13T16:00:00Z"
	p := publish(t, "clave-presente\n", epoch, 1e-12)
	input, err := canonical.PasswordBytes("clave-ausente")
	if err != nil {
		t.Fatal(err)
	}
	output, err := oprfcore.Evaluate(p.key, input)
	if err != nil {
		t.Fatal(err)
	}
	vector, err := os.ReadFile(filepath.Join(p.filterDir, "bloom.bin"))
	if err != nil {
		t.Fatal(err)
	}
	manifestBytes, err := os.ReadFile(filepath.Join(p.filterDir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest adminbuild.Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatal(err)
	}
	filter, err := bloom.FromBytes(manifest.Parameters.MBits, manifest.Parameters.KHashes, vector)
	if err != nil {
		t.Fatal(err)
	}
	present, err := filter.Contains(output)
	if err != nil {
		t.Fatal(err)
	}
	if present {
		t.Fatal("fixture password is not absent from the published filter")
	}
	got, err := client.Consult("clave-ausente", p.cfg)
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
	p := publish(t, password+"\n", epoch, 1e-12)
	first, err := client.Consult(password, p.cfg)
	if err != nil {
		t.Fatal(err)
	}
	second, err := client.Consult(password, p.cfg)
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
	if p.bloomDownloads() != 1 {
		t.Fatalf("cached epoch downloaded bloom.bin %d times", p.bloomDownloads())
	}
}

func TestRotationRefreshesFilterBeforeVerdict(t *testing.T) {
	const password = "clave-presente"
	p := publish(t, password+"\n", "2026-11-13T16:00:00Z", 1e-12)
	first, err := client.Consult(password, p.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if first.Verdict != client.VerdictCompromised {
		t.Fatalf("verdict %q", first.Verdict)
	}
	oldBloom, err := os.ReadFile(filepath.Join(p.cfg.CacheDir, "bloom.bin"))
	if err != nil {
		t.Fatal(err)
	}

	signingSeed, err := adminbuild.ReadHexFile(p.signPath, ed25519.SeedSize)
	if err != nil {
		t.Fatal(err)
	}
	public := ed25519.NewKeyFromSeed(signingSeed).Public().(ed25519.PublicKey)
	rotated, err := adminbuild.Rotate(adminbuild.RotateConfig{
		CorpusPath:     p.corpus,
		SeedPath:       p.seedPath,
		SigningKeyPath: p.signPath,
		TargetFPP:      1e-12,
		OutputDir:      filepath.Join(p.dir, "rotated"),
		PublishDir:     p.filterDir,
		PublicKey:      public,
		Now:            time.Date(2026, 11, 13, 17, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}

	second, err := client.Consult(password, p.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if second.Verdict != client.VerdictCompromised {
		t.Fatalf("verdict after rotation %q", second.Verdict)
	}
	if p.bloomDownloads() != 2 {
		t.Fatalf("rotation downloaded bloom.bin %d times", p.bloomDownloads())
	}
	cachedManifest, err := os.ReadFile(filepath.Join(p.cfg.CacheDir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest adminbuild.Manifest
	if err := json.Unmarshal(cachedManifest, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.KeyEpoch != rotated.KeyEpoch {
		t.Fatalf("cache epoch %q, rotated epoch %q", manifest.KeyEpoch, rotated.KeyEpoch)
	}
	cachedBloom, err := os.ReadFile(filepath.Join(p.cfg.CacheDir, "bloom.bin"))
	if err != nil {
		t.Fatal(err)
	}
	publishedBloom, err := os.ReadFile(filepath.Join(p.filterDir, "bloom.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cachedBloom, publishedBloom) {
		t.Fatal("cache kept a filter other than the published one")
	}
	if bytes.Equal(cachedBloom, oldBloom) {
		t.Fatal("verdict used the filter from the previous epoch")
	}
}

func TestStaleCacheDoesNotVerdictWhenRefreshFails(t *testing.T) {
	const password = "clave-presente"
	p := publish(t, password+"\n", "2026-11-13T16:00:00Z", 1e-12)
	if _, err := client.Consult(password, p.cfg); err != nil {
		t.Fatal(err)
	}
	signingSeed, err := adminbuild.ReadHexFile(p.signPath, ed25519.SeedSize)
	if err != nil {
		t.Fatal(err)
	}
	public := ed25519.NewKeyFromSeed(signingSeed).Public().(ed25519.PublicKey)
	if _, err := adminbuild.Rotate(adminbuild.RotateConfig{
		CorpusPath:     p.corpus,
		SeedPath:       p.seedPath,
		SigningKeyPath: p.signPath,
		TargetFPP:      1e-12,
		OutputDir:      filepath.Join(p.dir, "rotated"),
		PublishDir:     p.filterDir,
		PublicKey:      public,
		Now:            time.Date(2026, 11, 13, 18, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	p.failBloom = true
	p.mu.Unlock()

	got, err := client.Consult(password, p.cfg)
	if err == nil {
		t.Fatal("stale cache produced a verdict without the new filter")
	}
	if got.Verdict != "" || got.Format() != "" {
		t.Fatalf("failed refresh produced a verdict: %#v", got)
	}
	if _, statErr := os.Stat(filepath.Join(p.cfg.CacheDir, "manifest.json")); !os.IsNotExist(statErr) {
		t.Fatal("previous epoch remained cached after the refresh failed")
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

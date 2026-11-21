package oprfserver_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/andresgomez2310/OPRF---BloomFilter/internal/adminbuild"
	"github.com/andresgomez2310/OPRF---BloomFilter/internal/oprfserver"
	"github.com/cloudflare/circl/oprf"
)

type harness struct {
	URL       string
	SeedPath  string
	FilterDir string
	Epoch     string
	Server    *httptest.Server
	Dir       string
}

func setup(t *testing.T) *harness {
	t.Helper()
	dir := t.TempDir()
	seed := bytes.Repeat([]byte{0x42}, 32)
	signSeed := bytes.Repeat([]byte{0x99}, 32)
	seedPath := filepath.Join(dir, "oprf-seed.hex")
	signPath := filepath.Join(dir, "signing-seed.hex")
	if err := os.WriteFile(seedPath, []byte(hex.EncodeToString(seed)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(signPath, []byte(hex.EncodeToString(signSeed)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	corpus := filepath.Join(dir, "corpus.txt")
	if err := os.WriteFile(corpus, []byte("alpha\nbeta\n"), 0600); err != nil {
		t.Fatal(err)
	}
	filterDir := filepath.Join(dir, "filter")
	epoch := "2026-01-01T00:00:00Z"
	if _, err := adminbuild.Build(adminbuild.BuildConfig{
		CorpusPath: corpus, SeedPath: seedPath, SigningKeyPath: signPath,
		KeyEpoch: epoch, TargetFPP: 0.01, OutputDir: filterDir,
		Now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatal(err)
	}

	s, err := oprfserver.New(oprfserver.Config{
		SeedPath: seedPath, FilterDir: filterDir,
	})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return &harness{
		URL: ts.URL, SeedPath: seedPath, FilterDir: filterDir,
		Epoch: epoch, Server: ts, Dir: dir,
	}
}

func (h *harness) blindedBytes(t *testing.T, scalar uint64) []byte {
	t.Helper()
	suite := oprf.SuiteRistretto255
	blind := suite.Group().NewScalar()
	blind.SetUint64(scalar)
	client := oprf.NewClient(suite)
	_, req, err := client.DeterministicBlind(
		[][]byte{[]byte("probe")},
		[]oprf.Blind{blind},
	)
	if err != nil {
		t.Fatal(err)
	}
	b, err := req.Elements[0].MarshalBinaryCompress()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParameters(t *testing.T) {
	h := setup(t)
	resp, err := http.Get(h.URL + "/v1/parameters")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var got map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got["suite_id"] != "OPRF-ristretto255-SHA512" {
		t.Fatalf("suite %q", got["suite_id"])
	}
	if got["key_epoch"] != h.Epoch {
		t.Fatalf("epoch %q", got["key_epoch"])
	}
	if got["api_version"] != "v1" {
		t.Fatalf("api_version %q", got["api_version"])
	}
}

func TestEvaluateRoundTrip(t *testing.T) {
	h := setup(t)
	blinded := h.blindedBytes(t, 7)
	body := fmt.Sprintf(`{"blindedElement": %q, "key_epoch": %q}`,
		hex.EncodeToString(blinded), h.Epoch)
	resp, err := http.Post(h.URL+"/v1/oprf/evaluate",
		"application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d body %s", resp.StatusCode, b)
	}
	var out evalResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	evaluated, err := hex.DecodeString(out.EvaluatedElement)
	if err != nil || len(evaluated) != 32 {
		t.Fatalf("bad evaluatedElement %q", out.EvaluatedElement)
	}
}

type evalResponse struct {
	EvaluatedElement string `json:"evaluatedElement"`
}

func TestWrongEpochRejected(t *testing.T) {
	h := setup(t)
	body := `{"blindedElement": "` + hex.EncodeToString(h.blindedBytes(t, 7)) +
		`", "key_epoch": "wrong"}`
	resp, err := http.Post(h.URL+"/v1/oprf/evaluate",
		"application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d want 400", resp.StatusCode)
	}
}

func TestInvalidBlindedRejected(t *testing.T) {
	h := setup(t)
	body := fmt.Sprintf(`{"blindedElement": %q, "key_epoch": %q}`,
		"deadbeef", h.Epoch)
	resp, err := http.Post(h.URL+"/v1/oprf/evaluate",
		"application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d want 400", resp.StatusCode)
	}
}

func TestUppercaseHexRejected(t *testing.T) {
	h := setup(t)
	body := fmt.Sprintf(`{"blindedElement": %q, "key_epoch": %q}`,
		strings.ToUpper(hex.EncodeToString(h.blindedBytes(t, 7))), h.Epoch)
	resp, err := http.Post(h.URL+"/v1/oprf/evaluate",
		"application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d want 400", resp.StatusCode)
	}
}

func TestIdentityRejected(t *testing.T) {
	h := setup(t)
	suite := oprf.SuiteRistretto255
	identity := suite.Group().Identity()
	bytesID, err := identity.MarshalBinaryCompress()
	if err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf(`{"blindedElement": %q, "key_epoch": %q}`,
		hex.EncodeToString(bytesID), h.Epoch)
	resp, err := http.Post(h.URL+"/v1/oprf/evaluate",
		"application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d want 400", resp.StatusCode)
	}
}

func TestManifestETag(t *testing.T) {
	h := setup(t)
	resp, err := http.Get(h.URL + "/v1/filter/manifest")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	etag := resp.Header.Get("ETag")
	if etag == "" {
		t.Fatal("missing ETag")
	}
	req, _ := http.NewRequest("GET", h.URL+"/v1/filter/manifest", nil)
	req.Header.Set("If-None-Match", etag)
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusNotModified {
		t.Fatalf("status %d want 304", resp2.StatusCode)
	}
}

func TestBloomBytes(t *testing.T) {
	h := setup(t)
	resp, err := http.Get(h.URL + "/v1/filter/bloom")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	disk, _ := os.ReadFile(filepath.Join(h.FilterDir, "bloom.bin"))
	if !bytes.Equal(body, disk) {
		t.Fatal("bytes differ from disk")
	}
}

// La rotación cambia la época en /v1/parameters sin reiniciar el servidor.
func TestRotationPickedUpWithoutRestart(t *testing.T) {
	h := setup(t)

	// El servidor anuncia la época actual.
	resp, _ := http.Get(h.URL + "/v1/parameters")
	var got map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&got)
	resp.Body.Close()
	if got["key_epoch"] != h.Epoch {
		t.Fatalf("initial epoch %q", got["key_epoch"])
	}

	// Rotar: nueva semilla, nueva época, nuevo filtro publicado.
	signSeed, _ := adminbuild.ReadHexFile(filepath.Join(h.Dir, "signing-seed.hex"), 64)
	_ = signSeed
	pub, _, err := ed25519FromSeedFile(t, filepath.Join(h.Dir, "signing-seed.hex"))
	if err != nil {
		t.Fatal(err)
	}
	newEpoch := "2026-02-02T00:00:00Z"
	if _, err := adminbuild.Rotate(adminbuild.RotateConfig{
		CorpusPath:     filepath.Join(h.Dir, "corpus.txt"),
		SeedPath:       h.SeedPath,
		SigningKeyPath: filepath.Join(h.Dir, "signing-seed.hex"),
		TargetFPP:      0.01,
		OutputDir:      filepath.Join(h.Dir, "rot-out"),
		PublishDir:     h.FilterDir,
		PublicKey:      pub,
		Now:            time.Date(2026, 2, 2, 0, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatal(err)
	}

	// El servidor ve la época nueva y la clave nueva.
	resp, _ = http.Get(h.URL + "/v1/parameters")
	got = nil
	_ = json.NewDecoder(resp.Body).Decode(&got)
	resp.Body.Close()
	if got["key_epoch"] != newEpoch {
		t.Fatalf("epoch after rotation %q want %q", got["key_epoch"], newEpoch)
	}

	// Un elemento válido con la época nueva se acepta.
	body := fmt.Sprintf(`{"blindedElement": %q, "key_epoch": %q}`,
		hex.EncodeToString(h.blindedBytes(t, 11)), newEpoch)
	resp, _ = http.Post(h.URL+"/v1/oprf/evaluate", "application/json",
		strings.NewReader(body))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("new epoch rejected: %d %s", resp.StatusCode, b)
	}

	// La época anterior ya no se acepta.
	body = fmt.Sprintf(`{"blindedElement": %q, "key_epoch": %q}`,
		hex.EncodeToString(h.blindedBytes(t, 11)), h.Epoch)
	resp, _ = http.Post(h.URL+"/v1/oprf/evaluate", "application/json",
		strings.NewReader(body))
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("old epoch accepted: %d", resp.StatusCode)
	}
}

func ed25519FromSeedFile(t *testing.T, path string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	t.Helper()
	seed, err := adminbuild.ReadHexFile(path, ed25519.SeedSize)
	if err != nil {
		return nil, nil, err
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return priv.Public().(ed25519.PublicKey), priv, nil
}
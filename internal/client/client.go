// Package client checks a password against a published Bloom filter.
// The password, the blinding scalar and the OPRF output stay in this process.
// The server receives only a fresh blinded element and never the server key.
package client

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/andresgomez2310/OPRF---BloomFilter/internal/adminbuild"
	"github.com/andresgomez2310/OPRF---BloomFilter/internal/bloom"
	"github.com/andresgomez2310/OPRF---BloomFilter/internal/canonical"
	"github.com/andresgomez2310/OPRF---BloomFilter/internal/oprfcore"
)

const (
	VerdictCompromised = "COMPROMETIDA"
	VerdictNotFound    = "NO ENCONTRADA EN LA LISTA"
	NoteFalsePositive  = "Esta coincidencia puede ser un falso positivo."
	NotePublishedSet   = "Este resultado solo indica que la contraseña no está en el conjunto publicado."
)

var ErrEpochMismatch = errors.New("client: manifest epoch does not match the announced epoch")

// Config points at the OPRF server and the local filter cache.
// The cache holds the manifest and bloom.bin of one epoch. It does not hold skS.
type Config struct {
	ServerURL string
	CacheDir  string
	HTTP      *http.Client
}

// Outcome is a verdict for one password. Verdict is empty when the check aborts.
type Outcome struct {
	BlindedElement []byte
	Output         []byte
	Verdict        string
	Note           string
}

func (o Outcome) Format() string {
	if o.Verdict == "" {
		return ""
	}
	return o.Verdict + "\n" + o.Note + "\n"
}

// ReadPassword reads one password from r. A terminal prompt is written only
// when interactive is set. The trailing newline is removed; the rest is kept.
func ReadPassword(r io.Reader, prompt io.Writer, interactive bool) (string, error) {
	if interactive {
		if _, err := io.WriteString(prompt, "Contraseña: "); err != nil {
			return "", err
		}
	}
	reader := bufio.NewReader(r)
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	if errors.Is(err, io.EOF) && line == "" {
		return "", errors.New("client: no password was provided")
	}
	line = strings.TrimSuffix(line, "\n")
	line = strings.TrimSuffix(line, "\r")
	return line, nil
}

// Consult blinds the password, asks the server to evaluate that element, and
// looks the OPRF output up in the filter of the epoch the server is announcing.
// A cached filter from another epoch is discarded before the lookup.
func Consult(password string, cfg Config) (Outcome, error) {
	if cfg.ServerURL == "" || cfg.CacheDir == "" {
		return Outcome{}, errors.New("client: server URL and cache directory are required")
	}
	input, err := canonical.PasswordBytes(password)
	if err != nil {
		return Outcome{}, err
	}
	query, err := oprfcore.Blind(input)
	if err != nil {
		return Outcome{}, err
	}

	epoch, err := announcedEpoch(cfg)
	if err != nil {
		return Outcome{}, err
	}
	filter, err := filterForEpoch(cfg, epoch)
	if err != nil {
		return Outcome{}, err
	}

	body, err := json.Marshal(map[string]string{
		"blindedElement": hex.EncodeToString(query.BlindedElement()),
		"key_epoch":      epoch,
	})
	if err != nil {
		return Outcome{}, err
	}
	responseBody, err := httpDo(cfg, http.MethodPost, "/v1/oprf/evaluate", body)
	if err != nil {
		return Outcome{}, err
	}
	var evaluated struct {
		EvaluatedElement string `json:"evaluatedElement"`
	}
	if err := json.Unmarshal(responseBody, &evaluated); err != nil {
		return Outcome{}, err
	}
	raw, err := hex.DecodeString(evaluated.EvaluatedElement)
	if err != nil {
		return Outcome{}, fmt.Errorf("client: evaluated element: %w", err)
	}
	return Complete(query, raw, filter)
}

func announcedEpoch(cfg Config) (string, error) {
	body, err := httpDo(cfg, http.MethodGet, "/v1/parameters", nil)
	if err != nil {
		return "", err
	}
	var parameters struct {
		KeyEpoch string `json:"key_epoch"`
	}
	if err := json.Unmarshal(body, &parameters); err != nil {
		return "", err
	}
	if parameters.KeyEpoch == "" {
		return "", errors.New("client: server announced an empty epoch")
	}
	return parameters.KeyEpoch, nil
}

// filterForEpoch returns the cached filter when it belongs to epoch.
// Any other cache is removed before the new manifest and bloom.bin are downloaded.
func filterForEpoch(cfg Config, epoch string) (*bloom.Filter, error) {
	if filter, ok := cachedFilter(cfg.CacheDir, epoch); ok {
		return filter, nil
	}
	if err := discardCache(cfg.CacheDir); err != nil {
		return nil, err
	}
	manifestBytes, err := httpDo(cfg, http.MethodGet, "/v1/filter/manifest", nil)
	if err != nil {
		return nil, err
	}
	vector, err := httpDo(cfg, http.MethodGet, "/v1/filter/bloom", nil)
	if err != nil {
		return nil, err
	}
	var manifest adminbuild.Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return nil, err
	}
	if manifest.KeyEpoch != epoch {
		return nil, ErrEpochMismatch
	}
	if err := digestMatches(manifest, vector); err != nil {
		return nil, err
	}
	filter, err := bloom.FromBytes(manifest.Parameters.MBits, manifest.Parameters.KHashes, vector)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(cfg.CacheDir, 0700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(cfg.CacheDir, "bloom.bin"), vector, 0600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(cfg.CacheDir, "manifest.json"), manifestBytes, 0600); err != nil {
		_ = discardCache(cfg.CacheDir)
		return nil, err
	}
	return filter, nil
}

func cachedFilter(cacheDir, epoch string) (*bloom.Filter, bool) {
	manifestBytes, err := os.ReadFile(filepath.Join(cacheDir, "manifest.json"))
	if err != nil {
		return nil, false
	}
	vector, err := os.ReadFile(filepath.Join(cacheDir, "bloom.bin"))
	if err != nil {
		return nil, false
	}
	var manifest adminbuild.Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return nil, false
	}
	if manifest.KeyEpoch != epoch || digestMatches(manifest, vector) != nil {
		return nil, false
	}
	filter, err := bloom.FromBytes(manifest.Parameters.MBits, manifest.Parameters.KHashes, vector)
	if err != nil {
		return nil, false
	}
	return filter, true
}

func digestMatches(manifest adminbuild.Manifest, vector []byte) error {
	if manifest.HashAlgorithm != "SHA-256" {
		return fmt.Errorf("client: unsupported bloom digest %q", manifest.HashAlgorithm)
	}
	sum := sha256.Sum256(vector)
	if !strings.EqualFold(manifest.BloomBinDigest, hex.EncodeToString(sum[:])) {
		return errors.New("client: bloom.bin digest does not match the manifest")
	}
	return nil
}

func discardCache(cacheDir string) error {
	for _, name := range []string{"manifest.json", "bloom.bin"} {
		err := os.Remove(filepath.Join(cacheDir, name))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func httpDo(cfg Config, method, path string, body []byte) ([]byte, error) {
	httpClient := cfg.HTTP
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	request, err := http.NewRequest(method, strings.TrimRight(cfg.ServerURL, "/")+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(response.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("client: %s %s: %s", method, path, response.Status)
	}
	return payload, nil
}

// Complete turns an evaluated element into a verdict. An invalid element
// produces no verdict.
func Complete(query *oprfcore.Query, evaluated []byte, filter *bloom.Filter) (Outcome, error) {
	output, err := query.Finalize(evaluated)
	if err != nil {
		return Outcome{}, err
	}
	found, err := filter.Contains(output)
	if err != nil {
		return Outcome{}, err
	}
	outcome := Outcome{
		BlindedElement: query.BlindedElement(),
		Output:         output,
	}
	if found {
		outcome.Verdict = VerdictCompromised
		outcome.Note = NoteFalsePositive
		return outcome, nil
	}
	outcome.Verdict = VerdictNotFound
	outcome.Note = NotePublishedSet
	return outcome, nil
}

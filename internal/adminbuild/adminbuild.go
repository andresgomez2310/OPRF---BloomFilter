// Package adminbuild constructs signed Bloom filter artifacts without network access.
package adminbuild

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/andresgomez2310/OPRF---BloomFilter/internal/bloom"
	"github.com/andresgomez2310/OPRF---BloomFilter/internal/canonical"
	"github.com/andresgomez2310/OPRF---BloomFilter/internal/oprfcore"
)

const DefaultFPP = 0.01

type Parameters struct {
	NElements int     `json:"n_elements"`
	MBits     int     `json:"m_bits"`
	KHashes   int     `json:"k_hashes"`
	TargetFPP float64 `json:"target_fpp"`
}

type Manifest struct {
	Version        string     `json:"version"`
	KeyEpoch       string     `json:"key_epoch"`
	SuiteID        string     `json:"suite_id"`
	CreatedAt      string     `json:"created_at"`
	Parameters     Parameters `json:"parameters"`
	HashAlgorithm  string     `json:"hash_algorithm"`
	BloomBinDigest string     `json:"bloombin_digest"`
	Signature      string     `json:"signature,omitempty"`
}

type BuildConfig struct {
	CorpusPath     string
	SeedPath       string
	KeyInfo        []byte
	SigningKeyPath string
	KeyEpoch       string
	TargetFPP      float64
	OutputDir      string
	Now            time.Time
}

// ReadHexFile accepts an ASCII hex secret, with only surrounding whitespace ignored.
func ReadHexFile(path string, expectedBytes int) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(b) != expectedBytes {
		return nil, fmt.Errorf("invalid secret in %s: require %d bytes as hex", path, expectedBytes)
	}
	return b, nil
}

func Build(cfg BuildConfig) (Manifest, error) {
	var zero Manifest
	if cfg.CorpusPath == "" || cfg.SeedPath == "" || cfg.SigningKeyPath == "" || cfg.OutputDir == "" || cfg.KeyEpoch == "" {
		return zero, errors.New("corpus, seed, signing key, epoch and output directory are required")
	}
	if cfg.TargetFPP == 0 {
		cfg.TargetFPP = DefaultFPP
	}
	if cfg.Now.IsZero() {
		cfg.Now = time.Now().UTC()
	}
	seed, err := ReadHexFile(cfg.SeedPath, 32)
	if err != nil {
		return zero, fmt.Errorf("OPRF seed: %w", err)
	}
	signingSeed, err := ReadHexFile(cfg.SigningKeyPath, ed25519.SeedSize)
	if err != nil {
		return zero, fmt.Errorf("signing seed: %w", err)
	}
	if bytes.Equal(seed, signingSeed) {
		return zero, errors.New("OPRF seed and signing seed must be different")
	}
	key, err := oprfcore.DeriveServerKey(seed, cfg.KeyInfo)
	if err != nil {
		return zero, err
	}
	// Pass 1: count exactly the number of input lines. Empty lines are valid passwords.
	n, err := visitCorpus(cfg.CorpusPath, func(_ string) error { return nil })
	if err != nil {
		return zero, err
	}
	if n == 0 {
		return zero, errors.New("corpus is empty")
	}
	filter, err := bloom.New(n, cfg.TargetFPP)
	if err != nil {
		return zero, err
	}
	// Pass 2: normalize and evaluate each corpus entry before adding it to the filter.
	_, err = visitCorpus(cfg.CorpusPath, func(password string) error {
		input, err := canonical.PasswordBytes(password)
		if err != nil {
			return err
		}
		out, err := oprfcore.Evaluate(key, input)
		if err != nil {
			return err
		}
		return filter.Add(out)
	})
	if err != nil {
		return zero, err
	}
	vector := filter.Bytes()
	digest := sha256.Sum256(vector)
	m := Manifest{
		Version: "1.0.0", KeyEpoch: cfg.KeyEpoch, SuiteID: oprfcore.SuiteID,
		CreatedAt:     cfg.Now.UTC().Format(time.RFC3339),
		Parameters:    Parameters{NElements: n, MBits: filter.M(), KHashes: filter.K(), TargetFPP: cfg.TargetFPP},
		HashAlgorithm: "SHA-256", BloomBinDigest: hex.EncodeToString(digest[:]),
	}
	unsigned, err := json.Marshal(m)
	if err != nil {
		return zero, err
	}
	sig := ed25519.Sign(ed25519.NewKeyFromSeed(signingSeed), unsigned)
	m.Signature = hex.EncodeToString(sig)
	signed, err := json.Marshal(m)
	if err != nil {
		return zero, err
	}
	if err := os.MkdirAll(cfg.OutputDir, 0755); err != nil {
		return zero, err
	}
	if err := writeAtomic(filepath.Join(cfg.OutputDir, "bloom.bin"), vector, 0644); err != nil {
		return zero, err
	}
	if err := writeAtomic(filepath.Join(cfg.OutputDir, "manifest.json"), signed, 0644); err != nil {
		return zero, err
	}
	return m, nil
}

// visitCorpus reads one password per line, preserving spaces and accepting CRLF.
// It limits each line to 2 MiB, avoiding unbounded allocations for malformed corpora.
func visitCorpus(path string, fn func(string) error) (int, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	r := bufio.NewReader(file)
	count := 0
	for {
		line, readErr := r.ReadString('\n')
		if readErr != nil && readErr != io.EOF {
			return 0, readErr
		}
		if readErr == io.EOF && len(line) == 0 {
			break
		}
		if len(line) > 2*1024*1024 {
			return 0, fmt.Errorf("line %d exceeds 2 MiB", count+1)
		}
		if strings.HasSuffix(line, "\n") {
			line = strings.TrimSuffix(line, "\n")
			line = strings.TrimSuffix(line, "\r")
		}
		if err := fn(line); err != nil {
			return 0, fmt.Errorf("corpus line %d: %w", count+1, err)
		}
		count++
		if readErr == io.EOF {
			break
		}
	}
	return count, nil
}

// Verify checks the exact manifest signature and bloom bytes for an institutional public key.
func Verify(manifestBytes, bloomBytes []byte, publicKey ed25519.PublicKey) (Manifest, error) {
	var m Manifest
	if len(publicKey) != ed25519.PublicKeySize {
		return m, errors.New("invalid institutional public key")
	}
	if err := json.Unmarshal(manifestBytes, &m); err != nil {
		return m, err
	}
	sig, err := hex.DecodeString(m.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return m, errors.New("invalid signature encoding")
	}
	m.Signature = ""
	unsigned, err := json.Marshal(m)
	if err != nil {
		return m, err
	}
	if !ed25519.Verify(publicKey, unsigned, sig) {
		return m, errors.New("invalid manifest signature")
	}
	sum := sha256.Sum256(bloomBytes)
	if hex.EncodeToString(sum[:]) != m.BloomBinDigest {
		return m, errors.New("bloom SHA-256 mismatch")
	}
	if _, err := bloom.FromBytes(m.Parameters.MBits, m.Parameters.KHashes, bloomBytes); err != nil {
		return m, err
	}
	m.Signature = hex.EncodeToString(sig)
	return m, nil
}

// Publish validates artifacts and copies them into the server's shared filesystem directory.
// The server remains responsible for exposing GET /v1/filter/*.
func Publish(sourceDir, destinationDir string, publicKey ed25519.PublicKey) error {
	if sourceDir == "" || destinationDir == "" {
		return errors.New("source and destination required")
	}
	manifestData, err := os.ReadFile(filepath.Join(sourceDir, "manifest.json"))
	if err != nil {
		return err
	}
	vector, err := os.ReadFile(filepath.Join(sourceDir, "bloom.bin"))
	if err != nil {
		return err
	}
	if _, err := Verify(manifestData, vector, publicKey); err != nil {
		return err
	}
	if err := os.MkdirAll(destinationDir, 0755); err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(destinationDir, "bloom.bin"), vector, 0644); err != nil {
		return err
	}
	return writeAtomic(filepath.Join(destinationDir, "manifest.json"), manifestData, 0644)
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".tmp-filter-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	// Windows requires removing a preexisting destination before rename.
	if err := os.Rename(f.Name(), path); err != nil {
		if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return err
		}
		return os.Rename(f.Name(), path)
	}
	return nil
}

package metrics

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"time"

	"github.com/andresgomez2310/OPRF---BloomFilter/internal/adminbuild"
	"github.com/andresgomez2310/OPRF---BloomFilter/internal/bloom"
	"github.com/andresgomez2310/OPRF---BloomFilter/internal/client"
	"github.com/andresgomez2310/OPRF---BloomFilter/internal/oprfserver"
)

type RotationConfig struct {
	Entries           int
	TargetFPP         float64
	CorpusPath        string
	SeedPath          string
	SigningKeyPath    string
	FilterDir         string
	RotationOutputDir string
	CacheDir          string
	Password          string
}

type RotationResult struct {
	Duration             time.Duration
	OldEpoch             string
	NewEpoch             string
	NewFilterReady       bool
	OldFilterRejected    bool
	OldFilterMatchedNew  bool
	NewVerdict           string
	PollAttempts         int
}

func MeasureRotation(cfg RotationConfig) (RotationResult, error) {
	if cfg.Entries <= 0 {
		return RotationResult{}, fmt.Errorf("entries must be greater than zero")
	}

	if err := generateMetricCorpus(cfg.CorpusPath, cfg.Entries); err != nil {
		return RotationResult{}, err
	}

	const oldEpoch = "metrics-rotation-old"

	initialManifest, err := adminbuild.Build(adminbuild.BuildConfig{
		CorpusPath:     cfg.CorpusPath,
		SeedPath:       cfg.SeedPath,
		SigningKeyPath: cfg.SigningKeyPath,
		KeyEpoch:       oldEpoch,
		TargetFPP:      cfg.TargetFPP,
		OutputDir:      cfg.FilterDir,
	})
	if err != nil {
		return RotationResult{}, err
	}

	oldBloomBytes, err := os.ReadFile(
		filepath.Join(cfg.FilterDir, "bloom.bin"),
	)
	if err != nil {
		return RotationResult{}, err
	}

	oldFilter, err := bloom.FromBytes(
		initialManifest.Parameters.MBits,
		initialManifest.Parameters.KHashes,
		oldBloomBytes,
	)
	if err != nil {
		return RotationResult{}, err
	}

	signingSeed, err := adminbuild.ReadHexFile(
		cfg.SigningKeyPath,
		ed25519.SeedSize,
	)
	if err != nil {
		return RotationResult{}, err
	}

	publicKey := ed25519.NewKeyFromSeed(signingSeed).
		Public().(ed25519.PublicKey)

	server, err := oprfserver.New(oprfserver.Config{
		SeedPath:  cfg.SeedPath,
		FilterDir: cfg.FilterDir,
	})
	if err != nil {
		return RotationResult{}, err
	}

	httpServer := httptest.NewServer(server.Handler())
	defer httpServer.Close()

	if err := os.RemoveAll(cfg.CacheDir); err != nil {
		return RotationResult{}, err
	}

	clientConfig := client.Config{
		ServerURL:         httpServer.URL,
		CacheDir:          cfg.CacheDir,
		TrustedSigningKey: publicKey,
	}

	// Comprobamos que antes de rotar la contraseña pertenece al filtro viejo.
	before, err := client.Consult(cfg.Password, clientConfig)
	if err != nil {
		return RotationResult{}, err
	}

	if before.Verdict != client.VerdictCompromised {
		return RotationResult{}, fmt.Errorf(
			"password was not COMPROMETIDA before rotation",
		)
	}

	type rotationResponse struct {
		manifest adminbuild.Manifest
		err      error
	}

	done := make(chan rotationResponse, 1)

	start := time.Now()

	go func() {
		manifest, err := adminbuild.Rotate(adminbuild.RotateConfig{
			CorpusPath:     cfg.CorpusPath,
			SeedPath:       cfg.SeedPath,
			SigningKeyPath: cfg.SigningKeyPath,
			TargetFPP:      cfg.TargetFPP,
			OutputDir:      cfg.RotationOutputDir,
			PublishDir:     cfg.FilterDir,
			PublicKey:      publicKey,
			Now:            time.Now().UTC(),
		})

		done <- rotationResponse{
			manifest: manifest,
			err:      err,
		}
	}()

	var (
		readyOutcome client.Outcome
		readyEpoch   string
		duration     time.Duration
		attempts     int
	)

	deadline := time.Now().Add(2 * time.Minute)

	for time.Now().Before(deadline) {
		attempts++

		outcome, consultErr := client.Consult(
			cfg.Password,
			clientConfig,
		)

		if consultErr == nil &&
			outcome.Verdict == client.VerdictCompromised {

			cachedManifestBytes, readErr := os.ReadFile(
				filepath.Join(cfg.CacheDir, "manifest.json"),
			)

			if readErr == nil {
				var cachedManifest adminbuild.Manifest

				if json.Unmarshal(
					cachedManifestBytes,
					&cachedManifest,
				) == nil &&
					cachedManifest.KeyEpoch != oldEpoch {

					readyOutcome = outcome
					readyEpoch = cachedManifest.KeyEpoch
					duration = time.Since(start)
					break
				}
			}
		}

		time.Sleep(5 * time.Millisecond)
	}

	rotation := <-done

	if rotation.err != nil {
		return RotationResult{}, rotation.err
	}

	if readyEpoch == "" {
		return RotationResult{}, fmt.Errorf(
			"new filter did not become usable before timeout",
		)
	}

	if readyEpoch != rotation.manifest.KeyEpoch {
		return RotationResult{}, fmt.Errorf(
			"client epoch %q differs from rotated epoch %q",
			readyEpoch,
			rotation.manifest.KeyEpoch,
		)
	}

	// La salida OPRF nueva no debe producir una coincidencia válida
	// contra el Bloom Filter de la época anterior.
	oldMatchedNewOutput, err := oldFilter.Contains(readyOutcome.Output)
	if err != nil {
		return RotationResult{}, err
	}

	return RotationResult{
		Duration:            duration,
		OldEpoch:            oldEpoch,
		NewEpoch:            readyEpoch,
		NewFilterReady:      true,
		OldFilterRejected:   !oldMatchedNewOutput,
		OldFilterMatchedNew: oldMatchedNewOutput,
		NewVerdict:          readyOutcome.Verdict,
		PollAttempts:        attempts,
	}, nil
}
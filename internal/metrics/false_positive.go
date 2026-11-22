package metrics

import (
	"crypto/ed25519"
	"fmt"
	"math/rand"
	"net/http/httptest"
	"os"
	"path/filepath"

	"github.com/andresgomez2310/OPRF---BloomFilter/internal/adminbuild"
	"github.com/andresgomez2310/OPRF---BloomFilter/internal/bloom"
	"github.com/andresgomez2310/OPRF---BloomFilter/internal/client"
	"github.com/andresgomez2310/OPRF---BloomFilter/internal/oprfserver"
)

type FalsePositiveConfig struct {
	Entries         int
	TargetFPP       float64
	AbsentQueries   int
	GeneratorSeed   int64
	CorpusPath      string
	SeedPath        string
	SigningKeyPath  string
	OutputDir       string
	CacheDir        string
}

type FalsePositiveResult struct {
	Entries            int
	TargetFPP          float64
	MBits              int
	KHashes            int
	AbsentQueries      int
	FalsePositives     int
	EmpiricalFPP       float64
	TheoreticalFPP     float64
	PresentChecks      int
	PresentCompromised int
}

// MeasureFalsePositives construye un filtro real, levanta el servidor OPRF y consulta varias contraseñas ausentes para medir la tasa de falsos positivos.
func MeasureFalsePositives(cfg FalsePositiveConfig) (FalsePositiveResult, error) {
	if cfg.Entries <= 0 {
		return FalsePositiveResult{}, fmt.Errorf("entries must be greater than zero")
	}
	if cfg.AbsentQueries < 10000 {
		return FalsePositiveResult{}, fmt.Errorf("ticket 11 requires at least 10000 absent queries")
	}

	if err := generateMetricCorpus(cfg.CorpusPath, cfg.Entries); err != nil {
		return FalsePositiveResult{}, err
	}

	manifest, err := adminbuild.Build(adminbuild.BuildConfig{
		CorpusPath:     cfg.CorpusPath,
		SeedPath:       cfg.SeedPath,
		SigningKeyPath: cfg.SigningKeyPath,
		KeyEpoch:       fmt.Sprintf("metrics-fp-%d-%g", cfg.Entries, cfg.TargetFPP),
		TargetFPP:      cfg.TargetFPP,
		OutputDir:      cfg.OutputDir,
	})
	if err != nil {
		return FalsePositiveResult{}, err
	}

	vector, err := os.ReadFile(filepath.Join(cfg.OutputDir, "bloom.bin"))
	if err != nil {
		return FalsePositiveResult{}, err
	}

	filter, err := bloom.FromBytes(
		manifest.Parameters.MBits,
		manifest.Parameters.KHashes,
		vector,
	)
	if err != nil {
		return FalsePositiveResult{}, err
	}

	theoreticalFPP, err := filter.FalsePositiveRate(cfg.Entries)
	if err != nil {
		return FalsePositiveResult{}, err
	}

	signingSeed, err := adminbuild.ReadHexFile(
		cfg.SigningKeyPath,
		ed25519.SeedSize,
	)
	if err != nil {
		return FalsePositiveResult{}, err
	}

	publicKey := ed25519.NewKeyFromSeed(signingSeed).
		Public().(ed25519.PublicKey)

	server, err := oprfserver.New(oprfserver.Config{
		SeedPath:  cfg.SeedPath,
		FilterDir: cfg.OutputDir,
	})
	if err != nil {
		return FalsePositiveResult{}, err
	}

	httpServer := httptest.NewServer(server.Handler())
	defer httpServer.Close()

	// Comenzamos con una caché limpia para que la ejecución sea independiente.
	if err := os.RemoveAll(cfg.CacheDir); err != nil {
		return FalsePositiveResult{}, err
	}

	clientConfig := client.Config{
		ServerURL:         httpServer.URL,
		CacheDir:          cfg.CacheDir,
		TrustedSigningKey: publicKey,
	}

	result := FalsePositiveResult{
		Entries:        cfg.Entries,
		TargetFPP:      cfg.TargetFPP,
		MBits:          manifest.Parameters.MBits,
		KHashes:        manifest.Parameters.KHashes,
		AbsentQueries:  cfg.AbsentQueries,
		TheoreticalFPP: theoreticalFPP,
	}

	// Comprobamos varias contraseñas que sí pertenecen al corpus.
	presentIndexes := []int{
		0,
		cfg.Entries / 4,
		cfg.Entries / 2,
		(3 * cfg.Entries) / 4,
		cfg.Entries - 1,
	}

	for _, index := range presentIndexes {
		password := fmt.Sprintf("metric-password-%06d", index)

		outcome, err := client.Consult(password, clientConfig)
		if err != nil {
			return FalsePositiveResult{}, err
		}

		result.PresentChecks++

		if outcome.Verdict == client.VerdictCompromised {
			result.PresentCompromised++
		}
	}

	// Generador determinista: la misma seed produce las mismas contraseñas ausentes en cada ejecución.
	rng := rand.New(rand.NewSource(cfg.GeneratorSeed))

	for i := 0; i < cfg.AbsentQueries; i++ {
		password := fmt.Sprintf(
			"metric-absent-%016x-%016x",
			rng.Uint64(),
			rng.Uint64(),
		)

		outcome, err := client.Consult(password, clientConfig)
		if err != nil {
			return FalsePositiveResult{}, err
		}

		if outcome.Verdict == client.VerdictCompromised {
			result.FalsePositives++
		}
	}

	result.EmpiricalFPP =
		float64(result.FalsePositives) / float64(result.AbsentQueries)

	return result, nil
}

func generateMetricCorpus(path string, entries int) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}

	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	for i := 0; i < entries; i++ {
		if _, err := fmt.Fprintf(
			file,
			"metric-password-%06d\n",
			i,
		); err != nil {
			return err
		}
	}

	return nil
}
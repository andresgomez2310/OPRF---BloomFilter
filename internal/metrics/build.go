package metrics

import (
	"os"
	"path/filepath"
	"time"

	"github.com/andresgomez2310/OPRF---BloomFilter/internal/adminbuild"
)

// BuildResult contiene los resultados de una construcción del Bloom Filter.
type BuildResult struct {
	Entries         int
	BuildDuration   time.Duration
	BloomBytes      int64
	MBits           int
	KHashes         int
}

// BuildConfig contiene las rutas y parámetros necesarios para ejecutar
type BuildConfig struct {
	CorpusPath     string
	SeedPath       string
	SigningKeyPath string
	KeyEpoch       string
	TargetFPP      float64
	OutputDir      string
}

// MeasureBuild ejecuta el mismo proceso real de build-filter
func MeasureBuild(cfg BuildConfig) (BuildResult, error) {
	start := time.Now()

	manifest, err := adminbuild.Build(adminbuild.BuildConfig{
		CorpusPath:     cfg.CorpusPath,
		SeedPath:       cfg.SeedPath,
		SigningKeyPath: cfg.SigningKeyPath,
		KeyEpoch:       cfg.KeyEpoch,
		TargetFPP:      cfg.TargetFPP,
		OutputDir:      cfg.OutputDir,
	})

	duration := time.Since(start)

	if err != nil {
		return BuildResult{}, err
	}

	info, err := os.Stat(filepath.Join(cfg.OutputDir, "bloom.bin"))
	if err != nil {
		return BuildResult{}, err
	}

	return BuildResult{
		Entries:       manifest.Parameters.NElements,
		BuildDuration: duration,
		BloomBytes:    info.Size(),
		MBits:         manifest.Parameters.MBits,
		KHashes:       manifest.Parameters.KHashes,
	}, nil
}
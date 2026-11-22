package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	projectmetrics "github.com/andresgomez2310/OPRF---BloomFilter/internal/metrics"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "latency":
			if err := runLatencyOnly(); err != nil {
				fmt.Fprintln(os.Stderr, "metrics:", err)
				os.Exit(1)
			}
			return

		case "rotation":
			if err := runRotationOnly(); err != nil {
				fmt.Fprintln(os.Stderr, "metrics:", err)
				os.Exit(1)
			}
			return
		}
	}

	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "metrics:", err)
		os.Exit(1)
	}
}
func run() error {
	workDir := filepath.Join("metrics", "work")

	if err := os.MkdirAll(workDir, 0755); err != nil {
		return err
	}

	seedPath := filepath.Join(workDir, "oprf-seed.hex")
	signingSeedPath := filepath.Join(workDir, "signing-seed.hex")

	// Semillas fijas para poder repetir exactamente la medición.
	if err := os.WriteFile(
		seedPath,
		[]byte(strings.Repeat("11", 32)),
		0600,
	); err != nil {
		return err
	}

	if err := os.WriteFile(
		signingSeedPath,
		[]byte(strings.Repeat("22", 32)),
		0600,
	); err != nil {
		return err
	}

	sizes := []int{
		50000,
		100000,
		200000,
	}

	fmt.Println("TICKET 11 - BUILD FILTER METRICS")
	fmt.Println()

	for _, n := range sizes {
		corpusPath := filepath.Join(
			workDir,
			fmt.Sprintf("corpus-%d.txt", n),
		)

		if err := generateCorpus(corpusPath, n); err != nil {
			return err
		}

		outputDir := filepath.Join(
			workDir,
			fmt.Sprintf("build-%d", n),
		)

		result, err := projectmetrics.MeasureBuild(projectmetrics.BuildConfig{
			CorpusPath:     corpusPath,
			SeedPath:       seedPath,
			SigningKeyPath: signingSeedPath,
			KeyEpoch:       fmt.Sprintf("metrics-build-%d", n),
			TargetFPP:      0.01,
			OutputDir:      outputDir,
		})
		if err != nil {
			return err
		}

		fmt.Printf(
			"n=%d | build=%v | bloom.bin=%d bytes | m=%d | k=%d\n",
			result.Entries,
			result.BuildDuration,
			result.BloomBytes,
			result.MBits,
			result.KHashes,
		)
	}
		fmt.Println()
	fmt.Println("TICKET 11 - FALSE POSITIVE METRICS")
	fmt.Println()

	fpConfigurations := []struct {
		entries   int
		targetFPP float64
	}{
		{100000, 0.01},
		{100000, 0.001},
		{1000000, 0.01},
	}

	for _, configuration := range fpConfigurations {
		name := fmt.Sprintf(
			"%d-%.3g",
			configuration.entries,
			configuration.targetFPP,
		)

		result, err := projectmetrics.MeasureFalsePositives(
			projectmetrics.FalsePositiveConfig{
				Entries:        configuration.entries,
				TargetFPP:      configuration.targetFPP,
				AbsentQueries:  10000,
				GeneratorSeed:  20261121,
				CorpusPath: filepath.Join(
					workDir,
					"false-positive-"+name+"-corpus.txt",
				),
				SeedPath:       seedPath,
				SigningKeyPath: signingSeedPath,
				OutputDir: filepath.Join(
					workDir,
					"false-positive-"+name,
				),
				CacheDir: filepath.Join(
					workDir,
					"false-positive-"+name+"-cache",
				),
			},
		)
		if err != nil {
			return err
		}

		fmt.Printf(
			"n=%d | target=%.6f | m=%d | k=%d | absent=%d | false positives=%d | empirical=%.6f | theoretical=%.6f | present=%d/%d COMPROMETIDA\n",
			result.Entries,
			result.TargetFPP,
			result.MBits,
			result.KHashes,
			result.AbsentQueries,
			result.FalsePositives,
			result.EmpiricalFPP,
			result.TheoreticalFPP,
			result.PresentCompromised,
			result.PresentChecks,
		)
	}

	return nil
}

func generateCorpus(path string, entries int) error {
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

func runLatencyOnly() error {
	workDir := filepath.Join("metrics", "work")

	if err := os.MkdirAll(workDir, 0755); err != nil {
		return err
	}

	seedPath := filepath.Join(workDir, "oprf-seed.hex")
	signingSeedPath := filepath.Join(workDir, "signing-seed.hex")

	if err := os.WriteFile(
		seedPath,
		[]byte(strings.Repeat("11", 32)),
		0600,
	); err != nil {
		return err
	}

	if err := os.WriteFile(
		signingSeedPath,
		[]byte(strings.Repeat("22", 32)),
		0600,
	); err != nil {
		return err
	}

	// Corpus determinista para la medición de latencia.
	const entries = 100000

	corpusPath := filepath.Join(workDir, "latency-corpus.txt")
	filterDir := filepath.Join(workDir, "latency-filter")

	if err := generateCorpus(corpusPath, entries); err != nil {
		return err
	}

	// Construimos un filtro real antes de medir.
	// Este tiempo NO forma parte de la latencia de consulta.
	_, err := projectmetrics.MeasureBuild(projectmetrics.BuildConfig{
		CorpusPath:     corpusPath,
		SeedPath:       seedPath,
		SigningKeyPath: signingSeedPath,
		KeyEpoch:       "metrics-latency",
		TargetFPP:      0.01,
		OutputDir:      filterDir,
	})
	if err != nil {
		return err
	}

	results, err := projectmetrics.MeasureLatency(
		projectmetrics.LatencyConfig{
			SeedPath:       seedPath,
			SigningKeyPath: signingSeedPath,
			FilterDir:      filterDir,
			CacheDir:       filepath.Join(workDir, "latency-cache"),
			Samples:        30,
			Password:       "metric-password-000000",
		},
	)
	if err != nil {
		return err
	}

	fmt.Println("TICKET 11 - LATENCY METRICS")
	fmt.Println()

	for _, result := range results {
		fmt.Printf(
			"mode=%s | samples=%d | total=%.3f ms | blind=%.3f ms | network=%.3f ms | evaluation=%.3f ms | unblind=%.3f ms | bloom=%.3f ms\n",
			result.CacheMode,
			result.Samples,
			float64(result.AverageTotalNS)/1e6,
			float64(result.AverageBlindNS)/1e6,
			float64(result.AverageNetworkNS)/1e6,
			float64(result.AverageEvalNS)/1e6,
			float64(result.AverageUnblindNS)/1e6,
			float64(result.AverageLookupNS)/1e6,
		)
	}

	return nil
}

func runRotationOnly() error {
	workDir := filepath.Join("metrics", "work")

	if err := os.MkdirAll(workDir, 0755); err != nil {
		return err
	}

	seedPath := filepath.Join(workDir, "oprf-seed.hex")
	signingSeedPath := filepath.Join(workDir, "signing-seed.hex")

	if err := os.WriteFile(
		seedPath,
		[]byte(strings.Repeat("11", 32)),
		0600,
	); err != nil {
		return err
	}

	if err := os.WriteFile(
		signingSeedPath,
		[]byte(strings.Repeat("22", 32)),
		0600,
	); err != nil {
		return err
	}

	result, err := projectmetrics.MeasureRotation(
		projectmetrics.RotationConfig{
			Entries:           10000,
			TargetFPP:         0.01,
			CorpusPath:        filepath.Join(workDir, "rotation-corpus.txt"),
			SeedPath:          seedPath,
			SigningKeyPath:    signingSeedPath,
			FilterDir:         filepath.Join(workDir, "rotation-filter"),
			RotationOutputDir: filepath.Join(workDir, "rotation-new"),
			CacheDir:          filepath.Join(workDir, "rotation-cache"),
			Password:          "metric-password-000000",
		},
	)
	if err != nil {
		return err
	}

	fmt.Println("TICKET 11 - ROTATION METRICS")
	fmt.Println()

	fmt.Printf(
		"rotation=%v | old_epoch=%s | new_epoch=%s | ready=%t | old_filter_rejected=%t | verdict=%s | attempts=%d\n",
		result.Duration,
		result.OldEpoch,
		result.NewEpoch,
		result.NewFilterReady,
		result.OldFilterRejected,
		result.NewVerdict,
		result.PollAttempts,
	)

	return nil
}
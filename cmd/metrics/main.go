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

	// Cada ejecución completa empieza desde un entorno limpio.
	if err := os.RemoveAll(workDir); err != nil {
		return err
	}

	if err := os.MkdirAll(workDir, 0755); err != nil {
		return err
	}

	const (
		generatorSeed   int64 = 20261121
		absentQueries         = 10000
		latencySamples        = 30
		rotationEntries       = 10000
	)

	oprfSeedHex := strings.Repeat("11", 32)
	signingSeedHex := strings.Repeat("22", 32)

	seedPath := filepath.Join(workDir, "oprf-seed.hex")
	signingSeedPath := filepath.Join(workDir, "signing-seed.hex")

	if err := os.WriteFile(
		seedPath,
		[]byte(oprfSeedHex),
		0600,
	); err != nil {
		return err
	}

	if err := os.WriteFile(
		signingSeedPath,
		[]byte(signingSeedHex),
		0600,
	); err != nil {
		return err
	}

	// ============================================================
	// 1. BUILD FILTER METRICS
	// ============================================================

	fmt.Println("TICKET 11 - BUILD FILTER METRICS")
	fmt.Println()

	buildSizes := []int{
		50000,
		100000,
		200000,
	}

	buildResults := make([]projectmetrics.BuildResult, 0, len(buildSizes))

	for _, entries := range buildSizes {
		corpusPath := filepath.Join(
			workDir,
			fmt.Sprintf("corpus-%d.txt", entries),
		)

		outputDir := filepath.Join(
			workDir,
			fmt.Sprintf("build-%d", entries),
		)

		if err := generateCorpus(corpusPath, entries); err != nil {
			return err
		}

		result, err := projectmetrics.MeasureBuild(
			projectmetrics.BuildConfig{
				CorpusPath:     corpusPath,
				SeedPath:       seedPath,
				SigningKeyPath: signingSeedPath,
				KeyEpoch:       fmt.Sprintf("metrics-build-%d", entries),
				TargetFPP:      0.01,
				OutputDir:      outputDir,
			},
		)
		if err != nil {
			return err
		}

		buildResults = append(buildResults, result)

		fmt.Printf(
			"n=%d | build=%v | bloom.bin=%d bytes | m=%d | k=%d\n",
			result.Entries,
			result.BuildDuration,
			result.BloomBytes,
			result.MBits,
			result.KHashes,
		)
	}

	// ============================================================
	// 2. FALSE POSITIVE METRICS
	// ============================================================

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

	falsePositiveResults := make(
		[]projectmetrics.FalsePositiveResult,
		0,
		len(fpConfigurations),
	)

	for _, configuration := range fpConfigurations {
		name := fmt.Sprintf(
			"%d-%.3g",
			configuration.entries,
			configuration.targetFPP,
		)

		result, err := projectmetrics.MeasureFalsePositives(
			projectmetrics.FalsePositiveConfig{
				Entries:       configuration.entries,
				TargetFPP:     configuration.targetFPP,
				AbsentQueries: absentQueries,
				GeneratorSeed: generatorSeed,

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

		falsePositiveResults = append(
			falsePositiveResults,
			result,
		)

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

	// ============================================================
	// 3. LATENCY METRICS
	// ============================================================

	fmt.Println()
	fmt.Println("TICKET 11 - LATENCY METRICS")
	fmt.Println()

	latencyCorpusPath := filepath.Join(
		workDir,
		"latency-corpus.txt",
	)

	latencyFilterDir := filepath.Join(
		workDir,
		"latency-filter",
	)

	if err := generateCorpus(
		latencyCorpusPath,
		100000,
	); err != nil {
		return err
	}

	// Preparamos el filtro. Este build no forma parte de la latencia.
	_, err := projectmetrics.MeasureBuild(
		projectmetrics.BuildConfig{
			CorpusPath:     latencyCorpusPath,
			SeedPath:       seedPath,
			SigningKeyPath: signingSeedPath,
			KeyEpoch:       "metrics-latency",
			TargetFPP:      0.01,
			OutputDir:      latencyFilterDir,
		},
	)
	if err != nil {
		return err
	}

	latencyResults, err := projectmetrics.MeasureLatency(
		projectmetrics.LatencyConfig{
			SeedPath:       seedPath,
			SigningKeyPath: signingSeedPath,
			FilterDir:      latencyFilterDir,
			CacheDir: filepath.Join(
				workDir,
				"latency-cache",
			),
			Samples:  latencySamples,
			Password: "metric-password-000000",
		},
	)
	if err != nil {
		return err
	}

	for _, result := range latencyResults {
		fmt.Printf(
			"mode=%s | samples=%d | total=%.3f ms | blind=%.3f ms | network=%.3f ms | evaluation=%.3f ms | unblind=%.3f ms | bloom=%.3f us\n",
			result.CacheMode,
			result.Samples,
			float64(result.AverageTotalNS)/1e6,
			float64(result.AverageBlindNS)/1e6,
			float64(result.AverageNetworkNS)/1e6,
			float64(result.AverageEvalNS)/1e6,
			float64(result.AverageUnblindNS)/1e6,
			float64(result.AverageLookupNS)/1e3,
		)
	}

	// ============================================================
	// 4. ROTATION METRICS
	// ============================================================

	fmt.Println()
	fmt.Println("TICKET 11 - ROTATION METRICS")
	fmt.Println()

	rotationResult, err := projectmetrics.MeasureRotation(
		projectmetrics.RotationConfig{
			Entries:   rotationEntries,
			TargetFPP: 0.01,
			CorpusPath: filepath.Join(
				workDir,
				"rotation-corpus.txt",
			),
			SeedPath:       seedPath,
			SigningKeyPath: signingSeedPath,
			FilterDir: filepath.Join(
				workDir,
				"rotation-filter",
			),
			RotationOutputDir: filepath.Join(
				workDir,
				"rotation-new",
			),
			CacheDir: filepath.Join(
				workDir,
				"rotation-cache",
			),
			Password: "metric-password-000000",
		},
	)
	if err != nil {
		return err
	}

	fmt.Printf(
		"rotation=%v | old_epoch=%s | new_epoch=%s | ready=%t | old_filter_rejected=%t | verdict=%s | attempts=%d\n",
		rotationResult.Duration,
		rotationResult.OldEpoch,
		rotationResult.NewEpoch,
		rotationResult.NewFilterReady,
		rotationResult.OldFilterRejected,
		rotationResult.NewVerdict,
		rotationResult.PollAttempts,
	)

	// ============================================================
	// 5. REPORT
	// ============================================================

	reportData := projectmetrics.ReportData{
		Inputs: projectmetrics.ReportInputs{
			GeneratorSeed:       generatorSeed,
			AbsentQueries:       absentQueries,
			LatencySamples:      latencySamples,
			RotationEntries:     rotationEntries,
			OPRFSeedDescription: oprfSeedHex,
			SigningSeedDesc:     signingSeedHex,
		},
		Builds:         buildResults,
		FalsePositives: falsePositiveResults,
		Latency:        latencyResults,
		Rotation:       rotationResult,
	}

	if err := projectmetrics.WriteReport(
		"metrics",
		reportData,
	); err != nil {
		return err
	}

	fmt.Println()
	fmt.Println("REPORT GENERATED")
	fmt.Println("metrics/report.md")
	fmt.Println("metrics/results.json")

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
			"mode=%s | samples=%d | total=%.3f ms | blind=%.3f us | network=%.3f ms | evaluation=%.3f us | unblind=%.3f us | bloom=%d ns | calls: http=%d eval=%d blind=%d unblind=%d bloom=%d\n",
			result.CacheMode,
			result.Samples,
			float64(result.AverageTotalNS)/1e6,
			float64(result.AverageBlindNS)/1e3,
			float64(result.AverageNetworkNS)/1e6,
			float64(result.AverageEvalNS)/1e3,
			float64(result.AverageUnblindNS)/1e3,
			result.AverageLookupNS,
			result.HTTPCount,
			result.EvalCount,
			result.BlindCount,
			result.UnblindCount,
			result.LookupCount,
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

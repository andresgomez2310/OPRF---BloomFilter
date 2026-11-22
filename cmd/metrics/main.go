package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	projectmetrics "github.com/andresgomez2310/OPRF---BloomFilter/internal/metrics"
)

func main() {
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
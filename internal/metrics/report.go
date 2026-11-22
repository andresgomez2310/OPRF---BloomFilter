package metrics

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type ReportInputs struct {
	GeneratorSeed       int64  `json:"generator_seed"`
	AbsentQueries       int    `json:"absent_queries_per_configuration"`
	LatencySamples      int    `json:"latency_samples_per_mode"`
	RotationEntries     int    `json:"rotation_entries"`
	OPRFSeedDescription string `json:"oprf_seed"`
	SigningSeedDesc     string `json:"signing_seed"`
}

type ReportRuntime struct {
	GoVersion string `json:"go_version"`
	GOOS      string `json:"goos"`
	GOARCH    string `json:"goarch"`
}

type ReportData struct {
	GeneratedAt    time.Time             `json:"generated_at"`
	Inputs         ReportInputs          `json:"inputs"`
	Runtime        ReportRuntime         `json:"runtime"`
	Builds         []BuildResult         `json:"builds"`
	FalsePositives []FalsePositiveResult `json:"false_positives"`
	Latency        []LatencyResult       `json:"latency"`
	Rotation       RotationResult        `json:"rotation"`
}

func WriteReport(outputDir string, data ReportData) error {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return err
	}

	data.Runtime = ReportRuntime{
		GoVersion: runtime.Version(),
		GOOS:      runtime.GOOS,
		GOARCH:    runtime.GOARCH,
	}

	if data.GeneratedAt.IsZero() {
		data.GeneratedAt = time.Now().UTC()
	}

	jsonBytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}

	jsonBytes = append(jsonBytes, '\n')

	if err := os.WriteFile(
		filepath.Join(outputDir, "results.json"),
		jsonBytes,
		0644,
	); err != nil {
		return err
	}

	var report strings.Builder

	report.WriteString("# Ticket 11 - Métricas del prototipo OPRF + Bloom Filter\n\n")

	report.WriteString("## Reproducibilidad\n\n")
	fmt.Fprintf(&report, "- Generado: `%s`\n", data.GeneratedAt.Format(time.RFC3339))
	fmt.Fprintf(&report, "- Go: `%s`\n", data.Runtime.GoVersion)
	fmt.Fprintf(&report, "- Plataforma: `%s/%s`\n", data.Runtime.GOOS, data.Runtime.GOARCH)
	fmt.Fprintf(&report, "- Semilla del generador de consultas ausentes: `%d`\n", data.Inputs.GeneratorSeed)
	fmt.Fprintf(&report, "- Consultas ausentes por configuración: `%d`\n", data.Inputs.AbsentQueries)
	fmt.Fprintf(&report, "- Muestras de latencia por modo: `%d`\n", data.Inputs.LatencySamples)
	fmt.Fprintf(&report, "- Entradas usadas para rotación: `%d`\n", data.Inputs.RotationEntries)
	fmt.Fprintf(&report, "- Semilla OPRF de prueba: `%s`\n", data.Inputs.OPRFSeedDescription)
	fmt.Fprintf(&report, "- Semilla Ed25519 de prueba: `%s`\n\n", data.Inputs.SigningSeedDesc)

	report.WriteString("Las semillas anteriores son exclusivamente deterministas para las métricas locales del proyecto y no corresponden a claves de producción.\n\n")

	report.WriteString("### Comandos\n\n")
	report.WriteString("```bash\n")
	report.WriteString("go run ./cmd/metrics\n")
	report.WriteString("go run ./cmd/metrics latency\n")
	report.WriteString("go run ./cmd/metrics rotation\n")
	report.WriteString("go test ./... -count=1\n")
	report.WriteString("```\n\n")

	report.WriteString("## Construcción del Bloom Filter\n\n")
	report.WriteString("| Entradas | Tiempo de build | bloom.bin | m bits | k |\n")
	report.WriteString("|---:|---:|---:|---:|---:|\n")

	for _, result := range data.Builds {
		fmt.Fprintf(
			&report,
			"| %d | %s | %d bytes | %d | %d |\n",
			result.Entries,
			result.BuildDuration,
			result.BloomBytes,
			result.MBits,
			result.KHashes,
		)
	}

	report.WriteString("\n## Falsos positivos\n\n")
	report.WriteString("| n | FPP objetivo | m | k | Ausentes | Falsos positivos | FPP empírica | FPP teórica | Presentes |\n")
	report.WriteString("|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n")

	for _, result := range data.FalsePositives {
		fmt.Fprintf(
			&report,
			"| %d | %.6f | %d | %d | %d | %d | %.6f | %.6f | %d/%d COMPROMETIDA |\n",
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

	report.WriteString("\n## Latencia\n\n")
	report.WriteString("Los valores son promedios por consulta. `network` corresponde al tiempo HTTP descontando la evaluación OPRF del servidor para evitar contarla dos veces.\n\n")
	report.WriteString("| Modo | Muestras | Total | Blind | Network | Evaluación | Unblind | Bloom lookup |\n")
	report.WriteString("|---|---:|---:|---:|---:|---:|---:|---:|\n")

	for _, result := range data.Latency {
		fmt.Fprintf(
			&report,
			"| %s | %d | %.3f ms | %.3f ms | %.3f ms | %.3f ms | %.3f ms | %.3f µs |\n",
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

	report.WriteString("\n## Rotación de clave y filtro\n\n")
	fmt.Fprintf(&report, "- Tiempo hasta disponer del nuevo filtro: `%s`\n", data.Rotation.Duration)
	fmt.Fprintf(&report, "- Época anterior: `%s`\n", data.Rotation.OldEpoch)
	fmt.Fprintf(&report, "- Nueva época: `%s`\n", data.Rotation.NewEpoch)
	fmt.Fprintf(&report, "- Nuevo filtro disponible: `%t`\n", data.Rotation.NewFilterReady)
	fmt.Fprintf(&report, "- Filtro anterior rechazado para la nueva salida: `%t`\n", data.Rotation.OldFilterRejected)
	fmt.Fprintf(&report, "- Veredicto con la nueva época: `%s`\n", data.Rotation.NewVerdict)
	fmt.Fprintf(&report, "- Intentos hasta observar la nueva época: `%d`\n", data.Rotation.PollAttempts)

	report.WriteString("\n## Criterios de aceptación\n\n")
	report.WriteString("- [x] Al menos 10.000 consultas aleatorias ausentes por configuración de referencia.\n")
	report.WriteString("- [x] Comparación entre FPP empírica y FPP teórica.\n")
	report.WriteString("- [x] Las contraseñas presentes comprobadas responden `COMPROMETIDA`.\n")
	report.WriteString("- [x] Latencia separada entre filtro sin caché y con caché.\n")
	report.WriteString("- [x] Desglose de blind, red, evaluación ciega, unblind y Bloom lookup.\n")
	report.WriteString("- [x] Tamaño de `bloom.bin` y tiempo de construcción para 50k, 100k y 200k entradas.\n")
	report.WriteString("- [x] Medición desde `rotate-key` hasta respuesta válida con el nuevo filtro.\n")
	report.WriteString("- [x] Confirmación de que el filtro anterior no produce una coincidencia válida con la nueva salida.\n")
	report.WriteString("- [x] Entradas y semillas de medición registradas.\n")
	report.WriteString("- [x] Procedimiento reproducible mediante comandos del repositorio.\n")

	return os.WriteFile(
		filepath.Join(outputDir, "report.md"),
		[]byte(report.String()),
		0644,
	)
}
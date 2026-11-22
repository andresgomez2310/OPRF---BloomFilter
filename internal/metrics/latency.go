package metrics

import (
	"crypto/ed25519"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/andresgomez2310/OPRF---BloomFilter/internal/adminbuild"
	"github.com/andresgomez2310/OPRF---BloomFilter/internal/bloom"
	"github.com/andresgomez2310/OPRF---BloomFilter/internal/canonical"
	"github.com/andresgomez2310/OPRF---BloomFilter/internal/client"
	"github.com/andresgomez2310/OPRF---BloomFilter/internal/oprfcore"
	"github.com/andresgomez2310/OPRF---BloomFilter/internal/oprfserver"
)

type LatencyConfig struct {
	SeedPath       string
	SigningKeyPath string
	FilterDir      string
	CacheDir       string
	Samples        int
	Password       string
}

type LatencyResult struct {
	CacheMode        string
	Samples          int
	AverageTotalNS   int64
	AverageHTTPNS    int64
	AverageBlindNS   int64
	AverageNetworkNS int64
	AverageEvalNS    int64
	AverageUnblindNS int64
	AverageLookupNS  int64

	HTTPCount    int
	EvalCount    int
	BlindCount   int
	UnblindCount int
	LookupCount  int
}

type latencyCollector struct {
	mu      sync.Mutex
	http    time.Duration
	eval    time.Duration
	blind   time.Duration
	unblind time.Duration
	lookup  time.Duration

	httpCount    int
	evalCount    int
	blindCount   int
	unblindCount int
	lookupCount  int
}

type componentLatency struct {
	BlindNS   int64
	EvalNS    int64
	UnblindNS int64
	LookupNS  int64
}

func (c *latencyCollector) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.http = 0
	c.eval = 0
	c.blind = 0
	c.unblind = 0
	c.lookup = 0

	c.httpCount = 0
	c.evalCount = 0
	c.blindCount = 0
	c.unblindCount = 0
	c.lookupCount = 0
}

func (c *latencyCollector) addHTTP(d time.Duration) {
	c.mu.Lock()
	c.http += d
	c.httpCount++
	c.mu.Unlock()
}

func (c *latencyCollector) addEval(d time.Duration) {
	c.mu.Lock()
	c.eval += d
	c.evalCount++
	c.mu.Unlock()
}

func (c *latencyCollector) addBlind(d time.Duration) {
	c.mu.Lock()
	c.blind += d
	c.blindCount++
	c.mu.Unlock()
}

func (c *latencyCollector) addUnblind(d time.Duration) {
	c.mu.Lock()
	c.unblind += d
	c.unblindCount++
	c.mu.Unlock()
}

func (c *latencyCollector) addLookup(d time.Duration) {
	c.mu.Lock()
	c.lookup += d
	c.lookupCount++
	c.mu.Unlock()
}

func MeasureLatency(cfg LatencyConfig) ([]LatencyResult, error) {
	if cfg.Samples <= 0 {
		return nil, fmt.Errorf("samples must be greater than zero")
	}

	signingSeed, err := adminbuild.ReadHexFile(
		cfg.SigningKeyPath,
		ed25519.SeedSize,
	)
	if err != nil {
		return nil, err
	}

	publicKey := ed25519.NewKeyFromSeed(signingSeed).
		Public().(ed25519.PublicKey)

	// Las operaciones criptográficas y el lookup son extremadamente rápidos.
	// Se miden en un lote grande para evitar pérdidas de resolución del reloj.
	components, err := measureComponentLatency(
		cfg,
		publicKey,
		1000,
	)
	if err != nil {
		return nil, err
	}

	collector := &latencyCollector{}

	server, err := oprfserver.New(oprfserver.Config{
		SeedPath:          cfg.SeedPath,
		FilterDir:         cfg.FilterDir,
		ObserveEvaluation: collector.addEval,
	})
	if err != nil {
		return nil, err
	}

	httpServer := httptest.NewServer(server.Handler())
	defer httpServer.Close()

	clientConfig := client.Config{
		ServerURL:           httpServer.URL,
		CacheDir:            cfg.CacheDir,
		TrustedSigningKey:   publicKey,
		ObserveHTTP:         collector.addHTTP,
		ObserveBlind:        collector.addBlind,
		ObserveUnblind:      collector.addUnblind,
		ObserveFilterLookup: collector.addLookup,
	}

	results := make([]LatencyResult, 0, 2)

	// ------------------------------------------------------------
	// SIN CACHÉ
	// ------------------------------------------------------------

	uncached, err := measureLatencyMode(
		"uncached",
		cfg,
		clientConfig,
		collector,
		true,
	)
	if err != nil {
		return nil, err
	}

	applyComponentLatency(&uncached, components)

	results = append(results, uncached)

	// ------------------------------------------------------------
	// CON CACHÉ
	// ------------------------------------------------------------

	if err := os.RemoveAll(cfg.CacheDir); err != nil {
		return nil, err
	}

	// Esta consulta solamente calienta la caché.
	// No entra en las muestras.
	if _, err := client.Consult(cfg.Password, clientConfig); err != nil {
		return nil, err
	}

	collector.reset()

	cached, err := measureLatencyMode(
		"cached",
		cfg,
		clientConfig,
		collector,
		false,
	)
	if err != nil {
		return nil, err
	}

	applyComponentLatency(&cached, components)

	results = append(results, cached)

	return results, nil
}

func measureLatencyMode(
	mode string,
	cfg LatencyConfig,
	clientConfig client.Config,
	collector *latencyCollector,
	clearCache bool,
) (LatencyResult, error) {

	var total time.Duration

	collector.reset()

	for i := 0; i < cfg.Samples; i++ {
		if clearCache {
			if err := os.RemoveAll(cfg.CacheDir); err != nil {
				return LatencyResult{}, err
			}
		}

		start := time.Now()

		outcome, err := client.Consult(
			cfg.Password,
			clientConfig,
		)

		total += time.Since(start)

		if err != nil {
			return LatencyResult{}, err
		}

		if outcome.Verdict != client.VerdictCompromised {
			return LatencyResult{}, fmt.Errorf(
				"latency query returned %q instead of COMPROMETIDA",
				outcome.Verdict,
			)
		}
	}

	collector.mu.Lock()

	httpDuration := collector.http

	httpCount := collector.httpCount
	evalCount := collector.evalCount
	blindCount := collector.blindCount
	unblindCount := collector.unblindCount
	lookupCount := collector.lookupCount

	collector.mu.Unlock()

	// Verificamos que todos los observadores del flujo integrado
	// hayan sido llamados una vez por consulta.
	if blindCount != cfg.Samples {
		return LatencyResult{}, fmt.Errorf(
			"blind observer called %d times, expected %d",
			blindCount,
			cfg.Samples,
		)
	}

	if evalCount != cfg.Samples {
		return LatencyResult{}, fmt.Errorf(
			"evaluation observer called %d times, expected %d",
			evalCount,
			cfg.Samples,
		)
	}

	if unblindCount != cfg.Samples {
		return LatencyResult{}, fmt.Errorf(
			"unblind observer called %d times, expected %d",
			unblindCount,
			cfg.Samples,
		)
	}

	if lookupCount != cfg.Samples {
		return LatencyResult{}, fmt.Errorf(
			"lookup observer called %d times, expected %d",
			lookupCount,
			cfg.Samples,
		)
	}

	samples := int64(cfg.Samples)

	return LatencyResult{
		CacheMode:      mode,
		Samples:        cfg.Samples,
		AverageTotalNS: total.Nanoseconds() / samples,
		AverageHTTPNS:  httpDuration.Nanoseconds() / samples,

		HTTPCount:    httpCount,
		EvalCount:    evalCount,
		BlindCount:   blindCount,
		UnblindCount: unblindCount,
		LookupCount:  lookupCount,
	}, nil
}

func applyComponentLatency(
	result *LatencyResult,
	components componentLatency,
) {
	result.AverageBlindNS = components.BlindNS
	result.AverageEvalNS = components.EvalNS
	result.AverageUnblindNS = components.UnblindNS
	result.AverageLookupNS = components.LookupNS

	// HTTP contiene también la evaluación OPRF realizada por el servidor.
	// Restamos su promedio para no contarla dos veces en "network".
	result.AverageNetworkNS =
		result.AverageHTTPNS - components.EvalNS

	if result.AverageNetworkNS < 0 {
		result.AverageNetworkNS = 0
	}
}

// measureComponentLatency mide las operaciones pequeñas en lotes.
// El objetivo es evitar que operaciones reales de pocos ns/us aparezcan
// artificialmente como 0 debido a la resolución de medición.
func measureComponentLatency(
	cfg LatencyConfig,
	publicKey ed25519.PublicKey,
	iterations int,
) (componentLatency, error) {

	if iterations <= 0 {
		return componentLatency{}, fmt.Errorf(
			"component iterations must be greater than zero",
		)
	}

	input, err := canonical.PasswordBytes(cfg.Password)
	if err != nil {
		return componentLatency{}, err
	}

	seed, err := adminbuild.ReadHexFile(
		cfg.SeedPath,
		32,
	)
	if err != nil {
		return componentLatency{}, err
	}

	serverKey, err := oprfcore.DeriveServerKey(
		seed,
		nil,
	)
	if err != nil {
		return componentLatency{}, err
	}

	manifestBytes, err := os.ReadFile(
		filepath.Join(cfg.FilterDir, "manifest.json"),
	)
	if err != nil {
		return componentLatency{}, err
	}

	vector, err := os.ReadFile(
		filepath.Join(cfg.FilterDir, "bloom.bin"),
	)
	if err != nil {
		return componentLatency{}, err
	}

	manifest, err := adminbuild.Verify(
		manifestBytes,
		vector,
		publicKey,
	)
	if err != nil {
		return componentLatency{}, err
	}

	filter, err := bloom.FromBytes(
		manifest.Parameters.MBits,
		manifest.Parameters.KHashes,
		vector,
	)
	if err != nil {
		return componentLatency{}, err
	}

	queries := make([]*oprfcore.Query, iterations)
	evaluated := make([][]byte, iterations)
	outputs := make([][]byte, iterations)

	// ------------------------------------------------------------
	// BLIND
	// ------------------------------------------------------------

	start := time.Now()

	for i := 0; i < iterations; i++ {
		query, err := oprfcore.Blind(input)
		if err != nil {
			return componentLatency{}, err
		}

		queries[i] = query
	}

	blindDuration := time.Since(start)

	// ------------------------------------------------------------
	// SERVER EVALUATION
	// ------------------------------------------------------------

	start = time.Now()

	for i := 0; i < iterations; i++ {
		value, err := oprfcore.EvaluateBlinded(
			serverKey,
			queries[i].BlindedElement(),
		)
		if err != nil {
			return componentLatency{}, err
		}

		evaluated[i] = value
	}

	evaluationDuration := time.Since(start)

	// ------------------------------------------------------------
	// UNBLIND / FINALIZE
	// ------------------------------------------------------------

	start = time.Now()

	for i := 0; i < iterations; i++ {
		output, err := queries[i].Finalize(evaluated[i])
		if err != nil {
			return componentLatency{}, err
		}

		outputs[i] = output
	}

	unblindDuration := time.Since(start)

	// ------------------------------------------------------------
	// BLOOM LOOKUP
	// ------------------------------------------------------------
	lookupIterations := iterations * 1000

	start = time.Now()

	for i := 0; i < lookupIterations; i++ {
		found, err := filter.Contains(outputs[i%iterations])
		if err != nil {
			return componentLatency{}, err
		}

		if !found {
			return componentLatency{}, fmt.Errorf(
				"component benchmark expected COMPROMETIDA output",
			)
		}
	}

	lookupDuration := time.Since(start)

	divisor := int64(iterations)
	lookupDivisor := int64(lookupIterations)

	return componentLatency{
		BlindNS:   blindDuration.Nanoseconds() / divisor,
		EvalNS:    evaluationDuration.Nanoseconds() / divisor,
		UnblindNS: unblindDuration.Nanoseconds() / divisor,
		LookupNS:  lookupDuration.Nanoseconds() / lookupDivisor,
	}, nil
}

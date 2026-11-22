package metrics

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/andresgomez2310/OPRF---BloomFilter/internal/adminbuild"
	"github.com/andresgomez2310/OPRF---BloomFilter/internal/client"
	"github.com/andresgomez2310/OPRF---BloomFilter/internal/oprfserver"
	"net/http/httptest"
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
	AverageBlindNS   int64
	AverageNetworkNS int64
	AverageEvalNS    int64
	AverageUnblindNS int64
	AverageLookupNS  int64
}

type latencyCollector struct {
	mu       sync.Mutex
	http     time.Duration
	eval     time.Duration
	blind    time.Duration
	unblind  time.Duration
	lookup   time.Duration
}

func (c *latencyCollector) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.http = 0
	c.eval = 0
	c.blind = 0
	c.unblind = 0
	c.lookup = 0
}

func (c *latencyCollector) addHTTP(d time.Duration) {
	c.mu.Lock()
	c.http += d
	c.mu.Unlock()
}

func (c *latencyCollector) addEval(d time.Duration) {
	c.mu.Lock()
	c.eval += d
	c.mu.Unlock()
}

func (c *latencyCollector) addBlind(d time.Duration) {
	c.mu.Lock()
	c.blind += d
	c.mu.Unlock()
}

func (c *latencyCollector) addUnblind(d time.Duration) {
	c.mu.Lock()
	c.unblind += d
	c.mu.Unlock()
}

func (c *latencyCollector) addLookup(d time.Duration) {
	c.mu.Lock()
	c.lookup += d
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

	// 1. SIN CACHÉ:
	// Cada consulta empieza eliminando manifest.json y bloom.bin.
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
	results = append(results, uncached)

	// 2. CON CACHÉ:
	// Primero calentamos la caché y esa consulta NO entra en la medición.
	if err := os.RemoveAll(cfg.CacheDir); err != nil {
		return nil, err
	}

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

		outcome, err := client.Consult(cfg.Password, clientConfig)

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
	evaluationDuration := collector.eval
	blindDuration := collector.blind
	unblindDuration := collector.unblind
	lookupDuration := collector.lookup

	collector.mu.Unlock()

	// HTTP incluye la evaluación criptográfica realizada dentro del servidor, Para no contarla dos veces.
	networkDuration := httpDuration - evaluationDuration
	if networkDuration < 0 {
		networkDuration = 0
	}

	samples := int64(cfg.Samples)

	return LatencyResult{
		CacheMode:        mode,
		Samples:          cfg.Samples,
		AverageTotalNS:   total.Nanoseconds() / samples,
		AverageBlindNS:   blindDuration.Nanoseconds() / samples,
		AverageNetworkNS: networkDuration.Nanoseconds() / samples,
		AverageEvalNS:    evaluationDuration.Nanoseconds() / samples,
		AverageUnblindNS: unblindDuration.Nanoseconds() / samples,
		AverageLookupNS:  lookupDuration.Nanoseconds() / samples,
	}, nil
}
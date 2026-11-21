// Package oprfserver implementa el servidor HTTP del Servidor OPRF.
package oprfserver

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/andresgomez2310/OPRF---BloomFilter/internal/adminbuild"
	"github.com/andresgomez2310/OPRF---BloomFilter/internal/oprfcore"
)

type Config struct {
	SeedPath  string
	KeyInfo   []byte
	FilterDir string
}

type Server struct {
	cfg Config

	mu             sync.Mutex
	cachedKey      *oprfcore.ServerKey
	cachedSeedTime time.Time
}

func New(cfg Config) (*Server, error) {
	if cfg.SeedPath == "" {
		return nil, errors.New("oprfserver: SeedPath is required")
	}
	if cfg.FilterDir == "" {
		return nil, errors.New("oprfserver: FilterDir is required")
	}
	return &Server{cfg: cfg}, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/parameters", s.handleParameters)
	mux.HandleFunc("/v1/oprf/evaluate", s.handleEvaluate)
	mux.HandleFunc("/v1/filter/manifest", s.handleManifest)
	mux.HandleFunc("/v1/filter/bloom", s.handleBloom)
	return mux
}

// currentKey recarga skS cuando la semilla en disco cambia (rotación).
func (s *Server) currentKey() (*oprfcore.ServerKey, error) {
	info, err := os.Stat(s.cfg.SeedPath)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cachedKey != nil && info.ModTime().Equal(s.cachedSeedTime) {
		return s.cachedKey, nil
	}
	seed, err := adminbuild.ReadHexFile(s.cfg.SeedPath, 32)
	if err != nil {
		return nil, err
	}
	key, err := oprfcore.DeriveServerKey(seed, s.cfg.KeyInfo)
	if err != nil {
		return nil, err
	}
	s.cachedKey = key
	s.cachedSeedTime = info.ModTime()
	return key, nil
}

// currentManifest se lee en cada petición: la rotación publica el
// manifiesto nuevo y la siguiente consulta ya ve la época nueva.
func (s *Server) currentManifest() ([]byte, *adminbuild.Manifest, error) {
	data, err := os.ReadFile(filepath.Join(s.cfg.FilterDir, "manifest.json"))
	if err != nil {
		return nil, nil, err
	}
	var m adminbuild.Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, nil, err
	}
	return data, &m, nil
}

func (s *Server) handleParameters(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	_, m, err := s.currentManifest()
	if err != nil {
		http.Error(w, "manifest unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"suite_id":    oprfcore.SuiteID,
		"key_epoch":   m.KeyEpoch,
		"api_version": "v1",
	})
}

type evalRequest struct {
	BlindedElement string `json:"blindedElement"`
	KeyEpoch       string `json:"key_epoch"`
}

type evalResponse struct {
	EvaluatedElement string `json:"evaluatedElement"`
}

func (s *Server) handleEvaluate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)

	var req evalRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	_, m, err := s.currentManifest()
	if err != nil {
		http.Error(w, "manifest unavailable", http.StatusServiceUnavailable)
		return
	}
	if req.KeyEpoch != m.KeyEpoch {
		// Rechazo sin evaluar y sin registrar el elemento.
		http.Error(w, "epoch mismatch", http.StatusBadRequest)
		return
	}
	if req.BlindedElement != strings.ToLower(req.BlindedElement) {
		http.Error(w, "blindedElement must be lowercase hex", http.StatusBadRequest)
		return
	}
	blinded, err := hex.DecodeString(req.BlindedElement)
	if err != nil || len(blinded) != 32 {
		http.Error(w, "invalid blindedElement", http.StatusBadRequest)
		return
	}

	key, err := s.currentKey()
	if err != nil {
		http.Error(w, "server key unavailable", http.StatusServiceUnavailable)
		return
	}

	evaluated, err := oprfcore.EvaluateBlinded(key, blinded)
	if err != nil {
		// Elemento ilegible o identidad: 400, sin registrar.
		http.Error(w, "evaluation rejected", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(evalResponse{
		EvaluatedElement: hex.EncodeToString(evaluated),
	})
}

func (s *Server) handleManifest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	data, _, err := s.currentManifest()
	if err != nil {
		http.Error(w, "manifest unavailable", http.StatusServiceUnavailable)
		return
	}
	sum := sha256.Sum256(data)
	etag := `"` + hex.EncodeToString(sum[:]) + `"`
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("ETag", etag)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(data)
}

func (s *Server) handleBloom(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	data, err := os.ReadFile(filepath.Join(s.cfg.FilterDir, "bloom.bin"))
	if err != nil {
		http.Error(w, "bloom.bin unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(data)
}
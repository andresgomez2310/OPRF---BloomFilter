package oprfcore

import (
	"errors"
	"fmt"

	"github.com/cloudflare/circl/oprf"
)

const (
	// SuiteID identifica la suite acordada por el proyecto.
	SuiteID = "OPRF-ristretto255-SHA512"

	// OutputSize corresponde a SHA-512.
	OutputSize = 64
)

var (
	suite = oprf.SuiteRistretto255

	ErrNilServerKey = errors.New("oprfcore: nil server key")
)

type ServerKey struct {
	inner *oprf.PrivateKey
}

func DeriveServerKey(seed, keyInfo []byte) (*ServerKey, error) {
	key, err := oprf.DeriveKey(
		suite,
		oprf.BaseMode,
		seed,
		keyInfo,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"oprfcore: derive server key: %w",
			err,
		)
	}

	return &ServerKey{
		inner: key,
	}, nil
}

func (k *ServerKey) MarshalBinary() ([]byte, error) {
	if k == nil || k.inner == nil {
		return nil, ErrNilServerKey
	}

	data, err := k.inner.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf(
			"oprfcore: marshal server key: %w",
			err,
		)
	}

	return data, nil
}

// Evaluate realiza la evaluación OPRF sin cegado.

func Evaluate(
	key *ServerKey,
	inputBytes []byte,
) ([]byte, error) {

	if key == nil || key.inner == nil {
		return nil, ErrNilServerKey
	}

	server := oprf.NewServer(
		suite,
		key.inner,
	)

	output, err := server.FullEvaluate(inputBytes)
	if err != nil {
		return nil, fmt.Errorf(
			"oprfcore: evaluate: %w",
			err,
		)
	}

	if len(output) != OutputSize {
		return nil, fmt.Errorf(
			"oprfcore: unexpected output size: got %d want %d",
			len(output),
			OutputSize,
		)
	}

	return output, nil
}

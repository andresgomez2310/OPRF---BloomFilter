package oprfcore

import (
	"errors"
	"fmt"

	"github.com/cloudflare/circl/group" // <-- El import que faltaba
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

	ErrNilServerKey    = errors.New("oprfcore: nil server key")
	ErrIdentityElement = errors.New("oprfcore: identity element") // <-- Añadido
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

// EvaluateBlinded evalúa un elemento cegado de 32 bytes y devuelve el
// elemento evaluado. Rechaza el elemento identidad y bytes que no
// deserializan.
func EvaluateBlinded(key *ServerKey, blindedElement []byte) ([]byte, error) {
	if key == nil || key.inner == nil {
		return nil, ErrNilServerKey
	}

	element := suite.Group().NewElement()
	if err := element.UnmarshalBinary(blindedElement); err != nil {
		return nil, fmt.Errorf("oprfcore: invalid blinded element: %w", err)
	}
	if element.IsIdentity() {
		return nil, ErrIdentityElement
	}

	server := oprf.NewServer(suite, key.inner)
	request := &oprf.EvaluationRequest{
		Elements: []group.Element{element}, // <-- Corregido aquí
	}
	evaluation, err := server.Evaluate(request)
	if err != nil {
		return nil, fmt.Errorf("oprfcore: evaluate blinded: %w", err)
	}
	if len(evaluation.Elements) != 1 {
		return nil, errors.New("oprfcore: unexpected evaluated element count")
	}

	result, err := evaluation.Elements[0].MarshalBinaryCompress()
	if err != nil {
		return nil, fmt.Errorf("oprfcore: marshal evaluated element: %w", err)
	}
	return result, nil
}
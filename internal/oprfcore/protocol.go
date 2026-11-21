package oprfcore

import (
	"errors"
	"fmt"

	"github.com/cloudflare/circl/group"
	"github.com/cloudflare/circl/oprf"
)

const ElementSize = 32

var ErrMalformedElement = errors.New("oprfcore: malformed element")

// Query is the client's blinded session. The scalar and the input bytes stay
// inside FinalizeData; BlindedElement is the only value that would leave.
type Query struct {
	fin     *oprf.FinalizeData
	blinded []byte
}

func (q *Query) BlindedElement() []byte {
	if q == nil {
		return nil
	}
	return append([]byte(nil), q.blinded...)
}

func hashToGroupDST() []byte {
	dst := make([]byte, 0, 64)
	dst = append(dst, "HashToGroup-OPRFV1-"...)
	dst = append(dst, 0)
	dst = append(dst, "-ristretto255-SHA512"...)
	return dst
}

// Blind hashes input with the suite, rejects the identity element, and blinds
// the point with a fresh scalar.
func Blind(input []byte) (*Query, error) {
	copied := append([]byte(nil), input...)
	point := group.Ristretto255.HashToElement(copied, hashToGroupDST())
	return blindFromPoint(copied, point)
}

func blindFromPoint(input []byte, point group.Element) (*Query, error) {
	if point == nil || point.IsIdentity() {
		return nil, ErrIdentityElement
	}

	client := oprf.NewClient(suite)
	fin, req, err := client.Blind([][]byte{input})
	if err != nil {
		if errors.Is(err, oprf.ErrInvalidInput) {
			return nil, ErrIdentityElement
		}
		return nil, fmt.Errorf("oprfcore: blind: %w", err)
	}
	if req == nil || len(req.Elements) != 1 || req.Elements[0] == nil || req.Elements[0].IsIdentity() {
		return nil, ErrIdentityElement
	}

	raw, err := req.Elements[0].MarshalBinaryCompress()
	if err != nil {
		return nil, fmt.Errorf("oprfcore: marshal blinded element: %w", err)
	}
	if len(raw) != ElementSize {
		return nil, fmt.Errorf("oprfcore: unexpected blinded size: got %d want %d", len(raw), ElementSize)
	}

	return &Query{fin: fin, blinded: raw}, nil
}

func decodeElement(raw []byte) (group.Element, error) {
	if len(raw) != ElementSize {
		return nil, ErrMalformedElement
	}
	el := group.Ristretto255.NewElement()
	if err := el.UnmarshalBinary(raw); err != nil {
		return nil, ErrMalformedElement
	}
	return el, nil
}

// BlindEvaluate multiplies a blinded element by skS and returns the compressed
// evaluated element. It does not see the password or the final output.
func BlindEvaluate(key *ServerKey, blinded []byte) ([]byte, error) {
	if key == nil || key.inner == nil {
		return nil, ErrNilServerKey
	}
	el, err := decodeElement(blinded)
	if err != nil {
		return nil, err
	}
	if el.IsIdentity() {
		return nil, ErrIdentityElement
	}

	server := oprf.NewServer(suite, key.inner)
	evaluation, err := server.Evaluate(&oprf.EvaluationRequest{Elements: []oprf.Blinded{el}})
	if err != nil {
		return nil, fmt.Errorf("oprfcore: blind evaluate: %w", err)
	}
	if evaluation == nil || len(evaluation.Elements) != 1 || evaluation.Elements[0] == nil || evaluation.Elements[0].IsIdentity() {
		return nil, ErrIdentityElement
	}

	raw, err := evaluation.Elements[0].MarshalBinaryCompress()
	if err != nil {
		return nil, fmt.Errorf("oprfcore: marshal evaluated element: %w", err)
	}
	if len(raw) != ElementSize {
		return nil, fmt.Errorf("oprfcore: unexpected evaluated size: got %d want %d", len(raw), ElementSize)
	}
	return raw, nil
}

// Finalize unblinds an evaluated element and returns the 64-byte OPRF output.
// A malformed or identity element aborts before the finalize hash.
func (q *Query) Finalize(evaluated []byte) ([]byte, error) {
	if q == nil || q.fin == nil {
		return nil, ErrMalformedElement
	}
	el, err := decodeElement(evaluated)
	if err != nil {
		return nil, err
	}
	if el.IsIdentity() {
		return nil, ErrIdentityElement
	}

	client := oprf.NewClient(suite)
	outputs, err := client.Finalize(q.fin, &oprf.Evaluation{Elements: []oprf.Evaluated{el}})
	if err != nil {
		if errors.Is(err, oprf.ErrInvalidInput) {
			return nil, ErrIdentityElement
		}
		return nil, fmt.Errorf("oprfcore: finalize: %w", err)
	}
	if len(outputs) != 1 || len(outputs[0]) != OutputSize {
		return nil, fmt.Errorf("oprfcore: unexpected output size: got %d", len(outputs))
	}
	return append([]byte(nil), outputs[0]...), nil
}

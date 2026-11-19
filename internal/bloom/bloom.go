package bloom

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

const OutputSize = 64

var (
	ErrInvalidParameters = errors.New("bloom: invalid parameters")
	ErrInvalidElement    = errors.New("bloom: element must be 64 bytes")
	ErrInvalidData       = errors.New("bloom: invalid bit vector")
)

// Filter stores a Bloom filter with m bits and k hash positions per element.
type Filter struct {
	m    uint64
	k    uint64
	bits []byte
}

// Parameters calculates m and k using the formulas in the project spec.
func Parameters(n int, p float64) (int, int, error) {
	if n <= 0 || math.IsNaN(p) || math.IsInf(p, 0) || p <= 0 || p >= 1 {
		return 0, 0, ErrInvalidParameters
	}

	ln2 := math.Ln2
	mFloat := math.Round(-float64(n) * math.Log(p) / (ln2 * ln2))
	if math.IsNaN(mFloat) || math.IsInf(mFloat, 0) || mFloat < 1 || mFloat >= float64(math.MaxInt) {
		return 0, 0, ErrInvalidParameters
	}
	m := int(mFloat)
	kFloat := math.Round((float64(m) / float64(n)) * ln2)
	if kFloat < 1 || kFloat >= float64(math.MaxInt) {
		return 0, 0, ErrInvalidParameters
	}
	return m, int(kFloat), nil
}

func New(n int, p float64) (*Filter, error) {
	m, k, err := Parameters(n, p)
	if err != nil {
		return nil, err
	}
	return NewWithParameters(m, k)
}

// NewWithParameters constructs a zero-filled filter from exact parameters.
func NewWithParameters(m, k int) (*Filter, error) {
	if m <= 0 || k <= 0 || uint64(m) > uint64(math.MaxInt)-7 {
		return nil, ErrInvalidParameters
	}
	return &Filter{m: uint64(m), k: uint64(k), bits: make([]byte, (m+7)/8)}, nil
}

// FromBytes restores a filter from the exact bytes of bloom.bin.
func FromBytes(m, k int, data []byte) (*Filter, error) {
	if m <= 0 || k <= 0 || uint64(m) > uint64(math.MaxInt)-7 {
		return nil, ErrInvalidParameters
	}
	if len(data) != (m+7)/8 {
		return nil, ErrInvalidData
	}
	// Unused trailing bits (least significant bits) must be zero.
	if rem := m % 8; rem != 0 && data[len(data)-1]&byte((1<<(8-rem))-1) != 0 {
		return nil, ErrInvalidData
	}
	copyOfData := append([]byte(nil), data...)
	return &Filter{m: uint64(m), k: uint64(k), bits: copyOfData}, nil
}

func (f *Filter) M() int { return int(f.m) }
func (f *Filter) K() int { return int(f.k) }

// Bytes returns a defensive copy of bloom.bin (no header or metadata).
func (f *Filter) Bytes() []byte { return append([]byte(nil), f.bits...) }

// Positions implements (h1 + i*h2) mod m using arithmetic modulo m.
func (f *Filter) Positions(element []byte) ([]uint64, error) {
	if len(element) != OutputSize {
		return nil, ErrInvalidElement
	}
	h1 := binary.BigEndian.Uint64(element[:8]) % f.m
	h2 := binary.BigEndian.Uint64(element[8:16])
	if h2 == 0 {
		h2 = 1
	}
	step := h2 % f.m
	positions := make([]uint64, 0, f.k)
	pos := h1
	for i := uint64(0); i < f.k; i++ {
		positions = append(positions, pos)
		// Avoid overflow even when parameters are large.
		if step != 0 {
			if pos >= f.m-step {
				pos -= f.m - step
			} else {
				pos += step
			}
		}
	}
	return positions, nil
}

func (f *Filter) Add(element []byte) error {
	positions, err := f.Positions(element)
	if err != nil {
		return err
	}
	for _, pos := range positions {
		f.bits[pos/8] |= byte(0x80 >> (pos % 8))
	}
	return nil
}

func (f *Filter) Contains(element []byte) (bool, error) {
	positions, err := f.Positions(element)
	if err != nil {
		return false, err
	}
	for _, pos := range positions {
		if f.bits[pos/8]&byte(0x80>>(pos%8)) == 0 {
			return false, nil
		}
	}
	return true, nil
}

// FalsePositiveRate gives the approximate probability at n inserted elements.
func (f *Filter) FalsePositiveRate(n int) (float64, error) {
	if n < 0 {
		return 0, fmt.Errorf("%w: negative element count", ErrInvalidParameters)
	}
	return math.Pow(1-math.Exp(-float64(f.k)*float64(n)/float64(f.m)), float64(f.k)), nil
}

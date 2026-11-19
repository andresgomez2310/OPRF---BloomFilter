package bloom

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func fixture(v byte) []byte { return bytes.Repeat([]byte{v}, OutputSize) }

func TestReferenceParameters(t *testing.T) {
	tests := []struct {
		n    int
		p    float64
		m, k int
	}{
		{100000, 0.01, 958506, 7},
		{100000, 0.001, 1437759, 10},
		{1000000, 0.01, 9585058, 7},
	}
	for _, tt := range tests {
		m, k, err := Parameters(tt.n, tt.p)
		if err != nil || m != tt.m || k != tt.k {
			t.Fatalf("Parameters(%d,%g) = %d,%d,%v; want %d,%d", tt.n, tt.p, m, k, err, tt.m, tt.k)
		}
	}
}

func TestInsertAndLookupNoFalseNegatives(t *testing.T) {
	f, err := New(1000, 0.01)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 1000; i++ {
		e := make([]byte, OutputSize)
		binary.BigEndian.PutUint64(e[:8], uint64(i))
		binary.BigEndian.PutUint64(e[8:16], uint64(i*13+1))
		if err := f.Add(e); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 1000; i++ {
		e := make([]byte, OutputSize)
		binary.BigEndian.PutUint64(e[:8], uint64(i))
		binary.BigEndian.PutUint64(e[8:16], uint64(i*13+1))
		ok, err := f.Contains(e)
		if err != nil || !ok {
			t.Fatalf("inserted item %d not found: %v", i, err)
		}
	}
}

func TestPositionsBigEndianAndZeroH2(t *testing.T) {
	f, _ := NewWithParameters(10, 3)
	e := make([]byte, OutputSize)
	binary.BigEndian.PutUint64(e[:8], 9)
	positions, err := f.Positions(e)
	if err != nil {
		t.Fatal(err)
	}
	want := []uint64{9, 0, 1}
	for i, pos := range positions {
		if pos != want[i] {
			t.Fatalf("position %d: got %d want %d", i, pos, want[i])
		}
	}
	binary.BigEndian.PutUint64(e[8:16], 3)
	positions, _ = f.Positions(e)
	want = []uint64{9, 2, 5}
	for i, pos := range positions {
		if pos != want[i] {
			t.Fatalf("position %d: got %d want %d", i, pos, want[i])
		}
	}
}

func TestMSBAndTrailingBits(t *testing.T) {
	f, _ := NewWithParameters(10, 1)
	e := make([]byte, OutputSize)
	binary.BigEndian.PutUint64(e[:8], 0)
	if err := f.Add(e); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(f.Bytes(), []byte{0x80, 0x00}) {
		t.Fatalf("bit 0 not MSB: %x", f.Bytes())
	}
	binary.BigEndian.PutUint64(e[:8], 9)
	if err := f.Add(e); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(f.Bytes(), []byte{0x80, 0x40}) {
		t.Fatalf("bit 9 wrong: %x", f.Bytes())
	}
}

func TestBinaryRoundTripAndIndependentCopy(t *testing.T) {
	f, _ := New(100, 0.01)
	e := fixture(0x42)
	if err := f.Add(e); err != nil {
		t.Fatal(err)
	}
	data := f.Bytes()
	loaded, err := FromBytes(f.M(), f.K(), data)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := loaded.Contains(e)
	if err != nil || !ok || !bytes.Equal(data, loaded.Bytes()) {
		t.Fatalf("round trip failed: %v", err)
	}
	data[0] ^= 0xff
	if !bytes.Equal(f.Bytes(), loaded.Bytes()) {
		t.Fatal("external modification changed filter")
	}
}

func TestInvalidInputs(t *testing.T) {
	for _, tc := range []struct {
		n int
		p float64
	}{{0, .01}, {1, 0}, {1, 1}, {-1, .01}} {
		if _, _, err := Parameters(tc.n, tc.p); !errors.Is(err, ErrInvalidParameters) {
			t.Fatalf("expected invalid parameters for %+v", tc)
		}
	}
	f, _ := NewWithParameters(10, 2)
	if err := f.Add([]byte{1}); !errors.Is(err, ErrInvalidElement) {
		t.Fatal("should reject non-64-byte element")
	}
	if _, err := f.Contains([]byte{1}); !errors.Is(err, ErrInvalidElement) {
		t.Fatal("should reject non-64-byte element")
	}
	if _, err := FromBytes(10, 2, []byte{0x80}); !errors.Is(err, ErrInvalidData) {
		t.Fatal("should reject wrong size")
	}
	if _, err := FromBytes(10, 2, []byte{0, 0x01}); !errors.Is(err, ErrInvalidData) {
		t.Fatal("should reject nonzero trailing bits")
	}
}

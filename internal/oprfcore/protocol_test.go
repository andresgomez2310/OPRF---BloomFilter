package oprfcore

import (
	"bytes"
	"errors"
	"testing"

	"github.com/cloudflare/circl/group"

	"github.com/andresgomez2310/OPRF---BloomFilter/internal/canonical"
)

func testKey(t *testing.T) *ServerKey {
	t.Helper()
	key, err := DeriveServerKey(bytes.Repeat([]byte{0x12}, 32), []byte("epoca-prueba"))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func identityElement(t *testing.T) []byte {
	t.Helper()
	raw, err := group.Ristretto255.NewElement().MarshalBinaryCompress()
	if err != nil {
		t.Fatal(err)
	}
	if !group.Ristretto255.NewElement().IsIdentity() {
		t.Fatal("zero element is not the identity")
	}
	return raw
}

func mustBlindedOutput(t *testing.T, key *ServerKey, password string) (blinded, output []byte) {
	t.Helper()
	input, err := canonical.PasswordBytes(password)
	if err != nil {
		t.Fatal(err)
	}
	query, err := Blind(input)
	if err != nil {
		t.Fatal(err)
	}
	blinded = query.BlindedElement()
	evaluated, err := BlindEvaluate(key, blinded)
	if err != nil {
		t.Fatal(err)
	}
	output, err = query.Finalize(evaluated)
	if err != nil {
		t.Fatal(err)
	}
	return blinded, output
}

func TestTwoQueriesShareOutputAndDifferInBlind(t *testing.T) {
	key := testKey(t)
	password := "MiClave-2026!"
	input, err := canonical.PasswordBytes(password)
	if err != nil {
		t.Fatal(err)
	}
	direct, err := Evaluate(key, input)
	if err != nil {
		t.Fatal(err)
	}

	firstBlind, firstOut := mustBlindedOutput(t, key, password)
	secondBlind, secondOut := mustBlindedOutput(t, key, password)

	if len(firstBlind) != ElementSize || len(secondBlind) != ElementSize {
		t.Fatalf("blinded elements must be %d bytes", ElementSize)
	}
	if bytes.Equal(firstBlind, secondBlind) {
		t.Fatal("two queries produced the same blinded element")
	}
	for _, raw := range [][]byte{firstBlind, secondBlind} {
		el, err := decodeElement(raw)
		if err != nil {
			t.Fatal(err)
		}
		if el.IsIdentity() {
			t.Fatal("blinded element deserialized as the identity")
		}
	}
	if !bytes.Equal(firstOut, secondOut) {
		t.Fatal("unblinded outputs differ")
	}
	if !bytes.Equal(firstOut, direct) || len(firstOut) != OutputSize {
		t.Fatalf("blinded output does not match Evaluate\ngot:  %x\nwant: %x", firstOut, direct)
	}
}

func TestBlindAbortsBeforeBlindingIdentity(t *testing.T) {
	query, err := blindFromPoint([]byte("clave"), group.Ristretto255.NewElement())
	if query != nil {
		t.Fatal("identity point produced a blinded element")
	}
	if !errors.Is(err, ErrIdentityElement) {
		t.Fatalf("got %v, want ErrIdentityElement", err)
	}
}

func TestFinalizeRejectsMalformedAndIdentity(t *testing.T) {
	key := testKey(t)
	input, err := canonical.PasswordBytes("MiClave-2026!")
	if err != nil {
		t.Fatal(err)
	}
	query, err := Blind(input)
	if err != nil {
		t.Fatal(err)
	}

	output, err := query.Finalize([]byte{0x01, 0x02})
	if output != nil || !errors.Is(err, ErrMalformedElement) {
		t.Fatalf("malformed element produced output=%x err=%v", output, err)
	}

	output, err = query.Finalize(identityElement(t))
	if output != nil || !errors.Is(err, ErrIdentityElement) {
		t.Fatalf("identity element produced output=%x err=%v", output, err)
	}

	output, err = BlindEvaluate(key, identityElement(t))
	if output != nil || !errors.Is(err, ErrIdentityElement) {
		t.Fatalf("BlindEvaluate accepted the identity: output=%x err=%v", output, err)
	}

	output, err = BlindEvaluate(key, []byte{0xff})
	if output != nil || !errors.Is(err, ErrMalformedElement) {
		t.Fatalf("BlindEvaluate accepted a short element: output=%x err=%v", output, err)
	}
}

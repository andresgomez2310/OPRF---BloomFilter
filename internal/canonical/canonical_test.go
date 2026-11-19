package canonical_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/andresgomez2310/OPRF---BloomFilter/internal/canonical"
)

func TestPasswordBytesIsDeterministic(t *testing.T) {
	password := "MiClave-2026!"

	first, err := canonical.PasswordBytes(password)
	if err != nil {
		t.Fatal(err)
	}

	second, err := canonical.PasswordBytes(password)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(first, second) {
		t.Fatalf(
			"same password produced different bytes: %x != %x",
			first,
			second,
		)
	}
}

func TestPasswordBytesNormalizesUnicodeNFC(t *testing.T) {
	composed := "café"

	decomposed := "cafe\u0301"

	first, err := canonical.PasswordBytes(composed)
	if err != nil {
		t.Fatal(err)
	}

	second, err := canonical.PasswordBytes(decomposed)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(first, second) {
		t.Fatalf(
			"NFC-equivalent passwords produced different bytes: %x != %x",
			first,
			second,
		)
	}
}

func TestPasswordBytesPreservesWhitespace(t *testing.T) {
	password := " Password123! "

	got, err := canonical.PasswordBytes(password)
	if err != nil {
		t.Fatal(err)
	}

	if string(got) != password {
		t.Fatalf(
			"password whitespace changed: got %q want %q",
			string(got),
			password,
		)
	}
}

func TestPasswordBytesPreservesCase(t *testing.T) {
	upper, err := canonical.PasswordBytes("Password")
	if err != nil {
		t.Fatal(err)
	}

	lower, err := canonical.PasswordBytes("password")
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(upper, lower) {
		t.Fatal("canonicalization must preserve case")
	}
}

func TestPasswordBytesRejectsInvalidUTF8(t *testing.T) {
	invalid := string([]byte{0xff, 0xfe})

	_, err := canonical.PasswordBytes(invalid)

	if !errors.Is(err, canonical.ErrInvalidUTF8) {
		t.Fatalf(
			"got error %v, want ErrInvalidUTF8",
			err,
		)
	}
}

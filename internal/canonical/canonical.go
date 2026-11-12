package canonical

import (
	"errors"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

var ErrInvalidUTF8 = errors.New("canonical: password is not valid UTF-8")

func PasswordBytes(password string) ([]byte, error) {
	if !utf8.ValidString(password) {
		return nil, ErrInvalidUTF8
	}

	normalized := norm.NFC.String(password)

	return []byte(normalized), nil
}

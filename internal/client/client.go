// Package client checks a password against a published Bloom filter.
// The password, the blinding scalar and the OPRF output stay in this process.
// The blinded element is the only value that would be sent to an OPRF server.
package client

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/andresgomez2310/OPRF---BloomFilter/internal/adminbuild"
	"github.com/andresgomez2310/OPRF---BloomFilter/internal/bloom"
	"github.com/andresgomez2310/OPRF---BloomFilter/internal/canonical"
	"github.com/andresgomez2310/OPRF---BloomFilter/internal/oprfcore"
)

const (
	VerdictCompromised = "COMPROMETIDA"
	VerdictNotFound    = "NO ENCONTRADA EN LA LISTA"
	NoteFalsePositive  = "Esta coincidencia puede ser un falso positivo."
	NotePublishedSet   = "Este resultado solo indica que la contraseña no está en el conjunto publicado."
)

var ErrEpochMismatch = errors.New("client: manifest epoch does not match the evaluation key")

// Outcome is a verdict for one password. Verdict is empty when the check aborts.
type Outcome struct {
	BlindedElement []byte
	Output         []byte
	Verdict        string
	Note           string
}

func (o Outcome) Format() string {
	if o.Verdict == "" {
		return ""
	}
	return o.Verdict + "\n" + o.Note + "\n"
}

// ReadPassword reads one password from r. A terminal prompt is written only
// when interactive is set. The trailing newline is removed; the rest is kept.
func ReadPassword(r io.Reader, prompt io.Writer, interactive bool) (string, error) {
	if interactive {
		if _, err := io.WriteString(prompt, "Contraseña: "); err != nil {
			return "", err
		}
	}
	reader := bufio.NewReader(r)
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	if errors.Is(err, io.EOF) && line == "" {
		return "", errors.New("client: no password was provided")
	}
	line = strings.TrimSuffix(line, "\n")
	line = strings.TrimSuffix(line, "\r")
	return line, nil
}

// Consult loads the published manifest and bloom.bin, evaluates the password
// with key, and returns a verdict only when keyEpoch is the manifest epoch.
func Consult(password string, key *oprfcore.ServerKey, keyEpoch, publishedDir string) (Outcome, error) {
	manifestBytes, err := os.ReadFile(filepath.Join(publishedDir, "manifest.json"))
	if err != nil {
		return Outcome{}, err
	}
	var manifest adminbuild.Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return Outcome{}, err
	}
	if manifest.KeyEpoch != keyEpoch {
		return Outcome{}, ErrEpochMismatch
	}
	vector, err := os.ReadFile(filepath.Join(publishedDir, "bloom.bin"))
	if err != nil {
		return Outcome{}, err
	}
	filter, err := bloom.FromBytes(manifest.Parameters.MBits, manifest.Parameters.KHashes, vector)
	if err != nil {
		return Outcome{}, err
	}

	input, err := canonical.PasswordBytes(password)
	if err != nil {
		return Outcome{}, err
	}
	query, err := oprfcore.Blind(input)
	if err != nil {
		return Outcome{}, err
	}
	evaluated, err := oprfcore.BlindEvaluate(key, query.BlindedElement())
	if err != nil {
		return Outcome{}, err
	}
	return Complete(query, evaluated, filter)
}

// Complete turns an evaluated element into a verdict. An invalid element
// produces no verdict.
func Complete(query *oprfcore.Query, evaluated []byte, filter *bloom.Filter) (Outcome, error) {
	output, err := query.Finalize(evaluated)
	if err != nil {
		return Outcome{}, err
	}
	found, err := filter.Contains(output)
	if err != nil {
		return Outcome{}, err
	}
	outcome := Outcome{
		BlindedElement: query.BlindedElement(),
		Output:         output,
	}
	if found {
		outcome.Verdict = VerdictCompromised
		outcome.Note = NoteFalsePositive
		return outcome, nil
	}
	outcome.Verdict = VerdictNotFound
	outcome.Note = NotePublishedSet
	return outcome, nil
}

package oprfcore

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/cloudflare/circl/oprf"
)

func mustHex(t *testing.T, value string) []byte {
	t.Helper()

	data, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("invalid test hex: %v", err)
	}

	return data
}

func TestRFC9497KeyDerivation(t *testing.T) {
	seed := mustHex(
		t,
		"a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3"+
			"a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3",
	)

	keyInfo := mustHex(
		t,
		"74657374206b6579",
	)

	expectedKey := mustHex(
		t,
		"5ebcea5ee37023ccb9fc2d2019f9d773"+
			"7be85591ae8652ffa9ef0f4d37063b0e",
	)

	key, err := DeriveServerKey(
		seed,
		keyInfo,
	)
	if err != nil {
		t.Fatal(err)
	}

	got, err := key.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got, expectedKey) {
		t.Fatalf(
			"derived key does not match RFC 9497\n"+
				"got:  %x\n"+
				"want: %x",
			got,
			expectedKey,
		)
	}
}

func TestEvaluateMatchesRFC9497Vector1(t *testing.T) {
	seed := mustHex(
		t,
		"a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3"+
			"a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3",
	)

	keyInfo := mustHex(
		t,
		"74657374206b6579",
	)

	input := mustHex(
		t,
		"00",
	)

	expectedOutput := mustHex(
		t,
		"527759c3d9366f277d8c6020418d96bb"+
			"393ba2afb20ff90df23fb7708264e2f3"+
			"ab9135e3bd69955851de4b1f9fe8a097"+
			"3396719b7912ba9ee8aa7d0b5e24bcf6",
	)

	key, err := DeriveServerKey(
		seed,
		keyInfo,
	)
	if err != nil {
		t.Fatal(err)
	}

	output, err := Evaluate(
		key,
		input,
	)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(output, expectedOutput) {
		t.Fatalf(
			"Evaluate output does not match RFC 9497\n"+
				"got:  %x\n"+
				"want: %x",
			output,
			expectedOutput,
		)
	}
}

func TestRFC9497FullProtocolVectors(t *testing.T) {
	keySeed := mustHex(
		t,
		"a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3"+
			"a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3",
	)

	keyInfo := mustHex(
		t,
		"74657374206b6579",
	)

	key, err := DeriveServerKey(keySeed, keyInfo)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name             string
		input            string
		blind            string
		blindedElement   string
		evaluatedElement string
		output           string
	}{
		{
			name:  "vector 1",
			input: "00",
			blind: "64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706",
			blindedElement: "609a0ae68c15a3cf6903766461307e5c" +
				"8bb2f95e7e6550e1ffa2dc99e412803c",
			evaluatedElement: "7ec6578ae5120958eb2db1745758ff37" +
				"9e77cb64fe77b0b2d8cc917ea0869c7e",
			output: "527759c3d9366f277d8c6020418d96bb" +
				"393ba2afb20ff90df23fb7708264e2f3" +
				"ab9135e3bd69955851de4b1f9fe8a097" +
				"3396719b7912ba9ee8aa7d0b5e24bcf6",
		},
		{
			name:  "vector 2",
			input: "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
			blind: "64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706",
			blindedElement: "da27ef466870f5f15296299850aa0886" +
				"29945a17d1f5b7f5ff043f76b3c06418",
			evaluatedElement: "b4cbf5a4f1eeda5a63ce7b77c7d23f46" +
				"1db3fcab0dd28e4e17cecb5c90d02c25",
			output: "f4a74c9c592497375e796aa837e907b1" +
				"a045d34306a749db9f34221f7e750cb4" +
				"f2a6413a6bf6fa5e19ba6348eb673934" +
				"a722a7ede2e7621306d18951e7cf2c73",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := mustHex(t, tt.input)
			blindBytes := mustHex(t, tt.blind)

			blind := suite.Group().NewScalar()

			if err := blind.UnmarshalBinary(blindBytes); err != nil {
				t.Fatalf("cannot decode blind: %v", err)
			}

			client := oprf.NewClient(suite)

			finalizeData, request, err := client.DeterministicBlind(
				[][]byte{input},
				[]oprf.Blind{blind},
			)
			if err != nil {
				t.Fatalf("deterministic blind failed: %v", err)
			}

			gotBlinded, err := request.Elements[0].MarshalBinaryCompress()
			if err != nil {
				t.Fatal(err)
			}

			expectedBlinded := mustHex(t, tt.blindedElement)

			if !bytes.Equal(gotBlinded, expectedBlinded) {
				t.Fatalf(
					"blinded element mismatch\n"+
						"got:  %x\n"+
						"want: %x",
					gotBlinded,
					expectedBlinded,
				)
			}

			server := oprf.NewServer(suite, key.inner)

			evaluation, err := server.Evaluate(request)
			if err != nil {
				t.Fatalf("server evaluation failed: %v", err)
			}

			gotEvaluated, err := evaluation.Elements[0].MarshalBinaryCompress()
			if err != nil {
				t.Fatal(err)
			}

			expectedEvaluated := mustHex(t, tt.evaluatedElement)

			if !bytes.Equal(gotEvaluated, expectedEvaluated) {
				t.Fatalf(
					"evaluated element mismatch\n"+
						"got:  %x\n"+
						"want: %x",
					gotEvaluated,
					expectedEvaluated,
				)
			}

			outputs, err := client.Finalize(
				finalizeData,
				evaluation,
			)
			if err != nil {
				t.Fatalf("finalize failed: %v", err)
			}

			expectedOutput := mustHex(t, tt.output)

			if !bytes.Equal(outputs[0], expectedOutput) {
				t.Fatalf(
					"output mismatch\n"+
						"got:  %x\n"+
						"want: %x",
					outputs[0],
					expectedOutput,
				)
			}
		})
	}
}

// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dnsprotocol

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestCanonicalHandshakeTLD(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  string
	}{
		{input: "example1", want: "example1"},
		{input: "EXAMPLE1", want: "example1"},
		{input: "Example1.", want: "example1"},
		{input: "xn--bcher-kva", want: "xn--bcher-kva"},
		{input: "under_score", want: "under_score"},
		{input: "123", want: "123"},
	}
	for _, test := range tests {
		got, err := CanonicalHandshakeTLD(test.input)
		if err != nil {
			t.Fatalf("CanonicalHandshakeTLD(%q): %v", test.input, err)
		}
		if got != test.want {
			t.Fatalf(
				"CanonicalHandshakeTLD(%q) = %q, want %q",
				test.input,
				got,
				test.want,
			)
		}
	}
}

func TestCanonicalHandshakeTLDRejectsInvalidNames(t *testing.T) {
	t.Parallel()

	tests := []string{
		"",
		".",
		"example..",
		"sub.example",
		"-example",
		"example-",
		"_example",
		"example_",
		"ex ample",
		"bücher",
		"K",
		strings.Repeat("a", 64),
	}
	for _, test := range tests {
		if _, err := CanonicalHandshakeTLD(test); err == nil {
			t.Fatalf("CanonicalHandshakeTLD(%q) succeeded", test)
		}
	}
}

func TestCanonicalHandshakeTLDRejectsConsensusBlacklist(t *testing.T) {
	t.Parallel()

	for _, name := range []string{
		"example",
		"EXAMPLE.",
		"invalid",
		"local",
		"LOCAL.",
		"localhost",
		"test",
	} {
		if _, err := CanonicalHandshakeTLD(name); err == nil {
			t.Errorf("CanonicalHandshakeTLD(%q) succeeded", name)
		}
	}
}

func TestHashHandshakeNameCanonicalizesPresentation(t *testing.T) {
	t.Parallel()

	lower, err := HashHandshakeName("example1")
	if err != nil {
		t.Fatalf("hash lowercase name: %v", err)
	}
	upper, err := HashHandshakeName("EXAMPLE1.")
	if err != nil {
		t.Fatalf("hash presentation name: %v", err)
	}
	if lower != upper {
		t.Fatal("presentation forms produced different hashes")
	}
}

func TestBindingRoundTrip(t *testing.T) {
	t.Parallel()

	binding := testBinding(t)
	item, err := binding.MarshalTXTItem()
	if err != nil {
		t.Fatalf("marshal TXT item: %v", err)
	}
	if len(item) > MaxHandshakeTXTItemBytes {
		t.Fatalf("TXT item is %d bytes", len(item))
	}
	if !bytes.HasPrefix(item, []byte(bindingTXTMagicV1)) {
		t.Fatal("TXT item lacks CDNS1 discriminator")
	}

	got, err := UnmarshalBindingTXTItem(item)
	if err != nil {
		t.Fatalf("unmarshal TXT item: %v", err)
	}
	if got != binding {
		t.Fatalf("round trip mismatch:\n got: %#v\nwant: %#v", got, binding)
	}
	if err := got.ValidateForName("EXAMPLE1."); err != nil {
		t.Fatalf("validate for name: %v", err)
	}
}

func TestFindBindingTXT(t *testing.T) {
	t.Parallel()

	binding := testBinding(t)
	item, err := binding.MarshalTXTItem()
	if err != nil {
		t.Fatalf("marshal TXT item: %v", err)
	}

	got, err := FindBindingTXT([][]byte{
		[]byte("ordinary text"),
		item,
		[]byte("another item"),
	})
	if err != nil {
		t.Fatalf("find binding: %v", err)
	}
	if got != binding {
		t.Fatal("found binding differs from encoded binding")
	}

	if _, err := FindBindingTXT([][]byte{[]byte("ordinary text")}); !errors.Is(
		err,
		ErrBindingNotFound,
	) {
		t.Fatalf("missing binding error = %v", err)
	}
	if _, err := FindBindingTXT([][]byte{item, item}); !errors.Is(
		err,
		ErrMultipleBindings,
	) {
		t.Fatalf("duplicate binding error = %v", err)
	}
}

func TestBindingTXTDiscriminatorIsExact(t *testing.T) {
	t.Parallel()

	if _, err := UnmarshalBindingTXTItem([]byte("cdns1")); !errors.Is(
		err,
		ErrBindingNotFound,
	) {
		t.Fatalf("lowercase discriminator error = %v", err)
	}
	if _, err := UnmarshalBindingTXTItem([]byte("CDNS2")); !errors.Is(
		err,
		ErrBindingNotFound,
	) {
		t.Fatalf("different version discriminator error = %v", err)
	}
	if _, err := UnmarshalBindingTXTItem([]byte(bindingTXTMagicV1)); err == nil {
		t.Fatal("empty CDNS1 payload succeeded")
	}
}

func TestBindingValidateForNameRejectsTransplant(t *testing.T) {
	t.Parallel()

	binding := testBinding(t)
	if err := binding.ValidateForName("different"); err == nil {
		t.Fatal("binding validated for a different name")
	}
}

func TestBindingValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*Binding)
	}{
		{
			name: "version",
			mutate: func(binding *Binding) {
				binding.Version++
			},
		},
		{
			name: "Handshake network",
			mutate: func(binding *Binding) {
				binding.HandshakeNetwork = HandshakeNetworkTestnet
			},
		},
		{
			name: "name hash",
			mutate: func(binding *Binding) {
				binding.NameHash = HandshakeNameHash{}
			},
		},
		{
			name: "Cardano network ID",
			mutate: func(binding *Binding) {
				binding.CardanoNetworkID = MaxCardanoNetworkID + 1
			},
		},
		{
			name: "protocol policy ID",
			mutate: func(binding *Binding) {
				binding.ProtocolPolicyID = CardanoPolicyID{}
			},
		},
		{
			name: "controller kind",
			mutate: func(binding *Binding) {
				binding.ControllerKind = 2
			},
		},
		{
			name: "controller credential",
			mutate: func(binding *Binding) {
				binding.ControllerCredential = CardanoCredentialHash{}
			},
		},
		{
			name: "generation nonce",
			mutate: func(binding *Binding) {
				binding.GenerationNonce = Digest{}
			},
		},
		{
			name: "flags",
			mutate: func(binding *Binding) {
				binding.Flags = 1
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			binding := testBinding(t)
			test.mutate(&binding)
			if err := binding.Validate(); err == nil {
				t.Fatal("Validate succeeded")
			}
			if _, err := binding.MarshalTXTItem(); err == nil {
				t.Fatal("MarshalTXTItem succeeded")
			}
		})
	}
}

func TestUnmarshalBindingRejectsInvalidLengths(t *testing.T) {
	t.Parallel()

	binding := testBinding(t)
	wire := binding.wire()
	wire.ControllerCredential = wire.ControllerCredential[:27]
	data, err := encMode.Marshal(wire)
	if err != nil {
		t.Fatalf("marshal malformed wire: %v", err)
	}
	if _, err := UnmarshalBinding(data); err == nil {
		t.Fatal("short controller credential succeeded")
	}
}

func TestUnmarshalBindingRejectsNonCanonicalCBOR(t *testing.T) {
	t.Parallel()

	payload, err := testBinding(t).MarshalBinary()
	if err != nil {
		t.Fatalf("marshal binding: %v", err)
	}
	if len(payload) < 2 || payload[1] != 0x01 {
		t.Fatalf("unexpected canonical prefix %x", payload[:2])
	}
	nonCanonical := make([]byte, 0, len(payload)+1)
	nonCanonical = append(nonCanonical, payload[0], 0x18, 0x01)
	nonCanonical = append(nonCanonical, payload[2:]...)

	_, err = UnmarshalBinding(nonCanonical)
	if !errors.Is(err, ErrNonCanonicalCBOR) {
		t.Fatalf("non-canonical binding error = %v", err)
	}
}

func TestUnmarshalBindingRejectsOversize(t *testing.T) {
	t.Parallel()

	data := make([]byte, MaxHandshakeTXTItemBytes-len(bindingTXTMagicV1)+1)
	if _, err := UnmarshalBinding(data); err == nil {
		t.Fatal("oversize binding succeeded")
	}
}

func TestBindingGoldenVector(t *testing.T) {
	t.Parallel()

	fixtureData, err := os.ReadFile("testdata/v1/binding.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var fixture struct {
		PresentationName         string `json:"presentation_name"`
		CanonicalName            string `json:"canonical_name"`
		NameHash                 string `json:"name_hash_hex"`
		Version                  uint64 `json:"version"`
		HandshakeNetwork         uint64 `json:"handshake_network"`
		CardanoNetworkMagic      uint32 `json:"cardano_network_magic"`
		CardanoNetworkID         uint8  `json:"cardano_network_id"`
		ProtocolPolicyID         string `json:"protocol_policy_id_hex"`
		ControllerKind           uint64 `json:"controller_kind"`
		ControllerCredential     string `json:"controller_credential_hex"`
		GenerationNonce          string `json:"generation_nonce_hex"`
		Flags                    uint64 `json:"flags"`
		ExpectedCBOR             string `json:"expected_cbor_hex"`
		ExpectedHandshakeTXTItem string `json:"expected_handshake_txt_item_hex"`
	}
	if err := json.Unmarshal(fixtureData, &fixture); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}

	binding := testBinding(t)
	canonical, err := CanonicalHandshakeTLD(fixture.PresentationName)
	if err != nil {
		t.Fatalf("canonicalize fixture name: %v", err)
	}
	if canonical != fixture.CanonicalName ||
		fixture.NameHash != hex.EncodeToString(binding.NameHash[:]) ||
		fixture.Version != binding.Version ||
		fixture.HandshakeNetwork != uint64(binding.HandshakeNetwork) ||
		fixture.CardanoNetworkMagic != binding.CardanoNetworkMagic ||
		fixture.CardanoNetworkID != binding.CardanoNetworkID ||
		fixture.ProtocolPolicyID != hex.EncodeToString(binding.ProtocolPolicyID[:]) ||
		fixture.ControllerKind != uint64(binding.ControllerKind) ||
		fixture.ControllerCredential != hex.EncodeToString(
			binding.ControllerCredential[:],
		) ||
		fixture.GenerationNonce != hex.EncodeToString(binding.GenerationNonce[:]) ||
		fixture.Flags != uint64(binding.Flags) {
		t.Fatal("golden vector inputs do not match the reference binding")
	}
	payload, err := binding.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal binding: %v", err)
	}
	item, err := binding.MarshalTXTItem()
	if err != nil {
		t.Fatalf("marshal TXT item: %v", err)
	}
	if got := hex.EncodeToString(payload); got != fixture.ExpectedCBOR {
		t.Fatalf("CBOR mismatch:\n got: %s\nwant: %s", got, fixture.ExpectedCBOR)
	}
	if got := hex.EncodeToString(item); got != fixture.ExpectedHandshakeTXTItem {
		t.Fatalf(
			"TXT item mismatch:\n got: %s\nwant: %s",
			got,
			fixture.ExpectedHandshakeTXTItem,
		)
	}
}

func FuzzUnmarshalBindingTXTItem(f *testing.F) {
	binding := testBindingForFuzz(f)
	item, err := binding.MarshalTXTItem()
	if err != nil {
		f.Fatalf("marshal seed binding: %v", err)
	}
	f.Add(item)
	f.Add([]byte(bindingTXTMagicV1))
	f.Add([]byte("ordinary text"))

	f.Fuzz(func(t *testing.T, data []byte) {
		decoded, err := UnmarshalBindingTXTItem(data)
		if err != nil {
			return
		}
		reencoded, err := decoded.MarshalTXTItem()
		if err != nil {
			t.Fatalf("re-encode accepted binding: %v", err)
		}
		if !bytes.Equal(data, reencoded) {
			t.Fatal("accepted binding was not canonical")
		}
	})
}

type testingTB interface {
	Helper()
	Fatalf(string, ...any)
}

func testBinding(t testingTB) Binding {
	t.Helper()
	return testBindingForFuzz(t)
}

func testBindingForFuzz(t testingTB) Binding {
	t.Helper()
	nameHash, err := HashHandshakeName("example1")
	if err != nil {
		t.Fatalf("hash test name: %v", err)
	}
	return Binding{
		Version:              BindingVersionV1,
		HandshakeNetwork:     HandshakeNetworkMainnet,
		NameHash:             nameHash,
		CardanoNetworkMagic:  764824073,
		CardanoNetworkID:     1,
		ProtocolPolicyID:     policyIDSequence(0x22),
		ControllerKind:       ControllerKindScript,
		ControllerCredential: filledCredential(0x33),
		GenerationNonce:      digestSequence(0x44),
	}
}

func filledCredential(value byte) CardanoCredentialHash {
	var credential CardanoCredentialHash
	for i := range credential {
		credential[i] = value
	}
	return credential
}

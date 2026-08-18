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
	"testing"
)

func TestNameAuthorityRoundTripAndDigest(t *testing.T) {
	t.Parallel()
	authority := testNameAuthority()
	encoded, err := authority.MarshalCBOR()
	if err != nil {
		t.Fatalf("marshal authority: %v", err)
	}
	decoded, err := UnmarshalNameAuthority(encoded)
	if err != nil {
		t.Fatalf("unmarshal authority: %v", err)
	}
	if decoded.Version != authority.Version ||
		decoded.Kind != authority.Kind ||
		decoded.Class != authority.Class ||
		decoded.NetworkID != authority.NetworkID ||
		!bytes.Equal(decoded.CanonicalWireName, authority.CanonicalWireName) ||
		decoded.ParentDigest != authority.ParentDigest {
		t.Fatalf("round trip mismatch: %#v", decoded)
	}
	digest, err := authority.Digest()
	if err != nil {
		t.Fatalf("digest authority: %v", err)
	}
	fixture := loadAuthorityFixture(t)
	assertHex(t, "authority CBOR", encoded, fixture.NameAuthority.ExpectedCBOR)
	assertHex(t, "authority digest", digest[:], fixture.NameAuthority.ExpectedDigest)
}

func TestNameAuthoritySeparatesRoots(t *testing.T) {
	t.Parallel()
	icann := testNameAuthority()
	handshake := icann
	handshake.Kind = AuthorityKindHandshake
	icannDigest, err := icann.Digest()
	if err != nil {
		t.Fatalf("digest ICANN authority: %v", err)
	}
	handshakeDigest, err := handshake.Digest()
	if err != nil {
		t.Fatalf("digest Handshake authority: %v", err)
	}
	if icannDigest == handshakeDigest {
		t.Fatal("identical name in independent roots has identical digest")
	}
}

func TestNameAuthorityValidation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*NameAuthority)
	}{
		{
			name: "version",
			mutate: func(a *NameAuthority) {
				a.Version = 2
			},
		},
		{
			name: "kind",
			mutate: func(a *NameAuthority) {
				a.Kind = 3
			},
		},
		{
			name: "network",
			mutate: func(a *NameAuthority) {
				a.NetworkID = Digest{}
			},
		},
		{"class", func(a *NameAuthority) { a.Class = 3 }},
		{
			name: "wrong ICANN network",
			mutate: func(a *NameAuthority) {
				a.NetworkID = digestSequence(0x10)
			},
		},
		{
			name: "TLD parent",
			mutate: func(a *NameAuthority) {
				a.ParentDigest = digestSequence(0x30)
			},
		},
		{
			name: "TLD label count",
			mutate: func(a *NameAuthority) {
				a.CanonicalWireName = []byte{
					3, 'w', 'w', 'w',
					3, 'a', 'd', 'a',
					0,
				}
			},
		},
		{
			name: "missing root",
			mutate: func(a *NameAuthority) {
				a.CanonicalWireName = []byte{3, 'a', 'd', 'a'}
			},
		},
		{
			name: "upper case",
			mutate: func(a *NameAuthority) {
				a.CanonicalWireName = []byte{3, 'A', 'd', 'a', 0}
			},
		},
		{
			name: "non ASCII",
			mutate: func(a *NameAuthority) {
				a.CanonicalWireName = []byte{2, 0xc3, 0xa9, 0}
			},
		},
		{
			name: "non A-label byte",
			mutate: func(a *NameAuthority) {
				a.CanonicalWireName = []byte{3, 'a', '_', 'a', 0}
			},
		},
		{
			name: "leading hyphen",
			mutate: func(a *NameAuthority) {
				a.CanonicalWireName = []byte{3, '-', 'a', 'a', 0}
			},
		},
		{
			name: "compression pointer",
			mutate: func(a *NameAuthority) {
				a.CanonicalWireName = []byte{0xc0, 0}
			},
		},
		{
			name: "bytes after root",
			mutate: func(a *NameAuthority) {
				a.CanonicalWireName = []byte{3, 'a', 'd', 'a', 0, 0}
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			value := testNameAuthority()
			test.mutate(&value)
			if err := value.Validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestNameAuthoritySLDParentBinding(t *testing.T) {
	t.Parallel()
	parent := testNameAuthority()
	parentDigest, err := parent.Digest()
	if err != nil {
		t.Fatalf("digest parent: %v", err)
	}
	child := NameAuthority{
		Version:      NameAuthorityVersionV1,
		Kind:         AuthorityKindICANNDNS,
		Class:        NameClassSLD,
		NetworkID:    ICANNRootNetworkIDV1(),
		ParentDigest: parentDigest,
		CanonicalWireName: []byte{
			3, 'w', 'w', 'w',
			3, 'a', 'd', 'a',
			0,
		},
	}
	if err := child.Validate(); err != nil {
		t.Fatalf("validate SLD: %v", err)
	}
	child.ParentDigest = Digest{}
	if err := child.Validate(); err == nil {
		t.Fatal("SLD accepted a zero parent digest")
	}

	wrongName := parent
	wrongName.CanonicalWireName = []byte{3, 'c', 'o', 'm', 0}
	child.ParentDigest, err = wrongName.Digest()
	if err != nil {
		t.Fatalf("digest wrong-name parent: %v", err)
	}
	if err := child.Validate(); err == nil {
		t.Fatal("SLD accepted a parent digest for a different suffix")
	}

	wrongKind := parent
	wrongKind.Kind = AuthorityKindHandshake
	wrongKind.NetworkID = digestSequence(0xe0)
	child.ParentDigest, err = wrongKind.Digest()
	if err != nil {
		t.Fatalf("digest wrong-kind parent: %v", err)
	}
	if err := child.Validate(); err == nil {
		t.Fatal("SLD accepted a parent digest from a different authority")
	}
}

func TestCIP113RepresentationRoundTripAndDigest(t *testing.T) {
	t.Parallel()
	value := testCIP113Representation()
	encoded, err := value.MarshalCBOR()
	if err != nil {
		t.Fatalf("marshal representation: %v", err)
	}
	decoded, err := UnmarshalCIP113Representation(encoded)
	if err != nil {
		t.Fatalf("unmarshal representation: %v", err)
	}
	if decoded.Version != value.Version ||
		decoded.NameAuthorityDigest != value.NameAuthorityDigest ||
		decoded.CardanoNetworkID != value.CardanoNetworkID ||
		decoded.CardanoNetworkMagic != value.CardanoNetworkMagic ||
		decoded.CardanoByronGenesisHash != value.CardanoByronGenesisHash ||
		decoded.CardanoShelleyGenesisHash !=
			value.CardanoShelleyGenesisHash ||
		decoded.ProtocolConfigPolicyID != value.ProtocolConfigPolicyID ||
		!bytes.Equal(
			decoded.ProtocolConfigAssetName,
			value.ProtocolConfigAssetName,
		) ||
		decoded.RegistryPolicyID != value.RegistryPolicyID ||
		decoded.RegistryNodeLogicDigest != value.RegistryNodeLogicDigest ||
		decoded.TokenPolicyID != value.TokenPolicyID ||
		!bytes.Equal(decoded.AssetName, value.AssetName) ||
		decoded.DomainStatePolicyID != value.DomainStatePolicyID ||
		!bytes.Equal(decoded.DomainStateAssetName, value.DomainStateAssetName) ||
		decoded.DomainStateValidator != value.DomainStateValidator ||
		decoded.ProfileDigest != value.ProfileDigest {
		t.Fatalf("round trip mismatch: %#v", decoded)
	}
	digest, err := value.Digest()
	if err != nil {
		t.Fatalf("digest representation: %v", err)
	}
	fixture := loadAuthorityFixture(t)
	assertHex(t, "representation CBOR", encoded, fixture.Representation.ExpectedCBOR)
	assertHex(t, "representation digest", digest[:], fixture.Representation.ExpectedDigest)
}

func TestCIP113RepresentationValidation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*CIP113Representation)
	}{
		{"version", func(v *CIP113Representation) { v.Version = 2 }},
		{
			"name authority",
			func(v *CIP113Representation) {
				v.NameAuthorityDigest = Digest{}
			},
		},
		{
			"Cardano network ID",
			func(v *CIP113Representation) {
				v.CardanoNetworkID = 16
			},
		},
		{
			"Cardano Byron genesis",
			func(v *CIP113Representation) {
				v.CardanoByronGenesisHash = Digest{}
			},
		},
		{
			"Cardano Shelley genesis",
			func(v *CIP113Representation) {
				v.CardanoShelleyGenesisHash = Digest{}
			},
		},
		{
			"protocol policy",
			func(v *CIP113Representation) {
				v.ProtocolConfigPolicyID = CardanoPolicyID{}
			},
		},
		{
			"protocol config asset",
			func(v *CIP113Representation) {
				v.ProtocolConfigAssetName = nil
			},
		},
		{
			"long protocol config asset",
			func(v *CIP113Representation) {
				v.ProtocolConfigAssetName = make(
					[]byte,
					MaxCardanoAssetNameBytes+1,
				)
			},
		},
		{
			"registry policy",
			func(v *CIP113Representation) {
				v.RegistryPolicyID = CardanoPolicyID{}
			},
		},
		{
			"registry node logic",
			func(v *CIP113Representation) {
				v.RegistryNodeLogicDigest = Digest{}
			},
		},
		{
			"token policy",
			func(v *CIP113Representation) {
				v.TokenPolicyID = CardanoPolicyID{}
			},
		},
		{
			"domain state validator kind",
			func(v *CIP113Representation) {
				v.DomainStateValidator.Kind =
					CardanoCredentialVerificationKey
			},
		},
		{
			"domain state validator hash",
			func(v *CIP113Representation) {
				v.DomainStateValidator.Hash = CardanoCredentialHash{}
			},
		},
		{"empty asset", func(v *CIP113Representation) { v.AssetName = nil }},
		{
			"long asset",
			func(v *CIP113Representation) {
				v.AssetName = make([]byte, MaxCardanoAssetNameBytes+1)
			},
		},
		{
			"domain state policy",
			func(v *CIP113Representation) {
				v.DomainStatePolicyID = CardanoPolicyID{}
			},
		},
		{
			"empty domain state asset",
			func(v *CIP113Representation) {
				v.DomainStateAssetName = nil
			},
		},
		{
			"long domain state asset",
			func(v *CIP113Representation) {
				v.DomainStateAssetName = make(
					[]byte,
					MaxCardanoAssetNameBytes+1,
				)
			},
		},
		{
			"profile",
			func(v *CIP113Representation) {
				v.ProfileDigest = Digest{}
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			value := testCIP113Representation()
			test.mutate(&value)
			if err := value.Validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestCIP113RegistryNodeLogicRoundTripAndDigest(t *testing.T) {
	t.Parallel()
	value := testCIP113RegistryNodeLogic()
	encoded, err := value.MarshalCBOR()
	if err != nil {
		t.Fatalf("marshal registry node logic: %v", err)
	}
	decoded, err := UnmarshalCIP113RegistryNodeLogic(encoded)
	if err != nil {
		t.Fatalf("unmarshal registry node logic: %v", err)
	}
	if decoded != value {
		t.Fatalf("round trip mismatch: %#v", decoded)
	}
	digest, err := value.Digest()
	if err != nil {
		t.Fatalf("digest registry node logic: %v", err)
	}
	fixture := loadAuthorityFixture(t)
	assertHex(t, "registry node logic CBOR", encoded, fixture.RegistryNodeLogic.ExpectedCBOR)
	assertHex(t, "registry node logic digest", digest[:], fixture.RegistryNodeLogic.ExpectedDigest)
}

func TestCIP113RegistryNodeLogicValidation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*CIP113RegistryNodeLogic)
	}{
		{"version", func(v *CIP113RegistryNodeLogic) { v.Version = 2 }},
		{
			"token policy",
			func(v *CIP113RegistryNodeLogic) {
				v.TokenPolicyID = CardanoPolicyID{}
			},
		},
		{
			"minting logic",
			func(v *CIP113RegistryNodeLogic) {
				v.MintingLogic.Kind = CardanoCredentialVerificationKey
			},
		},
		{
			"transfer logic",
			func(v *CIP113RegistryNodeLogic) {
				v.TransferLogic.Hash = CardanoCredentialHash{}
			},
		},
		{
			"third-party logic",
			func(v *CIP113RegistryNodeLogic) {
				v.ThirdPartyLogic.Kind =
					CardanoCredentialVerificationKey
			},
		},
		{
			"global state",
			func(v *CIP113RegistryNodeLogic) {
				v.GlobalStatePolicyID = CardanoPolicyID{}
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			value := testCIP113RegistryNodeLogic()
			test.mutate(&value)
			if err := value.Validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestCIP113RepresentationRegistryNodeBinding(t *testing.T) {
	t.Parallel()
	representation := testCIP113Representation()
	node := testCIP113RegistryNodeLogic()
	if err := representation.ValidateRegistryNodeLogic(node); err != nil {
		t.Fatalf("validate registry node binding: %v", err)
	}

	wrongKey := node
	wrongKey.TokenPolicyID = policyIDSequence(0x11)
	if err := representation.ValidateRegistryNodeLogic(wrongKey); err == nil {
		t.Fatal("accepted registry node with wrong key")
	}

	wrongGlobalState := node
	wrongGlobalState.GlobalStatePolicyID = policyIDSequence(0x61)
	if err := representation.ValidateRegistryNodeLogic(
		wrongGlobalState,
	); err == nil {
		t.Fatal("accepted registry node with wrong global state")
	}

	wrongDigest := representation
	wrongDigest.RegistryNodeLogicDigest = digestSequence(0xee)
	if err := wrongDigest.ValidateRegistryNodeLogic(node); err == nil {
		t.Fatal("accepted registry node with wrong logic digest")
	}
}

func TestRejectNonCanonicalAuthorityCBOR(t *testing.T) {
	t.Parallel()
	authority := testNameAuthority()
	encoded, err := encMode.Marshal(authority.wire())
	if err != nil {
		t.Fatalf("marshal authority: %v", err)
	}
	// Version 1 encoded with a non-minimal additional-information width.
	nonCanonical := append([]byte(nil), encoded...)
	if len(nonCanonical) < 2 || nonCanonical[1] != 0x01 {
		t.Fatalf("unexpected canonical prefix: %x", nonCanonical[:2])
	}
	nonCanonical = append(
		append([]byte(nil), nonCanonical[:1]...),
		append([]byte{0x18, 0x01}, nonCanonical[2:]...)...,
	)
	_, err = UnmarshalNameAuthority(nonCanonical)
	if !errors.Is(err, ErrNonCanonicalCBOR) {
		t.Fatalf("expected ErrNonCanonicalCBOR, got %v", err)
	}
}

// authorityVector is one golden entry from testdata/v1/authority.json.
type authorityVector struct {
	ExpectedCBOR   string `json:"expected_cbor_hex"`
	ExpectedDigest string `json:"expected_digest_hex"`
}

// authorityFixture mirrors testdata/v1/authority.json.
type authorityFixture struct {
	ICANNRootNetworkID    string          `json:"icann_root_network_id_hex"`
	NameAuthority         authorityVector `json:"name_authority"`
	ICANNSLDAuthority     authorityVector `json:"icann_sld_authority"`
	HandshakeTLDAuthority authorityVector `json:"handshake_tld_authority"`
	HandshakeSLDAuthority authorityVector `json:"handshake_sld_authority"`
	Representation        authorityVector `json:"cip113_representation"`
	RegistryNodeLogic     authorityVector `json:"cip113_registry_node_logic"`
}

// loadAuthorityFixture is the single source of truth for the authority golden
// vectors. The round-trip tests below assert against it rather than repeating
// the same hex inline: this repository requires new vectors whenever an
// encoding changes, and two independent copies means an encoding change can be
// applied to one and silently leave the other inconsistent. The binding,
// binding-leaf, and checkpoint tests already take fixture-only vectors.
func loadAuthorityFixture(t *testing.T) authorityFixture {
	t.Helper()
	data, err := os.ReadFile("testdata/v1/authority.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var fixture authorityFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	return fixture
}

func TestAuthorityGoldenVectorFile(t *testing.T) {
	t.Parallel()
	fixture := loadAuthorityFixture(t)
	icannRootID := ICANNRootNetworkIDV1()
	if got := hex.EncodeToString(icannRootID[:]); got !=
		fixture.ICANNRootNetworkID {
		t.Fatalf(
			"ICANN root network ID mismatch:\n got: %s\nwant: %s",
			got,
			fixture.ICANNRootNetworkID,
		)
	}
	tests := []struct {
		name    string
		marshal func() ([]byte, error)
		digest  func() (Digest, error)
		vector  authorityVector
	}{
		{
			name:    "name authority",
			marshal: testNameAuthority().MarshalCBOR,
			digest:  testNameAuthority().Digest,
			vector:  fixture.NameAuthority,
		},
		{
			name:    "ICANN SLD authority",
			marshal: testICANNSLDAuthority(t).MarshalCBOR,
			digest:  testICANNSLDAuthority(t).Digest,
			vector:  fixture.ICANNSLDAuthority,
		},
		{
			name:    "Handshake TLD authority",
			marshal: testHandshakeTLDAuthority().MarshalCBOR,
			digest:  testHandshakeTLDAuthority().Digest,
			vector:  fixture.HandshakeTLDAuthority,
		},
		{
			name:    "Handshake SLD authority",
			marshal: testHandshakeSLDAuthority(t).MarshalCBOR,
			digest:  testHandshakeSLDAuthority(t).Digest,
			vector:  fixture.HandshakeSLDAuthority,
		},
		{
			name:    "CIP-113 representation",
			marshal: testCIP113Representation().MarshalCBOR,
			digest:  testCIP113Representation().Digest,
			vector:  fixture.Representation,
		},
		{
			name:    "CIP-113 registry node logic",
			marshal: testCIP113RegistryNodeLogic().MarshalCBOR,
			digest:  testCIP113RegistryNodeLogic().Digest,
			vector:  fixture.RegistryNodeLogic,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			encoded, err := test.marshal()
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			digest, err := test.digest()
			if err != nil {
				t.Fatalf("digest: %v", err)
			}
			if got := hex.EncodeToString(encoded); got != test.vector.ExpectedCBOR {
				t.Fatalf(
					"CBOR mismatch:\n got: %s\nwant: %s",
					got,
					test.vector.ExpectedCBOR,
				)
			}
			if got := hex.EncodeToString(digest[:]); got !=
				test.vector.ExpectedDigest {
				t.Fatalf(
					"digest mismatch:\n got: %s\nwant: %s",
					got,
					test.vector.ExpectedDigest,
				)
			}
		})
	}
}

func FuzzUnmarshalNameAuthority(f *testing.F) {
	value := testNameAuthority()
	data, err := value.MarshalCBOR()
	if err != nil {
		f.Fatalf("marshal seed: %v", err)
	}
	f.Add(data)
	f.Add([]byte{})
	f.Add([]byte{0x81, 0x01})
	f.Fuzz(func(t *testing.T, data []byte) {
		value, err := UnmarshalNameAuthority(data)
		if err != nil {
			return
		}
		assertCanonicalReencoding(t, data, value.MarshalCBOR)
	})
}

func FuzzUnmarshalCIP113Representation(f *testing.F) {
	value := testCIP113Representation()
	data, err := value.MarshalCBOR()
	if err != nil {
		f.Fatalf("marshal seed: %v", err)
	}
	f.Add(data)
	f.Add([]byte{})
	f.Add([]byte{0x81, 0x01})
	f.Fuzz(func(t *testing.T, data []byte) {
		value, err := UnmarshalCIP113Representation(data)
		if err != nil {
			return
		}
		assertCanonicalReencoding(t, data, value.MarshalCBOR)
	})
}

func FuzzUnmarshalCIP113RegistryNodeLogic(f *testing.F) {
	value := testCIP113RegistryNodeLogic()
	data, err := value.MarshalCBOR()
	if err != nil {
		f.Fatalf("marshal seed: %v", err)
	}
	f.Add(data)
	f.Add([]byte{})
	f.Add([]byte{0x81, 0x01})
	f.Fuzz(func(t *testing.T, data []byte) {
		value, err := UnmarshalCIP113RegistryNodeLogic(data)
		if err != nil {
			return
		}
		assertCanonicalReencoding(t, data, value.MarshalCBOR)
	})
}

func assertCanonicalReencoding(
	t *testing.T,
	original []byte,
	marshal func() ([]byte, error),
) {
	t.Helper()
	reencoded, err := marshal()
	if err != nil {
		t.Fatalf("re-encode accepted value: %v", err)
	}
	if !bytes.Equal(original, reencoded) {
		t.Fatal("accepted value was not canonical")
	}
}

func testNameAuthority() NameAuthority {
	return NameAuthority{
		Version:           NameAuthorityVersionV1,
		Kind:              AuthorityKindICANNDNS,
		Class:             NameClassTLD,
		NetworkID:         ICANNRootNetworkIDV1(),
		CanonicalWireName: []byte{3, 'a', 'd', 'a', 0},
	}
}

func testICANNSLDAuthority(t *testing.T) NameAuthority {
	t.Helper()
	parent := testNameAuthority()
	parentDigest, err := parent.Digest()
	if err != nil {
		t.Fatalf("digest ICANN parent: %v", err)
	}
	return NameAuthority{
		Version:      NameAuthorityVersionV1,
		Kind:         AuthorityKindICANNDNS,
		Class:        NameClassSLD,
		NetworkID:    ICANNRootNetworkIDV1(),
		ParentDigest: parentDigest,
		CanonicalWireName: []byte{
			3, 'w', 'w', 'w',
			3, 'a', 'd', 'a',
			0,
		},
	}
}

func testHandshakeTLDAuthority() NameAuthority {
	return NameAuthority{
		Version:           NameAuthorityVersionV1,
		Kind:              AuthorityKindHandshake,
		Class:             NameClassTLD,
		NetworkID:         digestSequence(0xc0),
		CanonicalWireName: []byte{3, 'a', 'd', 'a', 0},
	}
}

func testHandshakeSLDAuthority(t *testing.T) NameAuthority {
	t.Helper()
	parent := testHandshakeTLDAuthority()
	parentDigest, err := parent.Digest()
	if err != nil {
		t.Fatalf("digest Handshake parent: %v", err)
	}
	return NameAuthority{
		Version:      NameAuthorityVersionV1,
		Kind:         AuthorityKindHandshake,
		Class:        NameClassSLD,
		NetworkID:    parent.NetworkID,
		ParentDigest: parentDigest,
		CanonicalWireName: []byte{
			3, 'w', 'w', 'w',
			3, 'a', 'd', 'a',
			0,
		},
	}
}

func testCIP113Representation() CIP113Representation {
	assetName := digestSequence(0x70)
	domainStateAssetName := digestSequence(0x80)
	registryNodeDigest, err := testCIP113RegistryNodeLogic().Digest()
	if err != nil {
		panic(err)
	}
	return CIP113Representation{
		Version:                   CIP113RepresentationVersionV1,
		NameAuthorityDigest:       digestSequence(0x01),
		CardanoNetworkID:          1,
		CardanoNetworkMagic:       764824073,
		CardanoByronGenesisHash:   digestSequence(0x02),
		CardanoShelleyGenesisHash: digestSequence(0x03),
		ProtocolConfigPolicyID:    policyIDSequence(0x10),
		ProtocolConfigAssetName:   []byte("dns-config-v1"),
		RegistryPolicyID:          policyIDSequence(0x30),
		RegistryNodeLogicDigest:   registryNodeDigest,
		TokenPolicyID:             policyIDSequence(0x50),
		AssetName:                 assetName[:],
		DomainStatePolicyID:       policyIDSequence(0x60),
		DomainStateAssetName:      domainStateAssetName[:],
		DomainStateValidator: CardanoCredential{
			Kind: CardanoCredentialScript,
			Hash: credentialHashSequence(0xa0),
		},
		ProfileDigest: digestSequence(0x90),
	}
}

func testCIP113RegistryNodeLogic() CIP113RegistryNodeLogic {
	return CIP113RegistryNodeLogic{
		Version:       CIP113RegistryNodeLogicVersionV1,
		TokenPolicyID: policyIDSequence(0x50),
		MintingLogic: CardanoCredential{
			Kind: CardanoCredentialScript,
			Hash: credentialHashSequence(0x30),
		},
		TransferLogic: CardanoCredential{
			Kind: CardanoCredentialScript,
			Hash: credentialHashSequence(0x50),
		},
		ThirdPartyLogic: CardanoCredential{
			Kind: CardanoCredentialScript,
			Hash: credentialHashSequence(0x70),
		},
		GlobalStatePolicyID: policyIDSequence(0x60),
	}
}

func credentialHashSequence(start byte) CardanoCredentialHash {
	var ret CardanoCredentialHash
	for i := range ret {
		ret[i] = start + byte(i)
	}
	return ret
}

func assertHex(t *testing.T, name string, value []byte, expected string) {
	t.Helper()
	if expected == "" {
		t.Fatalf("%s golden missing; got %x", name, value)
	}
	decoded, err := hex.DecodeString(expected)
	if err != nil {
		t.Fatalf("decode %s golden: %v", name, err)
	}
	if !bytes.Equal(value, decoded) {
		t.Fatalf("%s mismatch:\n got %x\nwant %x", name, value, decoded)
	}
}

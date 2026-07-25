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

func TestBindingLeafRoundTrip(t *testing.T) {
	t.Parallel()

	leaf := testBindingLeaf(t)
	data, err := leaf.MarshalCBOR()
	if err != nil {
		t.Fatalf("marshal binding leaf: %v", err)
	}
	got, err := UnmarshalBindingLeaf(data)
	if err != nil {
		t.Fatalf("unmarshal binding leaf: %v", err)
	}
	if got != leaf {
		t.Fatalf("round trip mismatch:\n got: %#v\nwant: %#v", got, leaf)
	}
	if !got.Active() {
		t.Fatal("reference leaf is not active")
	}
	if err := got.ValidateActive(); err != nil {
		t.Fatalf("validate active leaf: %v", err)
	}
}

func TestBindingLeafLifecycle(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		registered bool
		expired    bool
		revoked    bool
		active     bool
	}{
		{
			name:       "active",
			registered: true,
			active:     true,
		},
		{
			name:   "not registered",
			active: false,
		},
		{
			name:       "expired",
			registered: true,
			expired:    true,
			active:     false,
		},
		{
			name:       "revoked",
			registered: true,
			revoked:    true,
			active:     false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			leaf := testBindingLeaf(t)
			leaf.Registered = test.registered
			leaf.Expired = test.expired
			leaf.Revoked = test.revoked
			if got := leaf.Active(); got != test.active {
				t.Fatalf("Active() = %t, want %t", got, test.active)
			}
			err := leaf.ValidateActive()
			if test.active && err != nil {
				t.Fatalf("ValidateActive: %v", err)
			}
			if !test.active && err == nil {
				t.Fatal("ValidateActive succeeded")
			}
		})
	}
}

func TestBindingLeafValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*BindingLeaf)
	}{
		{
			name: "version",
			mutate: func(leaf *BindingLeaf) {
				leaf.Version++
			},
		},
		{
			name: "binding",
			mutate: func(leaf *BindingLeaf) {
				leaf.Binding.Version++
			},
		},
		{
			name: "owner transaction ID",
			mutate: func(leaf *BindingLeaf) {
				leaf.OwnerTransactionID = Digest{}
			},
		},
		{
			name: "resource hash",
			mutate: func(leaf *BindingLeaf) {
				leaf.ResourceHash = Digest{}
			},
		},
		{
			name: "root commit height",
			mutate: func(leaf *BindingLeaf) {
				leaf.RootCommitHeight = 0
			},
		},
		{
			name: "root commit block hash",
			mutate: func(leaf *BindingLeaf) {
				leaf.RootCommitBlockHash = Digest{}
			},
		},
		{
			name: "transfer at commit",
			mutate: func(leaf *BindingLeaf) {
				leaf.TransferHeight = leaf.RootCommitHeight
			},
		},
		{
			name: "transfer after commit",
			mutate: func(leaf *BindingLeaf) {
				leaf.TransferHeight = leaf.RootCommitHeight + 1
			},
		},
		{
			name: "renewal at commit",
			mutate: func(leaf *BindingLeaf) {
				leaf.RenewalHeight = leaf.RootCommitHeight
			},
		},
		{
			name: "renewal after commit",
			mutate: func(leaf *BindingLeaf) {
				leaf.RenewalHeight = leaf.RootCommitHeight + 1
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			leaf := testBindingLeaf(t)
			test.mutate(&leaf)
			if err := leaf.Validate(); err == nil {
				t.Fatal("Validate succeeded")
			}
			if _, err := leaf.MarshalCBOR(); err == nil {
				t.Fatal("MarshalCBOR succeeded")
			}
		})
	}
}

func TestBindingLeafAllowsAbsentLifecycleHeights(t *testing.T) {
	t.Parallel()

	leaf := testBindingLeaf(t)
	leaf.TransferHeight = 0
	leaf.RenewalHeight = 0
	if err := leaf.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestBindingLeafDigestCoversEveryField(t *testing.T) {
	t.Parallel()

	base := testBindingLeaf(t)
	baseDigest, err := base.Digest()
	if err != nil {
		t.Fatalf("base digest: %v", err)
	}
	mutations := []func(*BindingLeaf){
		func(leaf *BindingLeaf) { leaf.Binding.GenerationNonce[0] ^= 0xff },
		func(leaf *BindingLeaf) { leaf.OwnerTransactionID[0] ^= 0xff },
		func(leaf *BindingLeaf) { leaf.OwnerOutputIndex++ },
		func(leaf *BindingLeaf) { leaf.ResourceHash[0] ^= 0xff },
		func(leaf *BindingLeaf) { leaf.Registered = false },
		func(leaf *BindingLeaf) { leaf.Expired = true },
		func(leaf *BindingLeaf) { leaf.Revoked = true },
		func(leaf *BindingLeaf) { leaf.TransferHeight++ },
		func(leaf *BindingLeaf) { leaf.RenewalHeight++ },
		func(leaf *BindingLeaf) { leaf.RootCommitHeight++ },
		func(leaf *BindingLeaf) { leaf.RootCommitBlockHash[0] ^= 0xff },
	}
	for i, mutate := range mutations {
		leaf := base
		mutate(&leaf)
		digest, err := leaf.Digest()
		if err != nil {
			t.Fatalf("mutation %d digest: %v", i, err)
		}
		if digest == baseDigest {
			t.Fatalf("mutation %d did not change digest", i)
		}
	}
}

func TestUnmarshalBindingLeafRejectsInvalidLengths(t *testing.T) {
	t.Parallel()

	wire := testBindingLeaf(t).wire()
	wire.OwnerTransactionID = wire.OwnerTransactionID[:31]
	data, err := encMode.Marshal(wire)
	if err != nil {
		t.Fatalf("marshal malformed wire: %v", err)
	}
	if _, err := UnmarshalBindingLeaf(data); err == nil {
		t.Fatal("short owner transaction ID succeeded")
	}
}

func TestUnmarshalBindingLeafRejectsNonCanonicalCBOR(t *testing.T) {
	t.Parallel()

	data, err := testBindingLeaf(t).MarshalCBOR()
	if err != nil {
		t.Fatalf("marshal binding leaf: %v", err)
	}
	if len(data) < 2 || data[1] != 0x01 {
		t.Fatalf("unexpected canonical prefix %x", data[:2])
	}
	nonCanonical := make([]byte, 0, len(data)+1)
	nonCanonical = append(nonCanonical, data[0], 0x18, 0x01)
	nonCanonical = append(nonCanonical, data[2:]...)

	_, err = UnmarshalBindingLeaf(nonCanonical)
	if !errors.Is(err, ErrNonCanonicalCBOR) {
		t.Fatalf("non-canonical binding leaf error = %v", err)
	}
}

func TestBindingLeafGoldenVector(t *testing.T) {
	t.Parallel()

	fixtureData, err := os.ReadFile("testdata/v1/binding-leaf.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var fixture struct {
		Version             uint64 `json:"version"`
		BindingNameHash     string `json:"binding_name_hash_hex"`
		OwnerTransactionID  string `json:"owner_transaction_id_hex"`
		OwnerOutputIndex    uint32 `json:"owner_output_index"`
		ResourceHash        string `json:"resource_hash_hex"`
		Registered          bool   `json:"registered"`
		Expired             bool   `json:"expired"`
		Revoked             bool   `json:"revoked"`
		TransferHeight      uint64 `json:"transfer_height"`
		RenewalHeight       uint64 `json:"renewal_height"`
		RootCommitHeight    uint64 `json:"root_commit_height"`
		RootCommitBlockHash string `json:"root_commit_block_hash_hex"`
		ExpectedCBOR        string `json:"expected_cbor_hex"`
		ExpectedDigest      string `json:"expected_digest_hex"`
	}
	if err := json.Unmarshal(fixtureData, &fixture); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}

	leaf := testBindingLeaf(t)
	if fixture.Version != leaf.Version ||
		fixture.BindingNameHash != hex.EncodeToString(leaf.Binding.NameHash[:]) ||
		fixture.OwnerTransactionID != hex.EncodeToString(
			leaf.OwnerTransactionID[:],
		) ||
		fixture.OwnerOutputIndex != leaf.OwnerOutputIndex ||
		fixture.ResourceHash != hex.EncodeToString(leaf.ResourceHash[:]) ||
		fixture.Registered != leaf.Registered ||
		fixture.Expired != leaf.Expired ||
		fixture.Revoked != leaf.Revoked ||
		fixture.TransferHeight != leaf.TransferHeight ||
		fixture.RenewalHeight != leaf.RenewalHeight ||
		fixture.RootCommitHeight != leaf.RootCommitHeight ||
		fixture.RootCommitBlockHash != hex.EncodeToString(
			leaf.RootCommitBlockHash[:],
		) {
		t.Fatal("golden vector inputs do not match the reference binding leaf")
	}
	data, err := leaf.MarshalCBOR()
	if err != nil {
		t.Fatalf("marshal binding leaf: %v", err)
	}
	digest, err := leaf.Digest()
	if err != nil {
		t.Fatalf("digest binding leaf: %v", err)
	}
	if got := hex.EncodeToString(data); got != fixture.ExpectedCBOR {
		t.Fatalf("CBOR mismatch:\n got: %s\nwant: %s", got, fixture.ExpectedCBOR)
	}
	if got := hex.EncodeToString(digest[:]); got != fixture.ExpectedDigest {
		t.Fatalf(
			"digest mismatch:\n got: %s\nwant: %s",
			got,
			fixture.ExpectedDigest,
		)
	}
}

func FuzzUnmarshalBindingLeaf(f *testing.F) {
	leaf := testBindingLeafForFuzz(f)
	data, err := leaf.MarshalCBOR()
	if err != nil {
		f.Fatalf("marshal seed binding leaf: %v", err)
	}
	f.Add(data)
	f.Add([]byte{})
	f.Add([]byte{0x81, 0x01})

	f.Fuzz(func(t *testing.T, data []byte) {
		decoded, err := UnmarshalBindingLeaf(data)
		if err != nil {
			return
		}
		reencoded, err := decoded.MarshalCBOR()
		if err != nil {
			t.Fatalf("re-encode accepted binding leaf: %v", err)
		}
		if !bytes.Equal(data, reencoded) {
			t.Fatal("accepted binding leaf was not canonical")
		}
	})
}

func testBindingLeaf(t testingTB) BindingLeaf {
	t.Helper()
	return testBindingLeafForFuzz(t)
}

func testBindingLeafForFuzz(t testingTB) BindingLeaf {
	t.Helper()
	return BindingLeaf{
		Version:             BindingLeafVersionV1,
		Binding:             testBinding(t),
		OwnerTransactionID:  digestSequence(0x70),
		OwnerOutputIndex:    2,
		ResourceHash:        digestSequence(0x90),
		Registered:          true,
		TransferHeight:      123000,
		RenewalHeight:       123100,
		RootCommitHeight:    123444,
		RootCommitBlockHash: digestSequence(0xb0),
	}
}

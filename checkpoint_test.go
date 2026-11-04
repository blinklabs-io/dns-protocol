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
	"os"
	"strings"
	"testing"
)

func TestCheckpointVoteRoundTrip(t *testing.T) {
	vote := testCheckpointVote()
	data, err := vote.MarshalCBOR()
	if err != nil {
		t.Fatalf("MarshalCBOR: %v", err)
	}
	decoded, err := UnmarshalCheckpointVote(data)
	if err != nil {
		t.Fatalf("UnmarshalCheckpointVote: %v", err)
	}
	if decoded != vote {
		t.Fatalf("decoded vote differs:\n got: %#v\nwant: %#v", decoded, vote)
	}
}

func TestCheckpointAgreementIgnoresDiagnostics(t *testing.T) {
	left := testCheckpointVote()
	right := left
	right.ImplementationID = "hsd"
	right.ImplementationVersion = "8.0.0"
	right.ObservedAtUnix++
	right.EvidenceURI = "https://mirror.example/checkpoint.car"

	leftDigest, err := left.AgreementDigest()
	if err != nil {
		t.Fatalf("left AgreementDigest: %v", err)
	}
	rightDigest, err := right.AgreementDigest()
	if err != nil {
		t.Fatalf("right AgreementDigest: %v", err)
	}
	if leftDigest != rightDigest {
		t.Fatalf("diagnostic fields changed agreement digest: %x != %x", leftDigest, rightDigest)
	}
	leftBody, err := left.MarshalCBOR()
	if err != nil {
		t.Fatalf("left MarshalCBOR: %v", err)
	}
	rightBody, err := right.MarshalCBOR()
	if err != nil {
		t.Fatalf("right MarshalCBOR: %v", err)
	}
	if bytes.Equal(leftBody, rightBody) {
		t.Fatal("diagnostic field changes did not change the transmitted body")
	}
}

func TestCheckpointAgreementBindsConsensusFields(t *testing.T) {
	base := testCheckpointVote()
	baseDigest, err := base.AgreementDigest()
	if err != nil {
		t.Fatalf("base AgreementDigest: %v", err)
	}
	tests := map[string]func(*CheckpointVote){
		"network": func(v *CheckpointVote) {
			v.HandshakeNetwork = HandshakeNetworkRegtest
		},
		"round": func(v *CheckpointVote) {
			v.Round++
		},
		"block hash": func(v *CheckpointVote) {
			v.RootCommitBlockHash[0] ^= 0xff
		},
		"name root": func(v *CheckpointVote) {
			v.HandshakeNameRoot[0] ^= 0xff
		},
		"binding root": func(v *CheckpointVote) {
			v.DNSBindingRoot[0] ^= 0xff
		},
		"policy": func(v *CheckpointVote) {
			v.FinalityPolicyDigest[0] ^= 0xff
		},
		"stake snapshot": func(v *CheckpointVote) {
			v.StakeSnapshotDigest[0] ^= 0xff
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			changed := base
			mutate(&changed)
			digest, err := changed.AgreementDigest()
			if err != nil {
				t.Fatalf("AgreementDigest: %v", err)
			}
			if digest == baseDigest {
				t.Fatal("consensus field change did not change agreement digest")
			}
		})
	}
}

func TestCheckpointVoteRejectsInvalidFields(t *testing.T) {
	tests := map[string]func(*CheckpointVote){
		"version": func(v *CheckpointVote) {
			v.ProtocolVersion = 2
		},
		"policy ID": func(v *CheckpointVote) {
			v.SignerPolicyID = CardanoPolicyID{}
		},
		"Handshake network": func(v *CheckpointVote) {
			v.HandshakeNetwork = 99
		},
		"uncommitted root": func(v *CheckpointVote) {
			v.RootCommitHeight = v.StateThroughHeight
		},
		"block hash": func(v *CheckpointVote) {
			v.RootCommitBlockHash = Digest{}
		},
		"chainwork": func(v *CheckpointVote) {
			v.RootCommitChainwork = Digest{}
		},
		"name root": func(v *CheckpointVote) {
			v.HandshakeNameRoot = Digest{}
		},
		"finality policy": func(v *CheckpointVote) {
			v.FinalityPolicyDigest = Digest{}
		},
		"evidence": func(v *CheckpointVote) {
			v.EvidenceBundleDigest = Digest{}
		},
		"snapshot": func(v *CheckpointVote) {
			v.StakeSnapshotDigest = Digest{}
		},
		"implementation ID": func(v *CheckpointVote) {
			v.ImplementationID = ""
		},
		"implementation version": func(v *CheckpointVote) {
			v.ImplementationVersion = strings.Repeat("v", MaxImplementationVersionBytes+1)
		},
		"timestamp": func(v *CheckpointVote) {
			v.ObservedAtUnix = 0
		},
		"evidence URI": func(v *CheckpointVote) {
			v.EvidenceURI = ""
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			vote := testCheckpointVote()
			mutate(&vote)
			if _, err := vote.MarshalCBOR(); err == nil {
				t.Fatal("MarshalCBOR unexpectedly succeeded")
			}
		})
	}
}

func TestCheckpointVoteRejectsWrongKind(t *testing.T) {
	wire := testCheckpointVote().wire()
	wire.MessageKind = 99
	data, err := encMode.Marshal(wire)
	if err != nil {
		t.Fatalf("encode wire: %v", err)
	}
	if _, err := UnmarshalCheckpointVote(data); err == nil {
		t.Fatal("wrong message kind unexpectedly succeeded")
	}
}

func TestCheckpointVoteRejectsWrongByteStringLengths(t *testing.T) {
	tests := map[string]func(*checkpointVoteWire){
		"policy ID": func(w *checkpointVoteWire) {
			w.SignerPolicyID = w.SignerPolicyID[:27]
		},
		"block hash": func(w *checkpointVoteWire) {
			w.RootCommitBlockHash = w.RootCommitBlockHash[:31]
		},
		"chainwork": func(w *checkpointVoteWire) {
			w.RootCommitChainwork = append(w.RootCommitChainwork, 0)
		},
		"name root": func(w *checkpointVoteWire) {
			w.HandshakeNameRoot = nil
		},
		"stake snapshot": func(w *checkpointVoteWire) {
			w.StakeSnapshotDigest = w.StakeSnapshotDigest[:31]
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			wire := testCheckpointVote().wire()
			mutate(&wire)
			data, err := encMode.Marshal(wire)
			if err != nil {
				t.Fatalf("encode wire: %v", err)
			}
			if _, err := UnmarshalCheckpointVote(data); err == nil {
				t.Fatal("invalid byte string length unexpectedly succeeded")
			}
		})
	}
}

func TestCheckpointVoteRejectsTrailingData(t *testing.T) {
	data, err := testCheckpointVote().MarshalCBOR()
	if err != nil {
		t.Fatalf("MarshalCBOR: %v", err)
	}
	data = append(data, 0)
	if _, err := UnmarshalCheckpointVote(data); err == nil {
		t.Fatal("trailing data unexpectedly succeeded")
	}
}

func TestCheckpointVoteRejectsNonCanonicalCBOR(t *testing.T) {
	data, err := testCheckpointVote().MarshalCBOR()
	if err != nil {
		t.Fatalf("MarshalCBOR: %v", err)
	}
	// The first field is protocol version 1. Canonical CBOR encodes it as 0x01;
	// 0x18 0x01 is an equivalent but non-canonical representation.
	if len(data) < 2 || data[1] != 0x01 {
		t.Fatalf("unexpected canonical prefix %x", data[:min(len(data), 2)])
	}
	nonCanonical := make([]byte, 0, len(data)+1)
	nonCanonical = append(nonCanonical, data[:1]...)
	nonCanonical = append(nonCanonical, 0x18, 0x01)
	nonCanonical = append(nonCanonical, data[2:]...)
	if _, err := UnmarshalCheckpointVote(nonCanonical); err == nil {
		t.Fatal("non-canonical encoding unexpectedly succeeded")
	}
}

func TestCheckpointVoteRejectsOversizeBody(t *testing.T) {
	data := make([]byte, MaxDMQMessageBodyBytes+1)
	if _, err := UnmarshalCheckpointVote(data); err == nil {
		t.Fatal("oversize body unexpectedly succeeded")
	}
}

func TestCheckpointVoteGoldenVector(t *testing.T) {
	fixtureData, err := os.ReadFile("testdata/v1/checkpoint-vote.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var fixture struct {
		ProtocolVersion          uint64 `json:"protocol_version"`
		MessageKind              uint64 `json:"message_kind"`
		CardanoNetworkMagic      uint32 `json:"cardano_network_magic"`
		SignerPolicyID           string `json:"signer_policy_id_hex"`
		HandshakeNetwork         uint64 `json:"handshake_network"`
		Round                    uint64 `json:"round"`
		StateThroughHeight       uint64 `json:"state_through_height"`
		RootCommitHeight         uint64 `json:"root_commit_height"`
		RootCommitBlockHash      string `json:"root_commit_block_hash_hex"`
		RootCommitChainwork      string `json:"root_commit_chainwork_hex"`
		HandshakeNameRoot        string `json:"handshake_name_root_hex"`
		DNSBindingRoot           string `json:"dns_binding_root_hex"`
		PreviousCheckpointDigest string `json:"previous_checkpoint_digest_hex"`
		FinalityPolicyDigest     string `json:"finality_policy_digest_hex"`
		EvidenceBundleDigest     string `json:"evidence_bundle_digest_hex"`
		CardanoStakeEpoch        uint64 `json:"cardano_stake_epoch"`
		StakeSnapshotDigest      string `json:"stake_snapshot_digest_hex"`
		ImplementationID         string `json:"implementation_id"`
		ImplementationVersion    string `json:"implementation_version"`
		ObservedAtUnix           uint64 `json:"observed_at_unix"`
		EvidenceURI              string `json:"evidence_uri"`
		ExpectedCBORHex          string `json:"expected_cbor_hex"`
		ExpectedAgreementHash    string `json:"expected_agreement_digest_hex"`
	}
	if err := json.Unmarshal(fixtureData, &fixture); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}

	vote := testCheckpointVote()
	if fixture.ProtocolVersion != vote.ProtocolVersion ||
		fixture.MessageKind != uint64(MessageKindCheckpointVote) ||
		fixture.CardanoNetworkMagic != vote.CardanoNetworkMagic ||
		fixture.SignerPolicyID != hex.EncodeToString(vote.SignerPolicyID[:]) ||
		fixture.HandshakeNetwork != uint64(vote.HandshakeNetwork) ||
		fixture.Round != vote.Round ||
		fixture.StateThroughHeight != vote.StateThroughHeight ||
		fixture.RootCommitHeight != vote.RootCommitHeight ||
		fixture.RootCommitBlockHash != hex.EncodeToString(vote.RootCommitBlockHash[:]) ||
		fixture.RootCommitChainwork != hex.EncodeToString(vote.RootCommitChainwork[:]) ||
		fixture.HandshakeNameRoot != hex.EncodeToString(vote.HandshakeNameRoot[:]) ||
		fixture.DNSBindingRoot != hex.EncodeToString(vote.DNSBindingRoot[:]) ||
		fixture.PreviousCheckpointDigest != hex.EncodeToString(vote.PreviousCheckpointDigest[:]) ||
		fixture.FinalityPolicyDigest != hex.EncodeToString(vote.FinalityPolicyDigest[:]) ||
		fixture.EvidenceBundleDigest != hex.EncodeToString(vote.EvidenceBundleDigest[:]) ||
		fixture.CardanoStakeEpoch != vote.CardanoStakeEpoch ||
		fixture.StakeSnapshotDigest != hex.EncodeToString(vote.StakeSnapshotDigest[:]) ||
		fixture.ImplementationID != vote.ImplementationID ||
		fixture.ImplementationVersion != vote.ImplementationVersion ||
		fixture.ObservedAtUnix != vote.ObservedAtUnix ||
		fixture.EvidenceURI != vote.EvidenceURI {
		t.Fatal("golden vector inputs do not match the reference vote")
	}
	data, err := vote.MarshalCBOR()
	if err != nil {
		t.Fatalf("MarshalCBOR: %v", err)
	}
	digest, err := vote.AgreementDigest()
	if err != nil {
		t.Fatalf("AgreementDigest: %v", err)
	}
	if got := hex.EncodeToString(data); got != fixture.ExpectedCBORHex {
		t.Fatalf("CBOR mismatch:\n got: %s\nwant: %s", got, fixture.ExpectedCBORHex)
	}
	if got := hex.EncodeToString(digest[:]); got != fixture.ExpectedAgreementHash {
		t.Fatalf(
			"digest mismatch:\n got: %s\nwant: %s",
			got,
			fixture.ExpectedAgreementHash,
		)
	}
}

func testCheckpointVote() CheckpointVote {
	return CheckpointVote{
		Checkpoint: Checkpoint{
			ProtocolVersion:          ProtocolVersionV1,
			CardanoNetworkMagic:      764824073,
			SignerPolicyID:           policyIDSequence(0x01),
			HandshakeNetwork:         HandshakeNetworkMainnet,
			Round:                    123456,
			StateThroughHeight:       123443,
			RootCommitHeight:         123444,
			RootCommitBlockHash:      digestSequence(0x20),
			RootCommitChainwork:      digestSequence(0x40),
			HandshakeNameRoot:        digestSequence(0x60),
			DNSBindingRoot:           digestSequence(0x80),
			PreviousCheckpointDigest: digestSequence(0xa0),
			FinalityPolicyDigest:     digestSequence(0xc0),
			EvidenceBundleDigest:     digestSequence(0x11),
			CardanoStakeEpoch:        600,
			StakeSnapshotDigest:      digestSequence(0x31),
		},
		ImplementationID:      "handshake-node",
		ImplementationVersion: "0.2.2-rc1",
		ObservedAtUnix:        1784916000,
		EvidenceURI:           "stoat://blake2b-256/abcdef",
	}
}

func digestSequence(start byte) Digest {
	var ret Digest
	for i := range ret {
		ret[i] = start + byte(i)
	}
	return ret
}

func policyIDSequence(start byte) CardanoPolicyID {
	var ret CardanoPolicyID
	for i := range ret {
		ret[i] = start + byte(i)
	}
	return ret
}

func FuzzUnmarshalCheckpointVote(f *testing.F) {
	valid, err := testCheckpointVote().MarshalCBOR()
	if err != nil {
		f.Fatalf("MarshalCBOR seed: %v", err)
	}
	f.Add(valid)
	f.Add([]byte{})
	f.Add([]byte{0x81, 0x01})
	f.Fuzz(func(t *testing.T, data []byte) {
		vote, err := UnmarshalCheckpointVote(data)
		if err != nil {
			return
		}
		canonical, err := vote.MarshalCBOR()
		if err != nil {
			t.Fatalf("accepted vote cannot be re-encoded: %v", err)
		}
		if !bytes.Equal(data, canonical) {
			t.Fatal("accepted vote was not canonical")
		}
	})
}

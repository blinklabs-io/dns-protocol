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

// Package dnsprotocol defines canonical wire formats shared by the
// decentralized DNS components.
package dnsprotocol

import (
	"bytes"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/blake2b"
)

const (
	// ProtocolVersionV1 is the first checkpoint attestation protocol version.
	ProtocolVersionV1 uint64 = 1

	// MaxDMQMessageBodyBytes is the CIP-0137 application body limit enforced by
	// dmq-lib. It is repeated here as a conformance guard, not transport policy.
	MaxDMQMessageBodyBytes = 2000

	MaxImplementationIDBytes      = 64
	MaxImplementationVersionBytes = 64
	MaxEvidenceURIBytes           = 256
)

const checkpointAgreementDomainV1 = "BLINK_DNS_HNS_CHECKPOINT_V1\x00"

var (
	// ErrNonCanonicalCBOR indicates that a message decoded successfully but
	// was not encoded in the one canonical form required for signing.
	ErrNonCanonicalCBOR = errors.New("non-canonical CBOR")
	encMode             cbor.EncMode
	decMode             cbor.DecMode
)

// MessageKind identifies the application message inside a CIP-0137 envelope.
type MessageKind uint64

const (
	MessageKindCheckpointVote MessageKind = 1
)

// HandshakeNetwork identifies a Handshake consensus network.
type HandshakeNetwork uint64

const (
	HandshakeNetworkMainnet HandshakeNetwork = iota
	HandshakeNetworkRegtest
	HandshakeNetworkTestnet
	HandshakeNetworkSimnet
)

// Digest is a Blake2b-256 digest.
type Digest [32]byte

// CardanoPolicyID is a Cardano script hash.
type CardanoPolicyID [28]byte

// Checkpoint contains the fields over which SPOs agree. Every field is covered
// by AgreementDigest.
type Checkpoint struct {
	ProtocolVersion          uint64
	CardanoNetworkMagic      uint32
	SignerPolicyID           CardanoPolicyID
	HandshakeNetwork         HandshakeNetwork
	Round                    uint64
	StateThroughHeight       uint64
	RootCommitHeight         uint64
	RootCommitBlockHash      Digest
	RootCommitChainwork      Digest
	HandshakeNameRoot        Digest
	DNSBindingRoot           Digest
	PreviousCheckpointDigest Digest
	FinalityPolicyDigest     Digest
	EvidenceBundleDigest     Digest
	CardanoStakeEpoch        uint64
	StakeSnapshotDigest      Digest
}

// CheckpointVote is the compact application body carried by a CIP-0137
// KES/opcert envelope. Diagnostic fields identify the implementation and a
// content-addressed evidence location, but are excluded from AgreementDigest.
type CheckpointVote struct {
	Checkpoint
	ImplementationID      string
	ImplementationVersion string
	ObservedAtUnix        uint64
	EvidenceURI           string
}

type checkpointAgreementWire struct {
	_                        struct{} `cbor:",toarray"`
	ProtocolVersion          uint64
	MessageKind              uint64
	CardanoNetworkMagic      uint32
	SignerPolicyID           []byte
	HandshakeNetwork         uint64
	Round                    uint64
	StateThroughHeight       uint64
	RootCommitHeight         uint64
	RootCommitBlockHash      []byte
	RootCommitChainwork      []byte
	HandshakeNameRoot        []byte
	DNSBindingRoot           []byte
	PreviousCheckpointDigest []byte
	FinalityPolicyDigest     []byte
	EvidenceBundleDigest     []byte
	CardanoStakeEpoch        uint64
	StakeSnapshotDigest      []byte
}

type checkpointVoteWire struct {
	_                        struct{} `cbor:",toarray"`
	ProtocolVersion          uint64
	MessageKind              uint64
	CardanoNetworkMagic      uint32
	SignerPolicyID           []byte
	HandshakeNetwork         uint64
	Round                    uint64
	StateThroughHeight       uint64
	RootCommitHeight         uint64
	RootCommitBlockHash      []byte
	RootCommitChainwork      []byte
	HandshakeNameRoot        []byte
	DNSBindingRoot           []byte
	PreviousCheckpointDigest []byte
	FinalityPolicyDigest     []byte
	EvidenceBundleDigest     []byte
	CardanoStakeEpoch        uint64
	StakeSnapshotDigest      []byte
	ImplementationID         string
	ImplementationVersion    string
	ObservedAtUnix           uint64
	EvidenceURI              string
}

func init() {
	var err error
	encMode, err = cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		panic(fmt.Sprintf("create canonical CBOR encoder: %v", err))
	}
	decMode, err = (cbor.DecOptions{
		DupMapKey:         cbor.DupMapKeyEnforcedAPF,
		IndefLength:       cbor.IndefLengthForbidden,
		TagsMd:            cbor.TagsForbidden,
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
	}).DecMode()
	if err != nil {
		panic(fmt.Sprintf("create strict CBOR decoder: %v", err))
	}
}

// Validate checks the version 1 checkpoint invariants.
func (c Checkpoint) Validate() error {
	if c.ProtocolVersion != ProtocolVersionV1 {
		return fmt.Errorf("unsupported protocol version %d", c.ProtocolVersion)
	}
	if isZero(c.SignerPolicyID[:]) {
		return errors.New("signer policy ID must not be zero")
	}
	if c.HandshakeNetwork > HandshakeNetworkSimnet {
		return fmt.Errorf("unsupported Handshake network %d", c.HandshakeNetwork)
	}
	if c.RootCommitHeight <= c.StateThroughHeight {
		return fmt.Errorf(
			"root commit height %d must be after state-through height %d",
			c.RootCommitHeight,
			c.StateThroughHeight,
		)
	}
	if isZero(c.RootCommitBlockHash[:]) {
		return errors.New("root commit block hash must not be zero")
	}
	if isZero(c.RootCommitChainwork[:]) {
		return errors.New("root commit chainwork must not be zero")
	}
	if isZero(c.HandshakeNameRoot[:]) {
		return errors.New("Handshake name root must not be zero")
	}
	if isZero(c.FinalityPolicyDigest[:]) {
		return errors.New("finality policy digest must not be zero")
	}
	if isZero(c.EvidenceBundleDigest[:]) {
		return errors.New("evidence bundle digest must not be zero")
	}
	if isZero(c.StakeSnapshotDigest[:]) {
		return errors.New("stake snapshot digest must not be zero")
	}
	return nil
}

// Validate checks the checkpoint and bounded diagnostic fields.
func (v CheckpointVote) Validate() error {
	if err := v.Checkpoint.Validate(); err != nil {
		return err
	}
	if err := validateText("implementation ID", v.ImplementationID, MaxImplementationIDBytes, false); err != nil {
		return err
	}
	if err := validateText(
		"implementation version",
		v.ImplementationVersion,
		MaxImplementationVersionBytes,
		false,
	); err != nil {
		return err
	}
	if v.ObservedAtUnix == 0 {
		return errors.New("observation timestamp must not be zero")
	}
	if err := validateText("evidence URI", v.EvidenceURI, MaxEvidenceURIBytes, false); err != nil {
		return err
	}
	return nil
}

// AgreementBytes returns the canonical CBOR fields that all signers in a round
// must agree on. Diagnostic fields are deliberately excluded.
func (c Checkpoint) AgreementBytes() ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return encMode.Marshal(c.agreementWire())
}

// AgreementDigest returns the domain-separated Blake2b-256 digest of the
// canonical agreement bytes.
func (c Checkpoint) AgreementDigest() (Digest, error) {
	agreement, err := c.AgreementBytes()
	if err != nil {
		return Digest{}, err
	}
	payload := make([]byte, 0, len(checkpointAgreementDomainV1)+len(agreement))
	payload = append(payload, checkpointAgreementDomainV1...)
	payload = append(payload, agreement...)
	return blake2b.Sum256(payload), nil
}

// MarshalCBOR encodes a checkpoint vote in its canonical, fixed-array form.
func (v CheckpointVote) MarshalCBOR() ([]byte, error) {
	if err := v.Validate(); err != nil {
		return nil, err
	}
	data, err := encMode.Marshal(v.wire())
	if err != nil {
		return nil, fmt.Errorf("encode checkpoint vote: %w", err)
	}
	if len(data) > MaxDMQMessageBodyBytes {
		return nil, fmt.Errorf(
			"checkpoint vote is %d bytes, exceeds DMQ body limit %d",
			len(data),
			MaxDMQMessageBodyBytes,
		)
	}
	return data, nil
}

// UnmarshalCheckpointVote decodes a canonical version 1 checkpoint vote.
func UnmarshalCheckpointVote(data []byte) (CheckpointVote, error) {
	if len(data) == 0 {
		return CheckpointVote{}, errors.New("checkpoint vote is empty")
	}
	if len(data) > MaxDMQMessageBodyBytes {
		return CheckpointVote{}, fmt.Errorf(
			"checkpoint vote is %d bytes, exceeds DMQ body limit %d",
			len(data),
			MaxDMQMessageBodyBytes,
		)
	}
	var wire checkpointVoteWire
	if err := decMode.Unmarshal(data, &wire); err != nil {
		return CheckpointVote{}, fmt.Errorf("decode checkpoint vote: %w", err)
	}
	vote, err := checkpointVoteFromWire(wire)
	if err != nil {
		return CheckpointVote{}, err
	}
	canonical, err := vote.MarshalCBOR()
	if err != nil {
		return CheckpointVote{}, err
	}
	if !bytes.Equal(data, canonical) {
		return CheckpointVote{}, ErrNonCanonicalCBOR
	}
	return vote, nil
}

func (c Checkpoint) agreementWire() checkpointAgreementWire {
	return checkpointAgreementWire{
		ProtocolVersion:          c.ProtocolVersion,
		MessageKind:              uint64(MessageKindCheckpointVote),
		CardanoNetworkMagic:      c.CardanoNetworkMagic,
		SignerPolicyID:           clone(c.SignerPolicyID[:]),
		HandshakeNetwork:         uint64(c.HandshakeNetwork),
		Round:                    c.Round,
		StateThroughHeight:       c.StateThroughHeight,
		RootCommitHeight:         c.RootCommitHeight,
		RootCommitBlockHash:      clone(c.RootCommitBlockHash[:]),
		RootCommitChainwork:      clone(c.RootCommitChainwork[:]),
		HandshakeNameRoot:        clone(c.HandshakeNameRoot[:]),
		DNSBindingRoot:           clone(c.DNSBindingRoot[:]),
		PreviousCheckpointDigest: clone(c.PreviousCheckpointDigest[:]),
		FinalityPolicyDigest:     clone(c.FinalityPolicyDigest[:]),
		EvidenceBundleDigest:     clone(c.EvidenceBundleDigest[:]),
		CardanoStakeEpoch:        c.CardanoStakeEpoch,
		StakeSnapshotDigest:      clone(c.StakeSnapshotDigest[:]),
	}
}

func (v CheckpointVote) wire() checkpointVoteWire {
	c := v.Checkpoint
	return checkpointVoteWire{
		ProtocolVersion:          c.ProtocolVersion,
		MessageKind:              uint64(MessageKindCheckpointVote),
		CardanoNetworkMagic:      c.CardanoNetworkMagic,
		SignerPolicyID:           clone(c.SignerPolicyID[:]),
		HandshakeNetwork:         uint64(c.HandshakeNetwork),
		Round:                    c.Round,
		StateThroughHeight:       c.StateThroughHeight,
		RootCommitHeight:         c.RootCommitHeight,
		RootCommitBlockHash:      clone(c.RootCommitBlockHash[:]),
		RootCommitChainwork:      clone(c.RootCommitChainwork[:]),
		HandshakeNameRoot:        clone(c.HandshakeNameRoot[:]),
		DNSBindingRoot:           clone(c.DNSBindingRoot[:]),
		PreviousCheckpointDigest: clone(c.PreviousCheckpointDigest[:]),
		FinalityPolicyDigest:     clone(c.FinalityPolicyDigest[:]),
		EvidenceBundleDigest:     clone(c.EvidenceBundleDigest[:]),
		CardanoStakeEpoch:        c.CardanoStakeEpoch,
		StakeSnapshotDigest:      clone(c.StakeSnapshotDigest[:]),
		ImplementationID:         v.ImplementationID,
		ImplementationVersion:    v.ImplementationVersion,
		ObservedAtUnix:           v.ObservedAtUnix,
		EvidenceURI:              v.EvidenceURI,
	}
}

func checkpointVoteFromWire(w checkpointVoteWire) (CheckpointVote, error) {
	if w.MessageKind != uint64(MessageKindCheckpointVote) {
		return CheckpointVote{}, fmt.Errorf("unexpected message kind %d", w.MessageKind)
	}
	policyID, err := cardanoPolicyID(w.SignerPolicyID)
	if err != nil {
		return CheckpointVote{}, err
	}
	commitHash, err := digest("root commit block hash", w.RootCommitBlockHash)
	if err != nil {
		return CheckpointVote{}, err
	}
	chainwork, err := digest("root commit chainwork", w.RootCommitChainwork)
	if err != nil {
		return CheckpointVote{}, err
	}
	nameRoot, err := digest("Handshake name root", w.HandshakeNameRoot)
	if err != nil {
		return CheckpointVote{}, err
	}
	bindingRoot, err := digest("DNS binding root", w.DNSBindingRoot)
	if err != nil {
		return CheckpointVote{}, err
	}
	previous, err := digest("previous checkpoint digest", w.PreviousCheckpointDigest)
	if err != nil {
		return CheckpointVote{}, err
	}
	finality, err := digest("finality policy digest", w.FinalityPolicyDigest)
	if err != nil {
		return CheckpointVote{}, err
	}
	evidence, err := digest("evidence bundle digest", w.EvidenceBundleDigest)
	if err != nil {
		return CheckpointVote{}, err
	}
	snapshot, err := digest("stake snapshot digest", w.StakeSnapshotDigest)
	if err != nil {
		return CheckpointVote{}, err
	}
	vote := CheckpointVote{
		Checkpoint: Checkpoint{
			ProtocolVersion:          w.ProtocolVersion,
			CardanoNetworkMagic:      w.CardanoNetworkMagic,
			SignerPolicyID:           policyID,
			HandshakeNetwork:         HandshakeNetwork(w.HandshakeNetwork),
			Round:                    w.Round,
			StateThroughHeight:       w.StateThroughHeight,
			RootCommitHeight:         w.RootCommitHeight,
			RootCommitBlockHash:      commitHash,
			RootCommitChainwork:      chainwork,
			HandshakeNameRoot:        nameRoot,
			DNSBindingRoot:           bindingRoot,
			PreviousCheckpointDigest: previous,
			FinalityPolicyDigest:     finality,
			EvidenceBundleDigest:     evidence,
			CardanoStakeEpoch:        w.CardanoStakeEpoch,
			StakeSnapshotDigest:      snapshot,
		},
		ImplementationID:      w.ImplementationID,
		ImplementationVersion: w.ImplementationVersion,
		ObservedAtUnix:        w.ObservedAtUnix,
		EvidenceURI:           w.EvidenceURI,
	}
	if err := vote.Validate(); err != nil {
		return CheckpointVote{}, err
	}
	return vote, nil
}

func digest(name string, value []byte) (Digest, error) {
	if len(value) != len(Digest{}) {
		return Digest{}, fmt.Errorf("%s must be 32 bytes, got %d", name, len(value))
	}
	var ret Digest
	copy(ret[:], value)
	return ret, nil
}

func cardanoPolicyID(value []byte) (CardanoPolicyID, error) {
	if len(value) != len(CardanoPolicyID{}) {
		return CardanoPolicyID{}, fmt.Errorf(
			"signer policy ID must be 28 bytes, got %d",
			len(value),
		)
	}
	var ret CardanoPolicyID
	copy(ret[:], value)
	return ret, nil
}

func validateText(name, value string, maxBytes int, allowEmpty bool) error {
	if !utf8.ValidString(value) {
		return fmt.Errorf("%s must be valid UTF-8", name)
	}
	if !allowEmpty && value == "" {
		return fmt.Errorf("%s must not be empty", name)
	}
	if len(value) > maxBytes {
		return fmt.Errorf("%s must not exceed %d bytes, got %d", name, maxBytes, len(value))
	}
	return nil
}

func isZero(value []byte) bool {
	for _, b := range value {
		if b != 0 {
			return false
		}
	}
	return true
}

func clone(value []byte) []byte {
	return append([]byte(nil), value...)
}

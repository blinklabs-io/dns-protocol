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
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/sha3"
)

const (
	// BindingVersionV1 is the first Handshake-to-Cardano binding version.
	BindingVersionV1 uint64 = 1

	// MaxHandshakeTXTItemBytes is the Handshake wire limit for one TXT item.
	MaxHandshakeTXTItemBytes = 255

	// MaxCardanoNetworkID is the largest network tag representable in a
	// Cardano address header.
	MaxCardanoNetworkID uint8 = 15
)

const bindingTXTMagicV1 = "CDNS1"

var (
	// ErrBindingNotFound indicates that no CDNS1 item was present.
	ErrBindingNotFound = errors.New("CDNS1 binding not found")

	// ErrMultipleBindings indicates that a TXT record contained more than one
	// CDNS1 item. Consumers must not choose between conflicting declarations.
	ErrMultipleBindings = errors.New("multiple CDNS1 bindings")
)

// ControllerKind identifies the Cardano credential that controls a bound
// zone.
type ControllerKind uint64

const (
	ControllerKindKey ControllerKind = iota
	ControllerKindScript
)

// BindingFlags is reserved for versioned capabilities. Version 1 defines no
// capability bits, so a valid version 1 binding has a zero value.
type BindingFlags uint64

// CardanoCredentialHash is a Cardano key or script credential hash.
type CardanoCredentialHash [28]byte

// HandshakeNameHash is the SHA3-256 consensus hash of a canonical Handshake
// name.
type HandshakeNameHash [32]byte

// Binding declares a Handshake owner's Cardano controller.
type Binding struct {
	Version              uint64
	HandshakeNetwork     HandshakeNetwork
	NameHash             HandshakeNameHash
	CardanoNetworkMagic  uint32
	CardanoNetworkID     uint8
	ProtocolPolicyID     CardanoPolicyID
	ControllerKind       ControllerKind
	ControllerCredential CardanoCredentialHash
	GenerationNonce      Digest
	Flags                BindingFlags
}

type bindingWire struct {
	_                    struct{} `cbor:",toarray"`
	Version              uint64
	HandshakeNetwork     uint64
	NameHash             []byte
	CardanoNetworkMagic  uint32
	CardanoNetworkID     uint8
	ProtocolPolicyID     []byte
	ControllerKind       uint64
	ControllerCredential []byte
	GenerationNonce      []byte
	Flags                uint64
}

// CanonicalHandshakeTLD converts a presentation-form Handshake TLD to the
// consensus name bytes used by HashName. ASCII case and one trailing root dot
// are normalized. Multi-label names, Unicode, and invalid Handshake label
// characters are rejected.
func CanonicalHandshakeTLD(name string) (string, error) {
	if strings.HasSuffix(name, ".") {
		name = strings.TrimSuffix(name, ".")
	}
	if name == "" {
		return "", errors.New("Handshake TLD is empty")
	}
	if strings.Contains(name, ".") {
		return "", errors.New("Handshake TLD must contain one label")
	}
	if len(name) > 63 {
		return "", fmt.Errorf("Handshake TLD is %d bytes, exceeds 63", len(name))
	}

	canonical := strings.ToLower(name)
	for i := range len(canonical) {
		ch := canonical[i]
		switch {
		case ch >= '0' && ch <= '9':
		case ch >= 'a' && ch <= 'z':
		case ch == '-' || ch == '_':
			if i == 0 || i == len(canonical)-1 {
				return "", errors.New(
					"Handshake TLD cannot start or end with '-' or '_'",
				)
			}
		default:
			return "", fmt.Errorf(
				"Handshake TLD contains invalid byte 0x%02x at offset %d",
				ch,
				i,
			)
		}
	}
	return canonical, nil
}

// HashHandshakeName returns the Handshake consensus SHA3-256 hash of the
// canonical TLD.
func HashHandshakeName(name string) (HandshakeNameHash, error) {
	canonical, err := CanonicalHandshakeTLD(name)
	if err != nil {
		return HandshakeNameHash{}, err
	}
	return HandshakeNameHash(sha3.Sum256([]byte(canonical))), nil
}

// Validate checks the version 1 binding invariants.
func (b Binding) Validate() error {
	if b.Version != BindingVersionV1 {
		return fmt.Errorf("unsupported binding version %d", b.Version)
	}
	switch b.HandshakeNetwork {
	case HandshakeNetworkMainnet, HandshakeNetworkRegtest:
	default:
		return fmt.Errorf(
			"unsupported binding Handshake network %d",
			b.HandshakeNetwork,
		)
	}
	if isZero(b.NameHash[:]) {
		return errors.New("Handshake name hash must not be zero")
	}
	if b.CardanoNetworkID > MaxCardanoNetworkID {
		return fmt.Errorf(
			"Cardano network ID %d exceeds %d",
			b.CardanoNetworkID,
			MaxCardanoNetworkID,
		)
	}
	if isZero(b.ProtocolPolicyID[:]) {
		return errors.New("protocol policy ID must not be zero")
	}
	switch b.ControllerKind {
	case ControllerKindKey, ControllerKindScript:
	default:
		return fmt.Errorf("unsupported controller kind %d", b.ControllerKind)
	}
	if isZero(b.ControllerCredential[:]) {
		return errors.New("controller credential must not be zero")
	}
	if isZero(b.GenerationNonce[:]) {
		return errors.New("generation nonce must not be zero")
	}
	if b.Flags != 0 {
		return fmt.Errorf("unsupported binding flags 0x%x", uint64(b.Flags))
	}
	return nil
}

// ValidateForName checks the binding and verifies that it is attached to the
// expected Handshake TLD.
func (b Binding) ValidateForName(name string) error {
	if err := b.Validate(); err != nil {
		return err
	}
	nameHash, err := HashHandshakeName(name)
	if err != nil {
		return err
	}
	if b.NameHash != nameHash {
		return errors.New("binding name hash does not match Handshake TLD")
	}
	return nil
}

// MarshalBinary returns the canonical CBOR binding payload without its TXT
// discriminator.
func (b Binding) MarshalBinary() ([]byte, error) {
	if err := b.Validate(); err != nil {
		return nil, err
	}
	data, err := encMode.Marshal(b.wire())
	if err != nil {
		return nil, fmt.Errorf("encode CDNS1 binding: %w", err)
	}
	if len(bindingTXTMagicV1)+len(data) > MaxHandshakeTXTItemBytes {
		return nil, fmt.Errorf(
			"CDNS1 TXT item is %d bytes, exceeds %d",
			len(bindingTXTMagicV1)+len(data),
			MaxHandshakeTXTItemBytes,
		)
	}
	return data, nil
}

// MarshalTXTItem returns one Handshake TXT item containing the CDNS1 magic
// followed by the canonical binary binding.
func (b Binding) MarshalTXTItem() ([]byte, error) {
	payload, err := b.MarshalBinary()
	if err != nil {
		return nil, err
	}
	item := make([]byte, 0, len(bindingTXTMagicV1)+len(payload))
	item = append(item, bindingTXTMagicV1...)
	item = append(item, payload...)
	return item, nil
}

// UnmarshalBinding decodes a canonical binary CDNS1 payload.
func UnmarshalBinding(data []byte) (Binding, error) {
	if len(data) == 0 {
		return Binding{}, errors.New("CDNS1 binding is empty")
	}
	if len(bindingTXTMagicV1)+len(data) > MaxHandshakeTXTItemBytes {
		return Binding{}, fmt.Errorf(
			"CDNS1 TXT item is %d bytes, exceeds %d",
			len(bindingTXTMagicV1)+len(data),
			MaxHandshakeTXTItemBytes,
		)
	}
	var wire bindingWire
	if err := decMode.Unmarshal(data, &wire); err != nil {
		return Binding{}, fmt.Errorf("decode CDNS1 binding: %w", err)
	}
	binding, err := bindingFromWire(wire)
	if err != nil {
		return Binding{}, err
	}
	canonical, err := binding.MarshalBinary()
	if err != nil {
		return Binding{}, err
	}
	if !bytes.Equal(data, canonical) {
		return Binding{}, ErrNonCanonicalCBOR
	}
	return binding, nil
}

// UnmarshalBindingTXTItem decodes one TXT item carrying a CDNS1 binding.
func UnmarshalBindingTXTItem(item []byte) (Binding, error) {
	if !bytes.HasPrefix(item, []byte(bindingTXTMagicV1)) {
		return Binding{}, ErrBindingNotFound
	}
	return UnmarshalBinding(item[len(bindingTXTMagicV1):])
}

// FindBindingTXT decodes the sole CDNS1 item in a Handshake TXT record.
func FindBindingTXT(items [][]byte) (Binding, error) {
	var (
		found   Binding
		matched bool
	)
	for _, item := range items {
		if !bytes.HasPrefix(item, []byte(bindingTXTMagicV1)) {
			continue
		}
		if matched {
			return Binding{}, ErrMultipleBindings
		}
		binding, err := UnmarshalBindingTXTItem(item)
		if err != nil {
			return Binding{}, err
		}
		found = binding
		matched = true
	}
	if !matched {
		return Binding{}, ErrBindingNotFound
	}
	return found, nil
}

func (b Binding) wire() bindingWire {
	return bindingWire{
		Version:              b.Version,
		HandshakeNetwork:     uint64(b.HandshakeNetwork),
		NameHash:             clone(b.NameHash[:]),
		CardanoNetworkMagic:  b.CardanoNetworkMagic,
		CardanoNetworkID:     b.CardanoNetworkID,
		ProtocolPolicyID:     clone(b.ProtocolPolicyID[:]),
		ControllerKind:       uint64(b.ControllerKind),
		ControllerCredential: clone(b.ControllerCredential[:]),
		GenerationNonce:      clone(b.GenerationNonce[:]),
		Flags:                uint64(b.Flags),
	}
}

func bindingFromWire(w bindingWire) (Binding, error) {
	binding := Binding{
		Version:             w.Version,
		HandshakeNetwork:    HandshakeNetwork(w.HandshakeNetwork),
		CardanoNetworkMagic: w.CardanoNetworkMagic,
		CardanoNetworkID:    w.CardanoNetworkID,
		ControllerKind:      ControllerKind(w.ControllerKind),
		Flags:               BindingFlags(w.Flags),
	}
	if err := copyFixed(
		"Handshake name hash",
		binding.NameHash[:],
		w.NameHash,
	); err != nil {
		return Binding{}, err
	}
	if err := copyFixed(
		"protocol policy ID",
		binding.ProtocolPolicyID[:],
		w.ProtocolPolicyID,
	); err != nil {
		return Binding{}, err
	}
	if err := copyFixed(
		"controller credential",
		binding.ControllerCredential[:],
		w.ControllerCredential,
	); err != nil {
		return Binding{}, err
	}
	if err := copyFixed(
		"generation nonce",
		binding.GenerationNonce[:],
		w.GenerationNonce,
	); err != nil {
		return Binding{}, err
	}
	if err := binding.Validate(); err != nil {
		return Binding{}, err
	}
	return binding, nil
}

func copyFixed(name string, destination, value []byte) error {
	if len(value) != len(destination) {
		return fmt.Errorf(
			"%s must be %d bytes, got %d",
			name,
			len(destination),
			len(value),
		)
	}
	copy(destination, value)
	return nil
}

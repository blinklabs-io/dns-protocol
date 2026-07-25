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

	"golang.org/x/crypto/blake2b"
)

const (
	// BindingLeafVersionV1 is the first certified binding leaf version.
	BindingLeafVersionV1 uint64 = 1
)

const bindingLeafDomainV1 = "BLINK_DNS_BINDING_LEAF_V1\x00"

// BindingLeaf combines an owner-published binding with the Handshake
// consensus facts that determine whether it is active at a committed name
// root.
type BindingLeaf struct {
	Version             uint64
	Binding             Binding
	OwnerTransactionID  Digest
	OwnerOutputIndex    uint32
	ResourceHash        Digest
	Registered          bool
	Expired             bool
	Revoked             bool
	TransferHeight      uint64
	RenewalHeight       uint64
	RootCommitHeight    uint64
	RootCommitBlockHash Digest
}

type bindingLeafWire struct {
	_                   struct{} `cbor:",toarray"`
	Version             uint64
	Binding             bindingWire
	OwnerTransactionID  []byte
	OwnerOutputIndex    uint32
	ResourceHash        []byte
	Registered          bool
	Expired             bool
	Revoked             bool
	TransferHeight      uint64
	RenewalHeight       uint64
	RootCommitHeight    uint64
	RootCommitBlockHash []byte
}

// Active reports whether the lifecycle fields select this binding for the
// active binding set.
func (l BindingLeaf) Active() bool {
	return l.Registered && !l.Expired && !l.Revoked
}

// Validate checks the version 1 binding leaf invariants.
func (l BindingLeaf) Validate() error {
	if l.Version != BindingLeafVersionV1 {
		return fmt.Errorf("unsupported binding leaf version %d", l.Version)
	}
	if err := l.Binding.Validate(); err != nil {
		return fmt.Errorf("binding: %w", err)
	}
	if isZero(l.OwnerTransactionID[:]) {
		return errors.New("owner transaction ID must not be zero")
	}
	if isZero(l.ResourceHash[:]) {
		return errors.New("resource hash must not be zero")
	}
	if l.RootCommitHeight == 0 {
		return errors.New("root commit height must not be zero")
	}
	if isZero(l.RootCommitBlockHash[:]) {
		return errors.New("root commit block hash must not be zero")
	}
	if l.TransferHeight >= l.RootCommitHeight && l.TransferHeight != 0 {
		return fmt.Errorf(
			"transfer height %d must be before root commit height %d",
			l.TransferHeight,
			l.RootCommitHeight,
		)
	}
	if l.RenewalHeight >= l.RootCommitHeight && l.RenewalHeight != 0 {
		return fmt.Errorf(
			"renewal height %d must be before root commit height %d",
			l.RenewalHeight,
			l.RootCommitHeight,
		)
	}
	return nil
}

// ValidateActive checks the leaf invariants and requires active lifecycle
// state.
func (l BindingLeaf) ValidateActive() error {
	if err := l.Validate(); err != nil {
		return err
	}
	if !l.Active() {
		return errors.New("binding leaf is not active")
	}
	return nil
}

// MarshalCBOR returns the canonical CBOR representation of a binding leaf.
func (l BindingLeaf) MarshalCBOR() ([]byte, error) {
	if err := l.Validate(); err != nil {
		return nil, err
	}
	data, err := encMode.Marshal(l.wire())
	if err != nil {
		return nil, fmt.Errorf("encode binding leaf: %w", err)
	}
	return data, nil
}

// UnmarshalBindingLeaf decodes a canonical version 1 binding leaf.
func UnmarshalBindingLeaf(data []byte) (BindingLeaf, error) {
	if len(data) == 0 {
		return BindingLeaf{}, errors.New("binding leaf is empty")
	}
	var wire bindingLeafWire
	if err := decMode.Unmarshal(data, &wire); err != nil {
		return BindingLeaf{}, fmt.Errorf("decode binding leaf: %w", err)
	}
	leaf, err := bindingLeafFromWire(wire)
	if err != nil {
		return BindingLeaf{}, err
	}
	canonical, err := leaf.MarshalCBOR()
	if err != nil {
		return BindingLeaf{}, err
	}
	if !bytes.Equal(data, canonical) {
		return BindingLeaf{}, ErrNonCanonicalCBOR
	}
	return leaf, nil
}

// Digest returns the domain-separated Blake2b-256 identity of the canonical
// binding leaf.
func (l BindingLeaf) Digest() (Digest, error) {
	data, err := l.MarshalCBOR()
	if err != nil {
		return Digest{}, err
	}
	payload := make([]byte, 0, len(bindingLeafDomainV1)+len(data))
	payload = append(payload, bindingLeafDomainV1...)
	payload = append(payload, data...)
	return blake2b.Sum256(payload), nil
}

func (l BindingLeaf) wire() bindingLeafWire {
	return bindingLeafWire{
		Version:             l.Version,
		Binding:             l.Binding.wire(),
		OwnerTransactionID:  clone(l.OwnerTransactionID[:]),
		OwnerOutputIndex:    l.OwnerOutputIndex,
		ResourceHash:        clone(l.ResourceHash[:]),
		Registered:          l.Registered,
		Expired:             l.Expired,
		Revoked:             l.Revoked,
		TransferHeight:      l.TransferHeight,
		RenewalHeight:       l.RenewalHeight,
		RootCommitHeight:    l.RootCommitHeight,
		RootCommitBlockHash: clone(l.RootCommitBlockHash[:]),
	}
}

func bindingLeafFromWire(w bindingLeafWire) (BindingLeaf, error) {
	binding, err := bindingFromWire(w.Binding)
	if err != nil {
		return BindingLeaf{}, fmt.Errorf("binding: %w", err)
	}
	leaf := BindingLeaf{
		Version:          w.Version,
		Binding:          binding,
		OwnerOutputIndex: w.OwnerOutputIndex,
		Registered:       w.Registered,
		Expired:          w.Expired,
		Revoked:          w.Revoked,
		TransferHeight:   w.TransferHeight,
		RenewalHeight:    w.RenewalHeight,
		RootCommitHeight: w.RootCommitHeight,
	}
	if err := copyFixed(
		"owner transaction ID",
		leaf.OwnerTransactionID[:],
		w.OwnerTransactionID,
	); err != nil {
		return BindingLeaf{}, err
	}
	if err := copyFixed(
		"resource hash",
		leaf.ResourceHash[:],
		w.ResourceHash,
	); err != nil {
		return BindingLeaf{}, err
	}
	if err := copyFixed(
		"root commit block hash",
		leaf.RootCommitBlockHash[:],
		w.RootCommitBlockHash,
	); err != nil {
		return BindingLeaf{}, err
	}
	if err := leaf.Validate(); err != nil {
		return BindingLeaf{}, err
	}
	return leaf, nil
}

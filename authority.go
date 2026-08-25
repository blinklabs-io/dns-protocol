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
	// NameAuthorityVersionV1 is the first typed name-authority schema.
	NameAuthorityVersionV1 uint64 = 1

	// CIP113RepresentationVersionV1 is the first programmable representation
	// reference schema.
	CIP113RepresentationVersionV1 uint64 = 1

	// CIP113RegistryNodeLogicVersionV1 is the first stable registry-node logic
	// schema. It excludes the mutable linked-list next pointer.
	CIP113RegistryNodeLogicVersionV1 uint64 = 1

	MaxCardanoAssetNameBytes = 32
)

const (
	nameAuthorityDomainV1        = "BLINK_DNS/NAME_AUTHORITY/V1\x00"
	cip113RepresentationDomainV1 = "BLINK_DNS/CIP113_REPRESENTATION/V1\x00"
	cip113RegistryLogicDomainV1  = "BLINK_DNS/CIP113_REGISTRY_LOGIC/V1\x00"
	icannRootNetworkDomainV1     = "BLINK_DNS/ICANN_IANA_ROOT/V1\x00"
)

// AuthorityKind selects the consensus or administrative root in which a DNS
// name exists. A Cardano token representation is deliberately not an
// authority kind.
type AuthorityKind uint64

const (
	AuthorityKindHandshake AuthorityKind = 1
	AuthorityKindICANNDNS  AuthorityKind = 2
)

// NameClass identifies a registrable name's level in its authority.
type NameClass uint64

const (
	NameClassTLD NameClass = 1
	NameClassSLD NameClass = 2
)

// NameAuthority identifies one canonical DNS name in one external namespace.
// CanonicalWireName is an uncompressed, lower-case DNS wire name with a
// terminal root label. Labels are LDH, except that Handshake permits an
// interior underscore in the final TLD label. Text-to-wire IDNA conversion is
// a separate protocol operation. For Handshake, NetworkID is the consensus
// genesis block hash in internal protocol byte order.
type NameAuthority struct {
	Version           uint64
	Kind              AuthorityKind
	Class             NameClass
	NetworkID         Digest
	CanonicalWireName []byte
	ParentDigest      Digest
}

// CIP113Representation identifies the programmable Cardano asset used as a
// control capability for a name. ProfileDigest binds the complete deployment
// and logic configuration.
type CIP113Representation struct {
	Version                   uint64
	NameAuthorityDigest       Digest
	CardanoNetworkID          uint8
	CardanoNetworkMagic       uint32
	CardanoByronGenesisHash   Digest
	CardanoShelleyGenesisHash Digest
	ProtocolConfigPolicyID    CardanoPolicyID
	ProtocolConfigAssetName   []byte
	RegistryPolicyID          CardanoPolicyID
	RegistryNodeLogicDigest   Digest
	TokenPolicyID             CardanoPolicyID
	AssetName                 []byte
	DomainStatePolicyID       CardanoPolicyID
	DomainStateAssetName      []byte
	DomainStateValidator      CardanoCredential
	ProfileDigest             Digest
}

// CIP113RegistryNodeLogic is the stable, security-relevant subset of a
// candidate CIP-113 registry node. TokenPolicyID is the node key. The mutable
// sorted-list next pointer is deliberately excluded.
type CIP113RegistryNodeLogic struct {
	Version             uint64
	TokenPolicyID       CardanoPolicyID
	MintingLogic        CardanoCredential
	TransferLogic       CardanoCredential
	ThirdPartyLogic     CardanoCredential
	GlobalStatePolicyID CardanoPolicyID
}

// CardanoCredentialKind distinguishes verification-key and script
// credentials. Candidate CIP-113 registry logic credentials support both.
type CardanoCredentialKind uint64

const (
	CardanoCredentialVerificationKey CardanoCredentialKind = 1
	CardanoCredentialScript          CardanoCredentialKind = 2
)

// CardanoCredential is a verification-key or script credential.
type CardanoCredential struct {
	Kind CardanoCredentialKind
	Hash CardanoCredentialHash
}

type nameAuthorityWire struct {
	_                 struct{} `cbor:",toarray"`
	Version           uint64
	Kind              uint64
	Class             uint64
	NetworkID         []byte
	CanonicalWireName []byte
	ParentDigest      []byte
}

type cip113RepresentationWire struct {
	_                         struct{} `cbor:",toarray"`
	Version                   uint64
	NameAuthorityDigest       []byte
	CardanoNetworkID          uint8
	CardanoNetworkMagic       uint32
	CardanoByronGenesisHash   []byte
	CardanoShelleyGenesisHash []byte
	ProtocolConfigPolicyID    []byte
	ProtocolConfigAssetName   []byte
	RegistryPolicyID          []byte
	RegistryNodeLogicDigest   []byte
	TokenPolicyID             []byte
	AssetName                 []byte
	DomainStatePolicyID       []byte
	DomainStateAssetName      []byte
	DomainStateValidator      cardanoCredentialWire
	ProfileDigest             []byte
}

type cip113RegistryNodeLogicWire struct {
	_                   struct{} `cbor:",toarray"`
	Version             uint64
	TokenPolicyID       []byte
	MintingLogic        cardanoCredentialWire
	TransferLogic       cardanoCredentialWire
	ThirdPartyLogic     cardanoCredentialWire
	GlobalStatePolicyID []byte
}

type cardanoCredentialWire struct {
	_    struct{} `cbor:",toarray"`
	Kind uint64
	Hash []byte
}

// Validate checks the version 1 name-authority invariants.
func (a NameAuthority) Validate() error {
	if a.Version != NameAuthorityVersionV1 {
		return fmt.Errorf("unsupported name authority version %d", a.Version)
	}
	if a.Kind != AuthorityKindHandshake && a.Kind != AuthorityKindICANNDNS {
		return fmt.Errorf("unsupported authority kind %d", a.Kind)
	}
	if isZero(a.NetworkID[:]) {
		return errors.New("authority network ID must not be zero")
	}
	if a.Kind == AuthorityKindICANNDNS && a.NetworkID != ICANNRootNetworkIDV1() {
		return errors.New("ICANN authority network ID is not the IANA root ID")
	}
	labelCount, err := canonicalWireNameLabelCount(a.CanonicalWireName, a.Kind)
	if err != nil {
		return fmt.Errorf("canonical wire name: %w", err)
	}
	switch a.Class {
	case NameClassTLD:
		if labelCount != 1 {
			return fmt.Errorf("TLD must contain one label, got %d", labelCount)
		}
		if !isZero(a.ParentDigest[:]) {
			return errors.New("TLD parent digest must be zero")
		}
	case NameClassSLD:
		if labelCount != 2 {
			return fmt.Errorf("SLD must contain two labels, got %d", labelCount)
		}
		if isZero(a.ParentDigest[:]) {
			return errors.New("SLD parent digest must not be zero")
		}
		expectedParent, err := a.expectedParentDigest()
		if err != nil {
			return err
		}
		if a.ParentDigest != expectedParent {
			return errors.New(
				"SLD parent digest does not match its authority and suffix",
			)
		}
	default:
		return fmt.Errorf("unsupported name class %d", a.Class)
	}
	return nil
}

func (a NameAuthority) expectedParentDigest() (Digest, error) {
	parentName, err := parentWireName(a.CanonicalWireName, a.Kind)
	if err != nil {
		return Digest{}, fmt.Errorf("derive SLD parent: %w", err)
	}
	parent := NameAuthority{
		Version:           a.Version,
		Kind:              a.Kind,
		Class:             NameClassTLD,
		NetworkID:         a.NetworkID,
		CanonicalWireName: parentName,
	}
	return parent.Digest()
}

// ICANNRootNetworkIDV1 returns the stable namespace ID for the
// IANA-coordinated DNS root. DNSSEC trust-anchor and observation policies are
// versioned separately and do not alter name identity.
func ICANNRootNetworkIDV1() Digest {
	return blake2b.Sum256([]byte(icannRootNetworkDomainV1))
}

// MarshalCBOR returns the canonical CBOR representation of a name authority.
func (a NameAuthority) MarshalCBOR() ([]byte, error) {
	if err := a.Validate(); err != nil {
		return nil, err
	}
	data, err := encMode.Marshal(a.wire())
	if err != nil {
		return nil, fmt.Errorf("encode name authority: %w", err)
	}
	return data, nil
}

// UnmarshalNameAuthority decodes a canonical version 1 name authority.
func UnmarshalNameAuthority(data []byte) (NameAuthority, error) {
	if len(data) == 0 {
		return NameAuthority{}, errors.New("name authority is empty")
	}
	var wire nameAuthorityWire
	if err := decMode.Unmarshal(data, &wire); err != nil {
		return NameAuthority{}, fmt.Errorf("decode name authority: %w", err)
	}
	a, err := nameAuthorityFromWire(wire)
	if err != nil {
		return NameAuthority{}, err
	}
	canonical, err := a.MarshalCBOR()
	if err != nil {
		return NameAuthority{}, err
	}
	if !bytes.Equal(data, canonical) {
		return NameAuthority{}, ErrNonCanonicalCBOR
	}
	return a, nil
}

// Digest returns the domain-separated identity of a name authority.
func (a NameAuthority) Digest() (Digest, error) {
	return canonicalDigest(nameAuthorityDomainV1, a.MarshalCBOR)
}

// Validate checks the programmable representation reference invariants.
func (r CIP113Representation) Validate() error {
	if r.Version != CIP113RepresentationVersionV1 {
		return fmt.Errorf(
			"unsupported CIP-113 representation version %d",
			r.Version,
		)
	}
	if isZero(r.NameAuthorityDigest[:]) {
		return errors.New("name authority digest must not be zero")
	}
	if r.CardanoNetworkID > 15 {
		return fmt.Errorf(
			"Cardano address network ID %d exceeds 15",
			r.CardanoNetworkID,
		)
	}
	if isZero(r.CardanoByronGenesisHash[:]) {
		return errors.New("Cardano Byron genesis hash must not be zero")
	}
	if isZero(r.CardanoShelleyGenesisHash[:]) {
		return errors.New("Cardano Shelley genesis hash must not be zero")
	}
	if isZero(r.ProtocolConfigPolicyID[:]) {
		return errors.New("protocol config policy ID must not be zero")
	}
	if err := validateAssetName(
		"protocol config asset name",
		r.ProtocolConfigAssetName,
	); err != nil {
		return err
	}
	if isZero(r.RegistryPolicyID[:]) {
		return errors.New("registry policy ID must not be zero")
	}
	if isZero(r.RegistryNodeLogicDigest[:]) {
		return errors.New("registry node logic digest must not be zero")
	}
	if isZero(r.TokenPolicyID[:]) {
		return errors.New("token policy ID must not be zero")
	}
	if err := validateAssetName("asset name", r.AssetName); err != nil {
		return err
	}
	if isZero(r.DomainStatePolicyID[:]) {
		return errors.New("domain state policy ID must not be zero")
	}
	if err := validateAssetName(
		"domain state asset name",
		r.DomainStateAssetName,
	); err != nil {
		return err
	}
	if err := r.DomainStateValidator.validateScript(
		"domain state validator",
	); err != nil {
		return err
	}
	if isZero(r.ProfileDigest[:]) {
		return errors.New("profile digest must not be zero")
	}
	return nil
}

// MarshalCBOR returns the canonical CBOR representation of a programmable
// representation reference.
func (r CIP113Representation) MarshalCBOR() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	data, err := encMode.Marshal(r.wire())
	if err != nil {
		return nil, fmt.Errorf("encode CIP-113 representation: %w", err)
	}
	return data, nil
}

// UnmarshalCIP113Representation decodes a canonical representation reference.
func UnmarshalCIP113Representation(
	data []byte,
) (CIP113Representation, error) {
	if len(data) == 0 {
		return CIP113Representation{}, errors.New(
			"CIP-113 representation is empty",
		)
	}
	var wire cip113RepresentationWire
	if err := decMode.Unmarshal(data, &wire); err != nil {
		return CIP113Representation{}, fmt.Errorf(
			"decode CIP-113 representation: %w",
			err,
		)
	}
	r, err := cip113RepresentationFromWire(wire)
	if err != nil {
		return CIP113Representation{}, err
	}
	canonical, err := r.MarshalCBOR()
	if err != nil {
		return CIP113Representation{}, err
	}
	if !bytes.Equal(data, canonical) {
		return CIP113Representation{}, ErrNonCanonicalCBOR
	}
	return r, nil
}

// Digest returns the domain-separated identity of a programmable
// representation reference.
func (r CIP113Representation) Digest() (Digest, error) {
	return canonicalDigest(cip113RepresentationDomainV1, r.MarshalCBOR)
}

// ValidateRegistryNodeLogic verifies that a stable registry-node logic object
// is the one bound by this representation. The node key must be the
// represented token policy, and its global state must be the external domain
// state policy.
func (r CIP113Representation) ValidateRegistryNodeLogic(
	node CIP113RegistryNodeLogic,
) error {
	if err := r.Validate(); err != nil {
		return err
	}
	if err := node.Validate(); err != nil {
		return err
	}
	if node.TokenPolicyID != r.TokenPolicyID {
		return errors.New(
			"registry node key does not match represented token policy",
		)
	}
	if node.GlobalStatePolicyID != r.DomainStatePolicyID {
		return errors.New(
			"registry global state does not match domain state policy",
		)
	}
	nodeDigest, err := node.Digest()
	if err != nil {
		return err
	}
	if nodeDigest != r.RegistryNodeLogicDigest {
		return errors.New("registry node logic digest does not match")
	}
	return nil
}

// Validate checks the stable registry-node logic invariants.
func (n CIP113RegistryNodeLogic) Validate() error {
	if n.Version != CIP113RegistryNodeLogicVersionV1 {
		return fmt.Errorf(
			"unsupported CIP-113 registry node logic version %d",
			n.Version,
		)
	}
	if isZero(n.TokenPolicyID[:]) {
		return errors.New("registry node token policy ID must not be zero")
	}
	credentials := []struct {
		name  string
		value CardanoCredential
	}{
		{"registry node minting logic", n.MintingLogic},
		{"registry node transfer logic", n.TransferLogic},
		{"registry node third-party logic", n.ThirdPartyLogic},
	}
	for _, credential := range credentials {
		if err := credential.value.validateScript(credential.name); err != nil {
			return err
		}
	}
	if isZero(n.GlobalStatePolicyID[:]) {
		return errors.New("registry node global state policy ID must not be zero")
	}
	return nil
}

// MarshalCBOR returns the canonical stable registry-node logic encoding.
func (n CIP113RegistryNodeLogic) MarshalCBOR() ([]byte, error) {
	if err := n.Validate(); err != nil {
		return nil, err
	}
	data, err := encMode.Marshal(n.wire())
	if err != nil {
		return nil, fmt.Errorf("encode CIP-113 registry node logic: %w", err)
	}
	return data, nil
}

// UnmarshalCIP113RegistryNodeLogic decodes canonical stable registry-node
// logic.
func UnmarshalCIP113RegistryNodeLogic(
	data []byte,
) (CIP113RegistryNodeLogic, error) {
	if len(data) == 0 {
		return CIP113RegistryNodeLogic{}, errors.New(
			"CIP-113 registry node logic is empty",
		)
	}
	var wire cip113RegistryNodeLogicWire
	if err := decMode.Unmarshal(data, &wire); err != nil {
		return CIP113RegistryNodeLogic{}, fmt.Errorf(
			"decode CIP-113 registry node logic: %w",
			err,
		)
	}
	node, err := cip113RegistryNodeLogicFromWire(wire)
	if err != nil {
		return CIP113RegistryNodeLogic{}, err
	}
	canonical, err := node.MarshalCBOR()
	if err != nil {
		return CIP113RegistryNodeLogic{}, err
	}
	if !bytes.Equal(data, canonical) {
		return CIP113RegistryNodeLogic{}, ErrNonCanonicalCBOR
	}
	return node, nil
}

// Digest returns the domain-separated stable registry-node logic digest.
func (n CIP113RegistryNodeLogic) Digest() (Digest, error) {
	return canonicalDigest(cip113RegistryLogicDomainV1, n.MarshalCBOR)
}

func (a NameAuthority) wire() nameAuthorityWire {
	return nameAuthorityWire{
		Version:           a.Version,
		Kind:              uint64(a.Kind),
		Class:             uint64(a.Class),
		NetworkID:         clone(a.NetworkID[:]),
		CanonicalWireName: clone(a.CanonicalWireName),
		ParentDigest:      clone(a.ParentDigest[:]),
	}
}

func nameAuthorityFromWire(w nameAuthorityWire) (NameAuthority, error) {
	networkID, err := digest("authority network ID", w.NetworkID)
	if err != nil {
		return NameAuthority{}, err
	}
	parentDigest, err := digest("parent digest", w.ParentDigest)
	if err != nil {
		return NameAuthority{}, err
	}
	a := NameAuthority{
		Version:           w.Version,
		Kind:              AuthorityKind(w.Kind),
		Class:             NameClass(w.Class),
		NetworkID:         networkID,
		CanonicalWireName: clone(w.CanonicalWireName),
		ParentDigest:      parentDigest,
	}
	if err := a.Validate(); err != nil {
		return NameAuthority{}, err
	}
	return a, nil
}

func (r CIP113Representation) wire() cip113RepresentationWire {
	return cip113RepresentationWire{
		Version:                   r.Version,
		NameAuthorityDigest:       clone(r.NameAuthorityDigest[:]),
		CardanoNetworkID:          r.CardanoNetworkID,
		CardanoNetworkMagic:       r.CardanoNetworkMagic,
		CardanoByronGenesisHash:   clone(r.CardanoByronGenesisHash[:]),
		CardanoShelleyGenesisHash: clone(r.CardanoShelleyGenesisHash[:]),
		ProtocolConfigPolicyID:    clone(r.ProtocolConfigPolicyID[:]),
		ProtocolConfigAssetName:   clone(r.ProtocolConfigAssetName),
		RegistryPolicyID:          clone(r.RegistryPolicyID[:]),
		RegistryNodeLogicDigest:   clone(r.RegistryNodeLogicDigest[:]),
		TokenPolicyID:             clone(r.TokenPolicyID[:]),
		AssetName:                 clone(r.AssetName),
		DomainStatePolicyID:       clone(r.DomainStatePolicyID[:]),
		DomainStateAssetName:      clone(r.DomainStateAssetName),
		DomainStateValidator:      r.DomainStateValidator.wire(),
		ProfileDigest:             clone(r.ProfileDigest[:]),
	}
}

func cip113RepresentationFromWire(
	w cip113RepresentationWire,
) (CIP113Representation, error) {
	nameAuthority, err := digest(
		"name authority digest",
		w.NameAuthorityDigest,
	)
	if err != nil {
		return CIP113Representation{}, err
	}
	cardanoByronGenesis, err := digest("Cardano Byron genesis hash", w.CardanoByronGenesisHash)
	if err != nil {
		return CIP113Representation{}, err
	}
	cardanoShelleyGenesis, err := digest(
		"Cardano Shelley genesis hash",
		w.CardanoShelleyGenesisHash,
	)
	if err != nil {
		return CIP113Representation{}, err
	}
	protocolConfig, err := policyID(
		"protocol config policy ID",
		w.ProtocolConfigPolicyID,
	)
	if err != nil {
		return CIP113Representation{}, err
	}
	registryNodeState, err := digest(
		"registry node logic digest",
		w.RegistryNodeLogicDigest,
	)
	if err != nil {
		return CIP113Representation{}, err
	}
	registry, err := policyID("registry policy ID", w.RegistryPolicyID)
	if err != nil {
		return CIP113Representation{}, err
	}
	domainStateValidator, err := cardanoCredentialFromWire(
		"domain state validator",
		w.DomainStateValidator,
	)
	if err != nil {
		return CIP113Representation{}, err
	}
	token, err := policyID("token policy ID", w.TokenPolicyID)
	if err != nil {
		return CIP113Representation{}, err
	}
	domainState, err := policyID(
		"domain state policy ID",
		w.DomainStatePolicyID,
	)
	if err != nil {
		return CIP113Representation{}, err
	}
	profile, err := digest("profile digest", w.ProfileDigest)
	if err != nil {
		return CIP113Representation{}, err
	}
	r := CIP113Representation{
		Version:                   w.Version,
		NameAuthorityDigest:       nameAuthority,
		CardanoNetworkID:          w.CardanoNetworkID,
		CardanoNetworkMagic:       w.CardanoNetworkMagic,
		CardanoByronGenesisHash:   cardanoByronGenesis,
		CardanoShelleyGenesisHash: cardanoShelleyGenesis,
		ProtocolConfigPolicyID:    protocolConfig,
		ProtocolConfigAssetName:   clone(w.ProtocolConfigAssetName),
		RegistryPolicyID:          registry,
		RegistryNodeLogicDigest:   registryNodeState,
		TokenPolicyID:             token,
		AssetName:                 clone(w.AssetName),
		DomainStatePolicyID:       domainState,
		DomainStateAssetName:      clone(w.DomainStateAssetName),
		DomainStateValidator:      domainStateValidator,
		ProfileDigest:             profile,
	}
	if err := r.Validate(); err != nil {
		return CIP113Representation{}, err
	}
	return r, nil
}

func (n CIP113RegistryNodeLogic) wire() cip113RegistryNodeLogicWire {
	return cip113RegistryNodeLogicWire{
		Version:             n.Version,
		TokenPolicyID:       clone(n.TokenPolicyID[:]),
		MintingLogic:        n.MintingLogic.wire(),
		TransferLogic:       n.TransferLogic.wire(),
		ThirdPartyLogic:     n.ThirdPartyLogic.wire(),
		GlobalStatePolicyID: clone(n.GlobalStatePolicyID[:]),
	}
}

func cip113RegistryNodeLogicFromWire(
	w cip113RegistryNodeLogicWire,
) (CIP113RegistryNodeLogic, error) {
	tokenPolicy, err := policyID(
		"registry node token policy ID",
		w.TokenPolicyID,
	)
	if err != nil {
		return CIP113RegistryNodeLogic{}, err
	}
	minting, err := cardanoCredentialFromWire(
		"registry node minting logic",
		w.MintingLogic,
	)
	if err != nil {
		return CIP113RegistryNodeLogic{}, err
	}
	transfer, err := cardanoCredentialFromWire(
		"registry node transfer logic",
		w.TransferLogic,
	)
	if err != nil {
		return CIP113RegistryNodeLogic{}, err
	}
	thirdParty, err := cardanoCredentialFromWire(
		"registry node third-party logic",
		w.ThirdPartyLogic,
	)
	if err != nil {
		return CIP113RegistryNodeLogic{}, err
	}
	globalState, err := policyID(
		"registry node global state policy ID",
		w.GlobalStatePolicyID,
	)
	if err != nil {
		return CIP113RegistryNodeLogic{}, err
	}
	node := CIP113RegistryNodeLogic{
		Version:             w.Version,
		TokenPolicyID:       tokenPolicy,
		MintingLogic:        minting,
		TransferLogic:       transfer,
		ThirdPartyLogic:     thirdParty,
		GlobalStatePolicyID: globalState,
	}
	if err := node.Validate(); err != nil {
		return CIP113RegistryNodeLogic{}, err
	}
	return node, nil
}

func canonicalWireNameLabelCount(
	name []byte,
	kind AuthorityKind,
) (int, error) {
	if len(name) < 2 {
		return 0, errors.New("must contain a label and terminal root")
	}
	if len(name) > 255 {
		return 0, fmt.Errorf("is %d bytes, maximum is 255", len(name))
	}
	labelCount := 0
	for offset := 0; ; {
		if offset >= len(name) {
			return 0, errors.New("missing terminal root label")
		}
		length := int(name[offset])
		offset++
		if length == 0 {
			if offset != len(name) {
				return 0, errors.New(
					"contains bytes after terminal root label",
				)
			}
			return labelCount, nil
		}
		labelCount++
		if length > 63 {
			return 0, fmt.Errorf("label length %d exceeds 63", length)
		}
		if offset+length > len(name) {
			return 0, errors.New("label exceeds wire name length")
		}
		label := name[offset : offset+length]
		if label[0] == '-' || label[len(label)-1] == '-' {
			return 0, errors.New("label begins or ends with a hyphen")
		}
		if label[0] == '_' || label[len(label)-1] == '_' {
			return 0, errors.New("label begins or ends with an underscore")
		}
		handshakeTLD := kind == AuthorityKindHandshake &&
			offset+length == len(name)-1 && name[len(name)-1] == 0
		for _, b := range label {
			switch {
			case b >= 'a' && b <= 'z':
			case b >= '0' && b <= '9':
			case b == '-':
			case b == '_' && handshakeTLD:
			case b >= 'A' && b <= 'Z':
				return 0, errors.New("contains upper-case ASCII")
			case b > 0x7f:
				return 0, errors.New("contains non-ASCII label bytes")
			default:
				return 0, errors.New("contains a non-LDH byte")
			}
		}
		offset += length
	}
}

func parentWireName(name []byte, kind AuthorityKind) ([]byte, error) {
	labelCount, err := canonicalWireNameLabelCount(name, kind)
	if err != nil {
		return nil, err
	}
	if labelCount != 2 {
		return nil, fmt.Errorf("expected two labels, got %d", labelCount)
	}
	firstLength := int(name[0])
	parentOffset := 1 + firstLength
	return clone(name[parentOffset:]), nil
}

func validateAssetName(name string, value []byte) error {
	if len(value) == 0 {
		return fmt.Errorf("%s must not be empty", name)
	}
	if len(value) > MaxCardanoAssetNameBytes {
		return fmt.Errorf(
			"%s is %d bytes, maximum is %d",
			name,
			len(value),
			MaxCardanoAssetNameBytes,
		)
	}
	return nil
}

func policyID(name string, value []byte) (CardanoPolicyID, error) {
	if len(value) != len(CardanoPolicyID{}) {
		return CardanoPolicyID{}, fmt.Errorf(
			"%s must be 28 bytes, got %d",
			name,
			len(value),
		)
	}
	var ret CardanoPolicyID
	copy(ret[:], value)
	return ret, nil
}

func (c CardanoCredential) validateScript(name string) error {
	if c.Kind != CardanoCredentialScript {
		return fmt.Errorf("%s must be a script credential", name)
	}
	if isZero(c.Hash[:]) {
		return fmt.Errorf("%s hash must not be zero", name)
	}
	return nil
}

func (c CardanoCredential) wire() cardanoCredentialWire {
	return cardanoCredentialWire{
		Kind: uint64(c.Kind),
		Hash: clone(c.Hash[:]),
	}
}

func cardanoCredentialFromWire(
	name string,
	w cardanoCredentialWire,
) (CardanoCredential, error) {
	hash, err := credentialHash(name+" hash", w.Hash)
	if err != nil {
		return CardanoCredential{}, err
	}
	credential := CardanoCredential{
		Kind: CardanoCredentialKind(w.Kind),
		Hash: hash,
	}
	if err := credential.validateScript(name); err != nil {
		return CardanoCredential{}, err
	}
	return credential, nil
}

func credentialHash(
	name string,
	value []byte,
) (CardanoCredentialHash, error) {
	if len(value) != len(CardanoCredentialHash{}) {
		return CardanoCredentialHash{}, fmt.Errorf(
			"%s must be 28 bytes, got %d",
			name,
			len(value),
		)
	}
	var ret CardanoCredentialHash
	copy(ret[:], value)
	return ret, nil
}

func canonicalDigest(
	domain string,
	marshal func() ([]byte, error),
) (Digest, error) {
	data, err := marshal()
	if err != nil {
		return Digest{}, err
	}
	payload := make([]byte, 0, len(domain)+len(data))
	payload = append(payload, domain...)
	payload = append(payload, data...)
	return blake2b.Sum256(payload), nil
}

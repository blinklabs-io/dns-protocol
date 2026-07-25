# dns-protocol

Language-neutral protocol definitions and a Go reference implementation for
Blink Labs decentralized DNS infrastructure.

The repository owns security-critical wire formats, domain separators,
canonical encodings, validation rules, and conformance vectors shared by
`dns-bridge`, `cdnsd`, Cardano validators, browser clients, and future Midnight
contracts.

## Current scope

The first protocol unit defines the version 1 Handshake checkpoint vote used by
Cardano stake pool operators:

- canonical CBOR wire encoding;
- a stable agreement digest over consensus fields;
- diagnostic fields that do not change the agreement digest;
- strict decoding that rejects non-canonical encodings and trailing data;
- field and size validation;
- CDDL and cross-implementation golden vectors.

The version 1 owner binding defines:

- canonical Handshake TLD normalization and name hashing;
- the compact `CDNS1` Handshake TXT item;
- Cardano network, policy, and controller credential binding;
- generation nonces and strict capability-bit validation;
- duplicate-binding and cross-name transplant rejection.

The outer CIP-0137 KES/opcert envelope is the individual SPO vote. This package
does not implement DMQ transport, KES authentication, quorum, or certificate
aggregation.

## Layout

```text
checkpoint.go              Go reference types and codec
checkpoint_test.go         behavior and negative tests
spec/v1/attestation.cddl   language-neutral CDDL
binding.go                 CDNS1 binding and Handshake name canonicalization
binding_test.go            binding behavior, negative tests, and fuzz coverage
spec/v1/binding.cddl       language-neutral CDNS1 binding schema
testdata/v1/               golden vector inputs and expected outputs
```

## Development

```sh
go test ./...
go vet ./...
```

Public types use fixed-size arrays for security-relevant hashes and identifiers.
The wire representation uses CBOR byte strings. Do not change field order,
domain separators, or accepted lengths without introducing a new protocol
version and new vectors.

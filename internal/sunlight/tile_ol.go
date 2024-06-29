// Copyright 2023 The Sunlight Authors

// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.

// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

package sunlight

import (
	"fmt"
	"github.com/google/certificate-transparency-go/x509"
	"math"

	"golang.org/x/crypto/cryptobyte"
)

const TileHeight = 8
const TileWidth = 1 << TileHeight

type UnsequencedEntry struct {
	// Certificate is either the X509ChainEntry.leaf_certificate, or the
	// PreCert.tbs_certificate for Precertificates.
	// It must be at most 2^24-1 bytes long.
	Certificate []byte

	// IsPrecert is true if LogEntryType is precert_entry. Otherwise, the
	// following three fields are zero and ignored.
	IsPrecert bool

	// IssuerKeyHash is the PreCert.issuer_key_hash.
	IssuerKeyHash [32]byte

	// PreCertificate is the PrecertChainEntry.pre_certificate.
	// It must be at most 2^24-1 bytes long.
	PreCertificate []byte

	// CertificateFp is the fingerprint of the first element of the chain
	CertificateFp [32]byte

	// ChainFp is a slice of the fingerprints of the entries
	// in the chain submitted the add-chain or add-pre-chain endpoints,
	// excluding the first element, with the original order maintained.
	ChainFp [][32]byte

	// Chain is the rest of the certificates in the chain
	// It will only be filled in if the LogEntry is generated in the
	// submit cert or precert endpoints
	Chain []*x509.Certificate
}

type LogEntry struct {
	// Certificate is either the X509ChainEntry.leaf_certificate, or the
	// PreCert.tbs_certificate for Precertificates.
	// It must be at most 2^24-1 bytes long.
	Certificate []byte

	// IsPrecert is true if LogEntryType is precert_entry. Otherwise, the
	// following three fields are zero and ignored.
	IsPrecert bool

	// IssuerKeyHash is the PreCert.issuer_key_hash.
	IssuerKeyHash [32]byte

	// PreCertificate is the PrecertChainEntry.pre_certificate.
	// It must be at most 2^24-1 bytes long.
	PreCertificate []byte

	// CertificateFp is the fingerprint of the first element of the chain
	CertificateFp [32]byte

	// ChainFp is a slice of the fingerprints of the entries
	// in the chain submitted the add-chain or add-pre-chain endpoints,
	// excluding the first element, with the original order maintained.
	ChainFp [][32]byte

	// Chain is the rest of the certificates in the chain
	// It will only be filled in if the LogEntry is generated in the
	// submit cert or precert endpoints
	Chain []*x509.Certificate

	// Timestamp is the TimestampedEntry.timestamp.
	Timestamp int64

	// LeafIndex is the zero-based index of the leaf in the log.
	// It must be between 0 and 2^40-1.
	LeafIndex uint64
}

// MerkleTreeLeaf returns a RFC 6962 MerkleTreeLeaf.
// MerkleTreeLeaf also returns a RFC 6962 digitally-signed struct
// As it is identical to the MerkleTreeLeaf and the spec has not changed since 2013 :)
func (e *LogEntry) MerkleTreeLeaf() []byte {
	b := &cryptobyte.Builder{}

	// for RFC 6962 MerkleTreeLeaf: version = v1
	// for RFC 6962 digitally-signed struct: sct_version = v1
	b.AddUint8(0 /* version = v1 */)

	// for RFC 6962 MerkleTreeLeaf: leaf_type = timestamped_entry (0)
	// for RFC 6962 digitally-signed struct: signature_type = certificate_timestamp (0)
	b.AddUint8(0)

	b.AddUint64(uint64(e.Timestamp))
	if !e.IsPrecert {
		b.AddUint16(0 /* entry_type = x509_entry */)
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(e.Certificate)
		})
	} else {
		b.AddUint16(1 /* entry_type = precert_entry */)
		b.AddBytes(e.IssuerKeyHash[:])
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(e.Certificate)
		})
	}
	addExtensions(b, e.LeafIndex)
	return b.BytesOrPanic()
}

// struct {
//     TimestampedEntry timestamped_entry;
//     select(entry_type) {
//         case x509_entry: Empty;
//         case precert_entry: ASN.1Cert pre_certificate;
//     } extra_data;
//     Fingerprint chain<0..2^16-1>;
// } TileLeaf;
//
// opaque Fingerprint[32];

// ReadTileLeaf reads a LogEntry from a data tile, and returns the remaining
// data in the tile.
func ReadTileLeaf(tile []byte) (e *LogEntry, rest []byte, err error) {
	e = &LogEntry{}
	s := cryptobyte.String(tile)
	var timestamp uint64
	var entryType uint16
	var extensions cryptobyte.String
	if !s.ReadUint64(&timestamp) || !s.ReadUint16(&entryType) || timestamp > math.MaxInt64 {
		return nil, s, fmt.Errorf("invalid data tile")
	}
	e.Timestamp = int64(timestamp)
	switch entryType {
	case 0: // x509_entry
		if !s.ReadUint24LengthPrefixed((*cryptobyte.String)(&e.Certificate)) ||
			!s.ReadUint16LengthPrefixed(&extensions) {
			return nil, s, fmt.Errorf("invalid data tile x509_entry")
		}
	case 1: // precert_entry
		e.IsPrecert = true
		if !s.CopyBytes(e.IssuerKeyHash[:]) ||
			!s.ReadUint24LengthPrefixed((*cryptobyte.String)(&e.Certificate)) ||
			!s.ReadUint16LengthPrefixed(&extensions) ||
			!s.ReadUint24LengthPrefixed((*cryptobyte.String)(&e.PreCertificate)) {
			return nil, s, fmt.Errorf("invalid data tile precert_entry")
		}
	default:
		return nil, s, fmt.Errorf("invalid data tile: unknown type %d", entryType)
	}

	// look at first byte to determine the length of the chain
	var fingerprintCount uint16
	if !s.ReadUint16(&fingerprintCount) {
		return nil, s, fmt.Errorf("invalid data tile precert_entry")
	}
	// then, try to read out that many fingerprints
	e.ChainFp = make([][32]byte, 0, fingerprintCount)
	for i := uint16(0); i < fingerprintCount; i++ {
		var fingerprint [32]byte
		if !s.CopyBytes(fingerprint[:]) {
			return nil, s, fmt.Errorf("invalid data tile precert_entry")
		}
		e.ChainFp = append(e.ChainFp, fingerprint)
	}
	e.CertificateFp = e.ChainFp[0]

	var extensionType uint8
	var extensionData cryptobyte.String
	if !extensions.ReadUint8(&extensionType) || extensionType != 0 ||
		!extensions.ReadUint16LengthPrefixed(&extensionData) ||
		!readUint40(&extensionData, &e.LeafIndex) || !extensionData.Empty() ||
		!extensions.Empty() {
		return nil, s, fmt.Errorf("invalid data tile extensions")
	}
	return e, s, nil
}

// AppendTileLeaf appends a LogEntry to a data tile.
func AppendTileLeaf(t []byte, e *LogEntry) []byte {
	b := cryptobyte.NewBuilder(t)
	b.AddUint64(uint64(e.Timestamp))
	if !e.IsPrecert {
		b.AddUint16(0 /* entry_type = x509_entry */)
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(e.Certificate)
		})
	} else {
		b.AddUint16(1 /* entry_type = precert_entry */)
		b.AddBytes(e.IssuerKeyHash[:])
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(e.Certificate)
		})
	}
	addExtensions(b, e.LeafIndex)
	if e.IsPrecert {
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(e.PreCertificate)
		})
	}
	b.AddUint16(uint16(len(e.ChainFp)))
	for _, fingerprint := range e.ChainFp {
		b.AddBytes(fingerprint[:])
	}

	return b.BytesOrPanic()
}

func addExtensions(b *cryptobyte.Builder, leafIndex uint64) {
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		ext, err := MarshalExtensions(Extensions{LeafIndex: leafIndex})
		if err != nil {
			b.SetError(err)
			return
		}
		b.AddBytes(ext)
	})
}

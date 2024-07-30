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
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	ct "github.com/google/certificate-transparency-go"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

// signTreeHead signs the tree and returns a checkpoint according to
// c2sp.org/checkpoint.
func SignTreeHeadCheckpoint(origin string, privKey *ecdsa.PrivateKey, treeSize, timestamp int64, sha256RootHash [32]byte) (checkpoint []byte, err error) {
	sthBytes, err := ct.SerializeSTHSignatureInput(ct.SignedTreeHead{
		Version:        ct.V1,
		TreeSize:       uint64(treeSize),
		Timestamp:      uint64(timestamp),
		SHA256RootHash: ct.SHA256Hash(sha256RootHash),
	})
	if err != nil {
		return nil, fmt.Errorf("couldn't serialize STH signature input: %w", err)
	}

	// We compute the signature here and inject it in a fixed note.Signer to
	// avoid a risky serialize-deserialize loop, and to control the timestamp.

	treeHeadSignature, err := DigitallySign(privKey, sthBytes)
	if err != nil {
		return nil, fmt.Errorf("couldn't produce signature: %w", err)
	}

	// struct {
	//     uint64 timestamp;
	//     TreeHeadSignature signature;
	// } RFC6962NoteSignature;
	var b cryptobyte.Builder
	b.AddUint64(uint64(timestamp))
	b.AddBytes(treeHeadSignature)
	sig, err := b.Bytes()
	if err != nil {
		return nil, fmt.Errorf("couldn't encode RFC6962NoteSignature: %w", err)
	}

	v, err := NewRFC6962Verifier(origin, privKey.Public(), nil)
	if err != nil {
		return nil, fmt.Errorf("couldn't construct verifier: %w", err)
	}
	signer := &injectedSigner{v, sig}
	signedNote, err := note.Sign(&note.Note{
		Text: FormatCheckpoint(Checkpoint{
			Origin: origin,
			Tree:   tlog.Tree{N: treeSize, Hash: sha256RootHash},
		}),
	}, signer)
	if err != nil {
		return nil, fmt.Errorf("couldn't sign note: %w", err)
	}
	return signedNote, nil
}

type injectedSigner struct {
	v   note.Verifier
	sig []byte
}

func (s *injectedSigner) Sign(msg []byte) ([]byte, error) { return s.sig, nil }
func (s *injectedSigner) Name() string                    { return s.v.Name() }
func (s *injectedSigner) KeyHash() uint32                 { return s.v.KeyHash() }
func (s *injectedSigner) Verifier() note.Verifier         { return s.v }

// functions from sunlight checkpoint.go

const maxCheckpointSize = 1e6

// A Checkpoint is a tree head to be formatted according to c2sp.org/checkpoint.
//
// A checkpoint looks like this:
//
//	example.com/origin
//	923748
//	nND/nri/U0xuHUrYSy0HtMeal2vzD9V4k/BO79C+QeI=
//
// It can be followed by extra extension lines.
type Checkpoint struct {
	Origin string
	tlog.Tree

	// Extension is empty or a sequence of non-empty lines,
	// each terminated by a newline character.
	Extension string
}

func ParseCheckpoint(text string) (Checkpoint, error) {
	// This is an extended version of tlog.ParseTree.

	if strings.Count(text, "\n") < 3 || len(text) > maxCheckpointSize {
		return Checkpoint{}, errors.New("malformed checkpoint")
	}
	if !strings.HasSuffix(text, "\n") {
		return Checkpoint{}, errors.New("malformed checkpoint")
	}

	lines := strings.SplitN(text, "\n", 4)

	n, err := strconv.ParseInt(lines[1], 10, 64)
	if err != nil || n < 0 || lines[1] != strconv.FormatInt(n, 10) {
		return Checkpoint{}, errors.New("malformed checkpoint")
	}

	h, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil || len(h) != tlog.HashSize {
		return Checkpoint{}, errors.New("malformed checkpoint")
	}

	rest := lines[3]
	for rest != "" {
		before, after, found := strings.Cut(rest, "\n")
		if before == "" || !found {
			return Checkpoint{}, errors.New("malformed checkpoint")
		}
		rest = after
	}

	var hash tlog.Hash
	copy(hash[:], h)
	return Checkpoint{lines[0], tlog.Tree{N: n, Hash: hash}, lines[3]}, nil
}

func FormatCheckpoint(c Checkpoint) string {
	return fmt.Sprintf("%s\n%d\n%s\n%s",
		c.Origin, c.N, base64.StdEncoding.EncodeToString(c.Hash[:]), c.Extension)
}

// NewRFC6962Verifier constructs a new [note.Verifier] that verifies a RFC 6962
// TreeHeadSignature formatted according to c2sp.org/sunlight.
//
// tf, if not nil, is called with the timestamp extracted from any valid
// verified signature.
func NewRFC6962Verifier(name string, key crypto.PublicKey, tf func(uint64)) (note.Verifier, error) {
	if !isValidName(name) {
		return nil, fmt.Errorf("invalid name %q", name)
	}

	pkix, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, err
	}
	keyID := sha256.Sum256(pkix)

	v := &verifier{}
	v.name = name
	v.hash = keyHash(name, append([]byte{0x05}, keyID[:]...))
	v.verify = func(msg, sig []byte) (ok bool) {
		c, err := ParseCheckpoint(string(msg))
		if err != nil {
			return false
		}
		if c.Extension != "" {
			return false
		}

		// Parse the RFC6962NoteSignature.
		var timestamp uint64
		var hashAlg, sigAlg uint8
		var signature []byte
		s := cryptobyte.String(sig)
		if !s.ReadUint64(&timestamp) ||
			!s.ReadUint8(&hashAlg) || hashAlg != 4 || !s.ReadUint8(&sigAlg) ||
			!s.ReadUint16LengthPrefixed((*cryptobyte.String)(&signature)) ||
			!s.Empty() {
			return false
		}

		defer func() {
			if ok && tf != nil {
				tf(timestamp)
			}
		}()

		sth := ct.SignedTreeHead{
			Version:        ct.V1,
			TreeSize:       uint64(c.N),
			Timestamp:      timestamp,
			SHA256RootHash: ct.SHA256Hash(c.Hash),
		}
		sthBytes, err := ct.SerializeSTHSignatureInput(sth)
		if err != nil {
			return false
		}

		digest := sha256.Sum256(sthBytes)
		switch key := key.(type) {
		case *rsa.PublicKey:
			if sigAlg != 1 {
				return false
			}
			return rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig) == nil
		case *ecdsa.PublicKey:
			if sigAlg != 3 {
				return false
			}
			return ecdsa.VerifyASN1(key, digest[:], signature)
		default:
			return false
		}
	}

	return v, nil
}

type verifier struct {
	name   string
	hash   uint32
	verify func(msg, sig []byte) bool
}

func (v *verifier) Name() string                { return v.name }
func (v *verifier) KeyHash() uint32             { return v.hash }
func (v *verifier) Verify(msg, sig []byte) bool { return v.verify(msg, sig) }

func isValidName(name string) bool {
	return name != "" && utf8.ValidString(name) &&
		strings.IndexFunc(name, unicode.IsSpace) < 0 &&
		!strings.Contains(name, "+")
}

func keyHash(name string, key []byte) uint32 {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte("\n"))
	h.Write(key)
	sum := h.Sum(nil)
	return binary.BigEndian.Uint32(sum)
}

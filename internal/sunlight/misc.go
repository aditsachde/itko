package sunlight

import (
	"crypto/ecdsa"
	"encoding/json"

	ct "github.com/google/certificate-transparency-go"
)

func (p UnsequencedEntry) Sequence(leafIndex uint64, timestamp int64) LogEntry {
	return LogEntry{
		Certificate:    p.Certificate,
		CertificateFp:  p.CertificateFp,
		IsPrecert:      p.IsPrecert,
		IssuerKeyHash:  p.IssuerKeyHash,
		PreCertificate: p.PreCertificate,
		ChainFp:        p.ChainFp,

		Timestamp: timestamp,
		LeafIndex: leafIndex,
	}
}

// SignTreeHead takes in the parameters to create a signed tree head and returns the JSON-encoded response.
func SignTreeHead(k *ecdsa.PrivateKey, treeSize, timestamp uint64, sha256RootHash [32]byte) ([]byte, error) {

	sthBytes, err := ct.SerializeSTHSignatureInput(ct.SignedTreeHead{
		Version:        ct.V1,
		TreeSize:       treeSize,
		Timestamp:      timestamp,
		SHA256RootHash: sha256RootHash,
	})
	if err != nil {
		return nil, err
	}

	sthSignature, err := DigitallySign(k, sthBytes)
	if err != nil {
		return nil, err
	}

	jsonBytes, err := json.Marshal(ct.GetSTHResponse{
		TreeSize:          treeSize,
		Timestamp:         timestamp,
		SHA256RootHash:    sha256RootHash[:],
		TreeHeadSignature: sthSignature,
	})
	if err != nil {
		return nil, err
	}

	return jsonBytes, err
}

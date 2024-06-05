package sunlight

type UnsequencedEntry struct {
	Certificate    []byte
	CertificateFp  [32]byte
	IsPrecert      bool
	IssuerKeyHash  [32]byte
	PreCertificate []byte
	ChainFp        [][32]byte
	Timestamp      int64
}

func (p UnsequencedEntry) Sequence(leafIndex uint64) LogEntry {
	return LogEntry{
		Certificate:    p.Certificate,
		CertificateFp:  p.CertificateFp,
		IsPrecert:      p.IsPrecert,
		IssuerKeyHash:  p.IssuerKeyHash,
		PreCertificate: p.PreCertificate,
		ChainFp:        p.ChainFp,
		Timestamp:      p.Timestamp,
		LeafIndex:      leafIndex,
	}
}

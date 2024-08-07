package ctsubmit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"

	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/google/certificate-transparency-go/x509"
	"golang.org/x/mod/sumdb/tlog"
	"golang.org/x/sync/errgroup"
	"itko.dev/internal/sunlight"
)

type Bucket struct {
	S Storage
}

// --------------------------------------------------------------------------------------------

func (b *Bucket) SetTile(ctx context.Context, tile tlog.Tile, data []byte) error {
	return b.S.Set(ctx, sunlight.Path(tile), data)
}

func (b *Bucket) SetSth(ctx context.Context, data []byte) error {
	return b.S.Set(ctx, "ct/v1/get-sth", data)
}

func (b *Bucket) SetCheckpoint(ctx context.Context, data []byte) error {
	return b.S.Set(ctx, "checkpoint", data)
}

func (b *Bucket) SetIssuer(ctx context.Context, cert *x509.Certificate) error {
	fingerprint := sha256.Sum256(cert.Raw)
	exists, err := b.S.Exists(ctx, fmt.Sprintf("issuer/%x", fingerprint))
	if err != nil {
		return err
	}
	if !exists {
		return b.S.Set(ctx, fmt.Sprintf("issuer/%x", fingerprint), cert.Raw)
	}
	return nil
}

// --------------------------------------------------------------------------------------------

type RecordHashUpload struct {
	hash      [16]byte // if 16 bytes is good enough for sunlight, its good enough for us
	leafIndex uint64
	hashPath  string
}

const (
	RHURecordSize = 21
	RHUHashSize   = 16
	// Sunlight defines index size to be 40 bits or 5 bytes
	RHULeafIndexSize = 5
)

func (r *RecordHashUpload) ToBytes() []byte {
	buf := make([]byte, RHURecordSize)
	copy(buf[:RHUHashSize], r.hash[:])

	// Convert the leaf index to a byte slice
	leafIndexBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(leafIndexBytes, r.leafIndex)

	// Copy the lower 5 bytes (40 bits) to the buffer
	copy(buf[RHUHashSize:], leafIndexBytes[0:5])

	return buf
}

func BytesToRecord(b []byte) (RecordHashUpload, error) {
	if len(b) != RHURecordSize {
		return RecordHashUpload{}, fmt.Errorf("invalid record size: %d", len(b))
	}
	record := RecordHashUpload{}
	copy(record.hash[:], b[:RHUHashSize])

	// Create a buffer for the full 64-bit timestamp
	fullIndxeBytes := make([]byte, 8)
	// Copy the 5 bytes to the buffer
	copy(fullIndxeBytes[0:5], b[RHUHashSize:])
	// Convert to uint64
	record.leafIndex = binary.LittleEndian.Uint64(fullIndxeBytes)
	return record, nil
}

// TODO: This NEEDS unit testing
// TODO: convert these to use binary search
func (b *Bucket) PutRecordHashes(ctx context.Context, hashes []RecordHashUpload, mask int) error {
	f := make(map[string][]byte)

	// Populate the hash paths
	for i := range hashes {
		hashes[i].hashPath = sunlight.KAnonHashPath(hashes[i].hash[:], mask)
	}

	// First, get all the files corresponding to all of the hashes.
	for _, e := range hashes {
		if _, ok := f[e.hashPath]; ok {
			continue
		}

		var err error
		f[e.hashPath], err = b.S.Get(ctx, "int/hashes/"+e.hashPath)
		if err != nil {
			// TODO: move this logic into the storage interface
			var notFound *s3types.NoSuchKey
			if errors.As(err, &notFound) || errors.Is(err, os.ErrNotExist) {
				// If the file is not found, create a new one.
				f[e.hashPath] = make([]byte, 0)
			} else {
				return err
			}
		}
	}

	// Now, update the files with the new hashes.
	for _, e := range hashes {
		records := f[e.hashPath]
		recordCount := len(records) / RHURecordSize

		// Find the insertion point
		insertIndex := recordCount
		for i := 0; i < recordCount; i++ {
			// insert 4 into the list 1 3 5 7 9.
			// iterate until we find the first value that 4 is less than. Then, insert into that index.

			// This is true if the first value is less than the second
			if bytes.Compare(e.hash[:], records[i*RHURecordSize:(i*RHURecordSize)+RHUHashSize]) < 0 {
				// the insertion point should be where the compared value currently is
				insertIndex = i
				break
			}
		}

		// Create the new byte slice with the inserted record
		newRecords := make([]byte, len(records)+RHURecordSize)
		copy(newRecords[:insertIndex*RHURecordSize], records[:insertIndex*RHURecordSize])
		// The end of the newRecords slice does not need to be defined since copy will only copy the minimum of the two slices
		copy(newRecords[insertIndex*RHURecordSize:], e.ToBytes())
		copy(newRecords[(insertIndex+1)*RHURecordSize:], records[insertIndex*RHURecordSize:])

		f[e.hashPath] = newRecords
	}

	// Now, write the updated files back to the bucket.
	g, gctx := errgroup.WithContext(ctx)
	for k, v := range f {
		g.Go(func() error { return b.S.Set(gctx, "int/hashes/"+k, v) })
	}

	if err := g.Wait(); err != nil {
		return err
	}

	return nil
}

func (b *Bucket) GetRecordHash(ctx context.Context, hash [16]byte, mask int) (RecordHashUpload, error) {
	f, err := b.S.Get(ctx, "int/hashes/"+sunlight.KAnonHashPath(hash[:], mask))
	if err != nil {
		return RecordHashUpload{}, err
	}

	recordCount := len(f) / RHURecordSize

	for i := 0; i < recordCount; i++ {
		record, err := BytesToRecord(f[i*RHURecordSize : (i+1)*RHURecordSize])
		if err != nil {
			return RecordHashUpload{}, err
		}
		if bytes.Equal(hash[:], record.hash[:]) {
			return record, nil
		}
	}
	return RecordHashUpload{}, errors.New("record not found")
}

// --------------------------------------------------------------------------------------------

type DedupeUpload struct {
	hash      [16]byte // if 16 bytes is good enough for sunlight, its good enough for us
	leafIndex uint64
	timestamp int64
	hashPath  string
}

const (
	DDURecordSize = 29
	DDUHashSize   = 16
	// Sunlight defines index size to be 40 bits or 5 bytes
	DDULeafIndexSize = 5
	DDUTimestampSize = 8
)

func (r *DedupeUpload) ToBytes() []byte {
	buf := make([]byte, DDURecordSize)
	copy(buf[:DDUHashSize], r.hash[:])

	// Convert the leaf index to a byte slice
	leafIndexBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(leafIndexBytes, r.leafIndex)

	// Copy the lower 5 bytes (40 bits) to the buffer
	copy(buf[DDUHashSize:], leafIndexBytes[0:5])

	binary.LittleEndian.PutUint64(buf[DDUHashSize+DDULeafIndexSize:], uint64(r.timestamp))

	return buf
}

func BytesToDedupe(b []byte) (DedupeUpload, error) {
	if len(b) != DDURecordSize {
		return DedupeUpload{}, fmt.Errorf("invalid record size: %d", len(b))
	}
	record := DedupeUpload{}
	copy(record.hash[:], b[:DDUHashSize])

	// Create a buffer for the full 64-bit timestamp
	fullIndxeBytes := make([]byte, 8)
	// Copy the 5 bytes to the buffer
	copy(fullIndxeBytes[0:5], b[DDUHashSize:])
	// Convert to uint64
	record.leafIndex = binary.LittleEndian.Uint64(fullIndxeBytes)
	record.timestamp = int64(binary.LittleEndian.Uint64(b[DDUHashSize+DDULeafIndexSize:]))
	return record, nil
}

// TODO: This NEEDS unit testing
func (b *Bucket) PutDedupeEntries(ctx context.Context, hashes []DedupeUpload, mask int) error {
	f := make(map[string][]byte)

	// Populate the hash paths
	for i := range hashes {
		hashes[i].hashPath = sunlight.KAnonHashPath(hashes[i].hash[:], mask)
	}

	// First, get all the files corresponding to all of the hashes.
	for _, e := range hashes {
		if _, ok := f[e.hashPath]; ok {
			continue
		}

		var err error
		f[e.hashPath], err = b.S.Get(ctx, "int/dedupe/"+e.hashPath)
		if err != nil {
			// TODO: move this logic into the storage interface
			var notFound *s3types.NoSuchKey
			if errors.As(err, &notFound) || errors.Is(err, os.ErrNotExist) {
				// If the file is not found, create a new one.
				f[e.hashPath] = make([]byte, 0)
			} else {
				return err
			}
		}
	}

	// Now, update the files with the new hashes.
	for _, e := range hashes {
		records := f[e.hashPath]
		recordCount := len(records) / DDURecordSize

		// Find the insertion point
		insertIndex := recordCount
		for i := 0; i < recordCount; i++ {
			// insert 4 into the list 1 3 5 7 9.
			// iterate until we find the first value that 4 is less than. Then, insert into that index.

			// This is true if the first value is less than the second
			if bytes.Compare(e.hash[:], records[i*DDURecordSize:(i*DDURecordSize)+DDUHashSize]) < 0 {
				// the insertion point should be where the compared value currently is
				insertIndex = i
				break
			}
		}

		// Create the new byte slice with the inserted record
		newRecords := make([]byte, len(records)+DDURecordSize)
		copy(newRecords[:insertIndex*DDURecordSize], records[:insertIndex*DDURecordSize])
		// The end of the newRecords slice does not need to be defined since copy will only copy the minimum of the two slices
		copy(newRecords[insertIndex*DDURecordSize:], e.ToBytes())
		copy(newRecords[(insertIndex+1)*DDURecordSize:], records[insertIndex*DDURecordSize:])

		f[e.hashPath] = newRecords
	}

	// Now, write the updated files back to the bucket.
	g, gctx := errgroup.WithContext(ctx)
	for k, v := range f {
		g.Go(func() error { return b.S.Set(gctx, "int/dedupe/"+k, v) })
	}

	if err := g.Wait(); err != nil {
		return err
	}

	return nil
}

func (b *Bucket) GetDedupeEntry(ctx context.Context, hash [16]byte, mask int) (DedupeUpload, error) {
	f, err := b.S.Get(ctx, "int/dedupe/"+sunlight.KAnonHashPath(hash[:], mask))
	if err != nil {
		return DedupeUpload{}, err
	}

	recordCount := len(f) / DDURecordSize

	for i := 0; i < recordCount; i++ {
		record, err := BytesToDedupe(f[i*DDURecordSize : (i+1)*DDURecordSize])
		if err != nil {
			return DedupeUpload{}, err
		}
		if bytes.Equal(hash[:], record.hash[:]) {
			return record, nil
		}
	}
	return DedupeUpload{}, errors.New("record not found")
}

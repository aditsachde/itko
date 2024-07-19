package ctmonitor

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	ct "github.com/google/certificate-transparency-go"
	"golang.org/x/mod/sumdb/tlog"
	"itko.dev/internal/sunlight"
)

type Fetch struct {
	urlPrefix string
	maskSize  int
}

func newFetch(urlPrefix string, maskSize int) Fetch {
	return Fetch{
		urlPrefix: urlPrefix,
		maskSize:  maskSize,
	}
}

func (f *Fetch) get(ctx context.Context, key string) ([]byte, error) {
	resp, err, _ := f.getWithStatus(ctx, key)
	return resp, err
}

func (f *Fetch) getWithStatus(ctx context.Context, key string) ([]byte, error, int) {
	req, err := http.NewRequestWithContext(ctx, "GET", f.urlPrefix+key, nil)
	if err != nil {
		return nil, err, 500
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err, 500
	}
	if resp.StatusCode != 200 {
		return nil, errors.New(resp.Status), resp.StatusCode
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err, 500
	}
	return body, nil, 200
}

func (f *Fetch) getSth(ctx context.Context) (ct.SignedTreeHead, error) {
	sthBytes, err := f.get(ctx, "ct/v1/get-sth")
	if err != nil {
		return ct.SignedTreeHead{}, err
	}
	var sth ct.SignedTreeHead
	err = json.Unmarshal(sthBytes, &sth)
	if err != nil {
		return ct.SignedTreeHead{}, err
	}
	return sth, nil
}

func (f *Fetch) getTile(ctx context.Context, tile tlog.Tile) ([]byte, error) {
	fallbackWidth := tile.W
	tile.W = sunlight.TileWidth
	resp, err, status := f.getWithStatus(ctx, tile.Path())
	// In case the tile is not found, try to fetch the partial tile
	if status == 404 {
		if fallbackWidth != sunlight.TileWidth {
			tile.W = fallbackWidth
			return f.get(ctx, tile.Path())
		}
	}
	return resp, err

}

// TODO: refactor the duplicate definitions of this stanza in this file and bucket.go
// to be in the sunlight package.
const (
	RHURecordSize = 21
	RHUHashSize   = 16
	// Sunlight defines index size to be 40 bits or 5 bytes
	RHULeafIndexSize = 5
)

// TODO: convert these to use binary search
func (f *Fetch) getIndexForHash(ctx context.Context, hash []byte) (int64, error) {
	// check if hash is 32 bytes
	if len(hash) != RHUHashSize {
		return 0, errors.New("hash must be 32 bytes")
	}

	path := sunlight.KAnonHashPath(hash, f.maskSize)
	file, err := f.get(ctx, "int/hashes/"+path)
	if err != nil {
		return 0, err
	}

	recordCount := len(file) / RHURecordSize

	for i := 0; i < recordCount; i++ {
		if bytes.Equal(hash[:], file[i*RHURecordSize:(i*RHURecordSize)+RHUHashSize]) {
			// Create a buffer for the full 64-bit timestamp
			fullIndxeBytes := make([]byte, 8)
			// Copy the 5 bytes to the buffer
			copy(fullIndxeBytes[0:5], file[(i*RHURecordSize)+RHUHashSize:(i+1)*RHURecordSize])
			// Convert to uint64
			leafIndex := binary.LittleEndian.Uint64(fullIndxeBytes)

			return int64(leafIndex), nil
		}
	}

	return 0, errors.New("record not found")
}

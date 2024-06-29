package ctsubmit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"maps"
	"math/rand"
	"net/http"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/trillian/ctfe"
	"github.com/google/certificate-transparency-go/x509"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"golang.org/x/mod/sumdb/tlog"
	"itko.dev/internal/sunlight"
)

// TODO: Evaluate if the context is actually needed
func (l *Log) Start(ctx context.Context) (http.Handler, error) {
	// Start the stages
	// TODO: somehow bail if these return an error
	go l.stageOneData.stageOne(ctx)
	go l.stageTwoData.stageTwo(ctx)

	// Wrap the HTTP handler function with OTel instrumentation
	addChain := otelhttp.NewHandler(http.HandlerFunc(l.stageZeroData.addChain), "add-chain")
	addPreChain := otelhttp.NewHandler(http.HandlerFunc(l.stageZeroData.addPreChain), "add-pre-chain")

	// Create a new HTTP server mux and start listening
	mux := http.NewServeMux()
	mux.Handle("POST /ct/v1/add-chain", addChain)
	mux.Handle("POST /ct/v1/add-pre-chain", addPreChain)

	return http.MaxBytesHandler(mux, 128*1024), nil
}

func (d *stageZeroData) addChain(w http.ResponseWriter, r *http.Request) {
	d.stageZeroWrapper(w, r, false)
}

func (d *stageZeroData) addPreChain(w http.ResponseWriter, r *http.Request) {
	d.stageZeroWrapper(w, r, true)
}

func (d *stageZeroData) stageZeroWrapper(w http.ResponseWriter, r *http.Request, precertEndpoint bool) {
	resp, code, err := d.stageZero(r.Context(), r.Body, precertEndpoint)
	if err != nil {
		log.Println(err)
		if code == http.StatusServiceUnavailable {
			w.Header().Set("Retry-After", fmt.Sprintf("%d", 30+rand.Intn(60)))
			http.Error(w, "pool full", code)
		} else {
			http.Error(w, err.Error(), code)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if _, err = w.Write(resp); err != nil {
		log.Printf("Error writing response: %v", err)
	}
}

func (d *stageZeroData) stageZero(ctx context.Context, reqBody io.ReadCloser, precertEndpoint bool) (resp []byte, code int, err error) {
	body, err := io.ReadAll(reqBody)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("unable to read request body: %w", err)
	}

	var req struct {
		Chain [][]byte `json:"chain"`
	}

	if err := json.Unmarshal(body, &req); err != nil {
		return nil, http.StatusBadRequest, fmt.Errorf("unable to unmarshal request body: %w", err)
	}
	if len(req.Chain) == 0 {
		return nil, http.StatusBadRequest, fmt.Errorf("chain is empty")
	}

	// TODO: What EKU parameters should be accepted by the log?
	// The trillian integration tests include leaf certificates without any EKU parameters

	// validationOpts := ctfe.NewCertValidationOpts(d.roots, time.Time{},
	// 	false, false, &d.notAfterStart, &d.notAfterLimit,
	// 	false, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	validationOpts := ctfe.NewCertValidationOpts(d.roots, time.Time{},
		false, false, &d.notAfterStart, &d.notAfterLimit,
		false, nil)

	chain, err := ctfe.ValidateChain(req.Chain, validationOpts)
	if err != nil {
		return nil, http.StatusBadRequest, fmt.Errorf("unable to validate chain: %w", err)
	}

	isPrecert, err := ctfe.IsPrecertificate(chain[0])
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("invalid leaf certificate: %w", err)
	}

	if isPrecert != precertEndpoint {
		if precertEndpoint {
			return nil, http.StatusBadRequest, fmt.Errorf("expected precertificate, got certificate")
		} else {
			return nil, http.StatusBadRequest, fmt.Errorf("expected certificate, got precertificate")
		}
	}

	var entry sunlight.UnsequencedEntry

	entry.IsPrecert = isPrecert
	entry.CertificateFp = sha256.Sum256(chain[0].Raw)
	entry.Chain = chain[1:]
	for _, cert := range chain[1:] {
		entry.ChainFp = append(entry.ChainFp, sha256.Sum256(cert.Raw))
	}

	if !isPrecert {
		entry.Certificate = chain[0].Raw
	} else {
		entry.PreCertificate = chain[0].Raw

		// Preissuer means that the intermediate that issued the precert is only valid
		// for issuing precertificates.
		var preIssuer *x509.Certificate
		if ct.IsPreIssuer(chain[1]) {
			preIssuer = chain[1]
		}
		// This function requires preIssuer to be nil if the issuer is not a preissuer
		tbsCertficiate, err := x509.BuildPrecertTBS(chain[0].RawTBSCertificate, preIssuer)
		if err != nil {
			return nil, http.StatusInternalServerError, fmt.Errorf("unable to build precert TBS: %w", err)
		}

		entry.Certificate = tbsCertficiate
		entry.IssuerKeyHash = sha256.Sum256(chain[1].RawSubjectPublicKeyInfo)
	}

	// Before we send the unsequenced entry to the first stage, we need to check if it's a duplicate
	// This is done by hashing the certificate fingerprint and checking if it exists in the dedupe map
	dedupeKey := base64.StdEncoding.EncodeToString(entry.CertificateFp[:])
	dedupeVal, err := d.bucket.Get(ctx, fmt.Sprintf("ct/v1/dedupe/%s", dedupeKey))

	var completeEntry sunlight.LogEntry

	if err == nil {
		// If we recieved a valid cache hit, then the certificate is a duplicate
		buf := bytes.NewReader(dedupeVal)
		var leafIndex uint64
		var timestamp int64
		err := binary.Read(buf, binary.LittleEndian, &leafIndex)
		if err != nil {
			return nil, 500, err
		}
		err = binary.Read(buf, binary.LittleEndian, &timestamp)
		if err != nil {
			return nil, 500, err
		}
		completeEntry = entry.Sequence(leafIndex, timestamp)
	} else {
		// Otherwise, we need to send it to the sequencer

		// Send the unsequenced entry to the first stage
		returnPath := make(chan sunlight.LogEntry)
		d.stageOneTx <- UnsequencedEntryWithReturnPath{entry, returnPath}

		// TODO: Add a timeout with select
		// If we recieve something here, that means that the entry has been both sequenced
		// and uploaded with a newly signed STH, so we can issue a SCT.
		completeEntry = <-returnPath
	}

	extension, err := sunlight.MarshalExtensions(sunlight.Extensions{LeafIndex: completeEntry.LeafIndex})
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("unable to marshal extensions: %w", err)
	}

	sctSignature, err := sunlight.DigitallySign(d.signingKey, completeEntry.MerkleTreeLeaf())
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("unable to sign SCT: %w", err)
	}

	response, err := json.Marshal(ct.AddChainResponse{
		SCTVersion: ct.V1,
		Timestamp:  uint64(completeEntry.Timestamp),
		ID:         d.logID[:],
		Extensions: base64.StdEncoding.EncodeToString(extension),
		Signature:  sctSignature,
	})
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("unable to marshal json response: %w", err)
	}

	return response, http.StatusOK, nil
}

func (d *stageOneData) stageOne(
	ctx context.Context,
) error {
	const MAX_POOL_SIZE = 255
	// const FLUSH_INTERVAL = time.Second
	const FLUSH_INTERVAL = time.Millisecond * 100

	// This variable will be incremented for each log entry
	sequence := d.startingSequence
	// Create a vector to store the pool
	pool := make([]LogEntryWithReturnPath, 0, MAX_POOL_SIZE)
	// Create a time variable to track the last flush
	lastFlushTime := time.Now()

	// Loop over the channel and context
	for {
		select {

		// Wait for the next log entry
		case entry, ok := <-d.stageOneRx:
			if !ok {
				return fmt.Errorf("stage one: stageOneRx channel closed")
			}

			// Sequence the unsequenced entry
			logEntry := LogEntryWithReturnPath{
				entry.entry.Sequence(sequence, time.Now().UnixMilli()),
				entry.returnPath,
			}
			// Increment the sequence
			sequence++
			// Append the log entry to the pool
			pool = append(pool, logEntry)

			// Conditions to flush the pool
			if len(pool) >= MAX_POOL_SIZE || time.Since(lastFlushTime) >= FLUSH_INTERVAL {
				// Create a copy of the pool
				closedPool := make([]LogEntryWithReturnPath, len(pool))
				copy(closedPool, pool)

				// Clear the original pool
				pool = pool[:0]
				d.stageTwoTx <- closedPool

				// Update the last flush time
				lastFlushTime = time.Now()
			}

		// If the flush interval has passed, flush the pool
		case <-time.After(FLUSH_INTERVAL):
			if len(pool) > 0 {
				// Create a copy of the pool
				closedPool := make([]LogEntryWithReturnPath, len(pool))
				copy(closedPool, pool)

				// Clear the original pool
				pool = pool[:0]
				d.stageTwoTx <- closedPool
			}
			// Update the last flush time
			lastFlushTime = time.Now()

		case <-ctx.Done():
			return fmt.Errorf("stage one: context finished")
		}
	}
}

// Error handling in this function is done by just bailing if *anything* goes wrong.
// The best way to recover is to just reload the entire log.
func (d *stageTwoData) stageTwo(
	ctx context.Context,
) error {
	// Loop over the channel and context
	for {
		select {
		case pool, ok := <-d.stageTwoRx:
			if !ok {
				return fmt.Errorf("stage two: stageTwoRx channel closed")
			}

			// TODO: Process the pool

			// The current tree size is the same as the index of the first leaf in the pool
			oldTreeSize := pool[0].entry.LeafIndex
			// LeafIndex is zero-indexed, so the tree size is the last leaf index + 1
			newTreeSize := pool[len(pool)-1].entry.LeafIndex + 1

			// ** Upload the data tiles **
			newHashes := make(map[int64]tlog.Hash)
			// The newHashes map is a reference type, so adding elements to
			// newHashes will let the hashReader function look them up.
			hashReader := d.hashReader(newHashes)

			// these are the hashes of the merkle tree leaves and are needed later
			recordHashes := make([]struct {
				hash      tlog.Hash
				leafIndex int64
			}, 0, len(pool))

			// This is the right most data tile
			dataTile := d.edgeTiles[-1]

			for _, e := range pool {
				recordHash := tlog.RecordHash(e.entry.MerkleTreeLeaf())
				recordHashes = append(recordHashes, struct {
					hash      tlog.Hash
					leafIndex int64
				}{recordHash, int64(e.entry.LeafIndex)})
				hashes, err := tlog.StoredHashesForRecordHash(int64(e.entry.LeafIndex), recordHash, hashReader)
				if err != nil {
					return fmt.Errorf("failed to calculate new hashes for leaf %d: %w", e.entry.LeafIndex, err)
				}
				for i, hash := range hashes {
					index := tlog.StoredHashIndex(0, int64(e.entry.LeafIndex)) + int64(i)
					newHashes[index] = hash
				}

				dataTile.Bytes = sunlight.AppendTileLeaf(dataTile.Bytes, &e.entry)
				dataTile.Tile.W++

				// This means we have a full width tile that we can go ahead and upload
				if dataTile.Tile.W == sunlight.TileWidth {
					err := d.bucket.Set(ctx, dataTile.Path(), dataTile.Bytes)
					if err != nil {
						return fmt.Errorf("failed to upload data tile %v: %w", dataTile.Tile, err)
					}

					// Reset the width to zero
					dataTile.Tile.W = 0
					// Increment the tile index
					dataTile.Tile.N++
					// Clear the bytes
					dataTile.Bytes = []byte{}
				}
			}

			// upload the partial data tile
			if dataTile.Tile.W > 0 {
				err := d.bucket.Set(ctx, dataTile.Path(), dataTile.Bytes)
				if err != nil {
					return fmt.Errorf("failed to upload partial data tile %v: %w", dataTile.Tile, err)
				}
			}
			d.edgeTiles[-1] = dataTile

			// ** Upload the tree tiles **
			// TODO: review if the treesize should be a int64 instead, to align with the tlog apis.
			newEdgeTiles := maps.Clone(d.edgeTiles)
			treeTiles := tlog.NewTiles(sunlight.TileHeight, int64(oldTreeSize), int64(newTreeSize))
			for _, tile := range treeTiles {
				data, err := tlog.ReadTileData(tile, hashReader)
				if err != nil {
					return fmt.Errorf("failed to read tile data for tile %v: %w", tile, err)
				}
				err = d.bucket.Set(ctx, tile.Path(), data)
				if err != nil {
					return fmt.Errorf("failed to upload tile %v: %w", tile, err)
				}
				newEdgeTiles[tile.L] = tileWithBytes{tile, data}
			}
			d.edgeTiles = newEdgeTiles

			// ** Upload the v1 leaf record hash mappings **
			// TODO: this will literally blow up S3
			for _, recordHash := range recordHashes {
				indexBuf := new(bytes.Buffer)
				err := binary.Write(indexBuf, binary.LittleEndian, recordHash.leafIndex)
				if err != nil {
					return fmt.Errorf("failed to encode leaf record hash %d: %w", recordHash.leafIndex, err)
				}

				hashString := base64.StdEncoding.EncodeToString(recordHash.hash[:])

				err = d.bucket.Set(ctx, fmt.Sprintf("ct/v1/leaf-record-hash/%s", hashString), indexBuf.Bytes())
				if err != nil {
					return fmt.Errorf("failed to upload leaf record hash %d: %w", recordHash.leafIndex, err)
				}
			}

			// ** Upload new intermediate certificates **
			// TODO: this won't blow up S3, but we're certainly making far more requests than needed. add a cache.
			for _, e := range pool {
				for _, cert := range e.entry.Chain {
					fingerprint := sha256.Sum256(cert.Raw)
					err := d.bucket.Set(ctx, fmt.Sprintf("issuer/%x", fingerprint), cert.Raw)
					if err != nil {
						return fmt.Errorf("failed to upload issuer certificate %x: %w", fingerprint, err)
					}
				}
			}

			// ** Upload a new STH **
			rootHash, err := tlog.TreeHash(int64(newTreeSize), hashReader)
			if err != nil {
				return fmt.Errorf("failed to calculate new root hash: %w", err)
			}

			jsonBytes, err := sunlight.SignTreeHead(d.signingKey, newTreeSize, uint64(time.Now().UnixMilli()), rootHash)
			if err != nil {
				return fmt.Errorf("failed to generate a new STH: %w", err)
			}

			err = d.bucket.Set(ctx, "/ct/v1/get-sth", jsonBytes)
			if err != nil {
				return fmt.Errorf("failed to upload new STH: %w", err)
			}

			// ** Upload the dedupe mappings **
			// TODO: this will also blow up S3
			for _, e := range pool {
				// TODO: This isn't the best cache key, because it fails to distinguish between
				// a certificate that is submitted with a different chain. This is a problem because
				// I think the specific chain the certificate was submitted with also matters.
				dedupeKey := base64.StdEncoding.EncodeToString(e.entry.CertificateFp[:])

				dedupeVal := new(bytes.Buffer)
				err := binary.Write(dedupeVal, binary.LittleEndian, e.entry.LeafIndex)
				if err != nil {
					return fmt.Errorf("failed to encode leaf index %d: %w", e.entry.LeafIndex, err)
				}
				err = binary.Write(dedupeVal, binary.LittleEndian, e.entry.Timestamp)
				if err != nil {
					return fmt.Errorf("failed to encode timestamp %d: %w", e.entry.Timestamp, err)
				}

				err = d.bucket.Set(ctx, fmt.Sprintf("ct/v1/dedupe/%s", dedupeKey), dedupeVal.Bytes())
				if err != nil {
					// TODO: sunlight doesn't make this a hard failure, should we?
					return fmt.Errorf("failed to upload dedupe mapping for %s: %w", dedupeKey, err)
				}
			}

			// ** Everything is uploaded, return the log entries **
			for _, entry := range pool {
				entry.returnPath <- entry.entry
			}

		case <-ctx.Done():
			return fmt.Errorf("stage two: context finished")
		}
	}
}

func (d *stageTwoData) hashReader(overlay map[int64]tlog.Hash) tlog.HashReaderFunc {
	return func(indexes []int64) ([]tlog.Hash, error) {
		hashes := make([]tlog.Hash, 0, len(indexes))
		for _, index := range indexes {
			if hash, ok := overlay[index]; ok {
				hashes = append(hashes, hash)
			} else {
				tile := d.edgeTiles[tlog.TileForIndex(sunlight.TileHeight, index).L]
				hash, err := tlog.HashFromTile(tile.Tile, tile.Bytes, index)
				if err != nil {
					return nil, fmt.Errorf("index %d not in overlay and %w", index, err)
				}
				hashes = append(hashes, hash)
			}
		}
		return hashes, nil
	}
}

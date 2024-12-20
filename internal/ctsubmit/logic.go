package ctsubmit

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
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
	"golang.org/x/sync/errgroup"
	"itko.dev/internal/sunlight"
)

// TODO: Evaluate if the context is actually needed
func (l *Log) Start(ctx context.Context) (http.Handler, error) {
	// Start the stages
	go func() {
		err := l.stageOneData.stageOne(ctx)
		fmt.Printf("Error in stageOne: %v\n", err)
		fmt.Println("Stopping log now!")
		l.eStop.Unlock()
	}()
	go func() {
		err := l.stageTwoData.stageTwo(ctx)
		fmt.Printf("Error in stageTwo: %v\n", err)
		fmt.Println("Stopping log now!")
		l.eStop.Unlock()
	}()

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
		issuer := chain[1]
		if ct.IsPreIssuer(chain[1]) {
			preIssuer = chain[1]
			issuer = chain[2]
		}

		// This function requires preIssuer to be nil if the issuer is not a preissuer
		tbsCertficiate, err := x509.BuildPrecertTBS(chain[0].RawTBSCertificate, preIssuer)
		if err != nil {
			return nil, http.StatusInternalServerError, fmt.Errorf("unable to build precert TBS: %w", err)
		}

		entry.Certificate = tbsCertficiate
		entry.IssuerKeyHash = sha256.Sum256(issuer.RawSubjectPublicKeyInfo)
	}

	// Before we send the unsequenced entry to the first stage, we need to check if it's a duplicate
	// This is done by hashing the certificate fingerprint and checking if it exists in the dedupe map
	dedupeKey := [16]byte(entry.CertificateFp[:16])
	dedupeVal, err := d.bucket.GetDedupeEntry(ctx, dedupeKey, d.maskSize)

	var completeEntry sunlight.LogEntry

	if err == nil {
		// If we recieved a valid cache hit, then the certificate is a duplicate
		completeEntry = entry.Sequence(dedupeVal.leafIndex, dedupeVal.timestamp)
	} else {
		// Otherwise, we need to send it to the sequencer

		// Send the unsequenced entry to the first stage
		// This channel is buffered so it doesn't block if an attempt is made to send
		// after the timeout fires.
		returnPath := make(chan sunlight.LogEntry, 1)
		d.stageOneTx <- UnsequencedEntryWithReturnPath{entry, returnPath}

		// If we recieve something here, that means that the entry has been both sequenced
		// and uploaded with a newly signed STH, so we can issue a SCT.
		select {
		case completeEntry = <-returnPath:
		// Nominally, this should complete in under 2 seconds.
		case <-time.After(5 * time.Second):
			return nil, http.StatusServiceUnavailable, fmt.Errorf("timed out waiting for sequencer")
		}
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
	var FLUSH_INTERVAL = time.Millisecond * time.Duration(d.flushMs)

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
			// Create a copy of the pool
			closedPool := make([]LogEntryWithReturnPath, len(pool))
			copy(closedPool, pool)

			// Clear the original pool
			pool = pool[:0]
			d.stageTwoTx <- closedPool
			
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

			// ** Upload the data tiles **
			newHashes := make(map[int64]tlog.Hash)
			// The newHashes map is a reference type, so adding elements to
			// newHashes will let the hashReader function look them up.
			hashReader := d.hashReader(newHashes)
			// This value is written back to the struct the new sth is written.
			updatedTreeSize := d.treeSize

			if len(pool) != 0 {

				// Errgroup to safely parallelize the uploads
				g, gctx := errgroup.WithContext(ctx)

				// The current tree size is the same as the index of the first leaf in the pool
				oldTreeSize := pool[0].entry.LeafIndex
				// LeafIndex is zero-indexed, so the tree size is the last leaf index + 1
				newTreeSize := pool[len(pool)-1].entry.LeafIndex + 1
				updatedTreeSize = newTreeSize

				// these are the hashes of the merkle tree leaves and are needed later
				recordHashes := make([]RecordHashUpload, 0, len(pool))

				// This is the right most data tile
				dataTile := d.edgeTiles[-1]
				if dataTile.Tile.W > sunlight.TileWidth {
					return fmt.Errorf("tile width is greater than the maximum width!! %d", dataTile.Tile.W)
				} else if dataTile.Tile.W == sunlight.TileWidth {
					// If the tile is full, reset it so we have a partial
					// Reset the width to zero
					dataTile.Tile.W = 0
					// Increment the tile index
					dataTile.Tile.N++
					// Clear the bytes
					dataTile.Bytes = []byte{}
				}

				for _, e := range pool {
					recordHash := tlog.RecordHash(e.entry.MerkleTreeLeaf())
					recordHashShort := [16]byte(recordHash[:16])
					recordHashes = append(recordHashes, RecordHashUpload{
						hash:      recordHashShort,
						leafIndex: e.entry.LeafIndex,
					})
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
					if dataTile.Tile.W > sunlight.TileWidth {
						return fmt.Errorf("tile width is greater than the maximum width!!! %d", dataTile.Tile.W)
					} else if dataTile.Tile.W == sunlight.TileWidth {
						// Upload the tile
						t := dataTile
						g.Go(func() error { return d.bucket.SetTile(gctx, t.Tile, t.Bytes) })
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
					t := dataTile
					g.Go(func() error { return d.bucket.SetTile(gctx, t.Tile, t.Bytes) })
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
					g.Go(func() error { return d.bucket.SetTile(gctx, tile, data) })
					if err != nil {
						return fmt.Errorf("failed to upload tile %v: %w", tile, err)
					}
					newEdgeTiles[tile.L] = tileWithBytes{tile, data}
				}
				d.edgeTiles = newEdgeTiles

				// ** Upload the v1 leaf record hash mappings **
				g.Go(func() error { return d.bucket.PutRecordHashes(gctx, recordHashes, d.maskSize) })

				// ** Upload new intermediate certificates **
				for _, e := range pool {
					for _, cert := range e.entry.Chain {
						g.Go(func() error { return d.bucket.SetIssuer(gctx, cert) })
					}
				}

				err := g.Wait()
				if err != nil {
					return fmt.Errorf("failed to upload data: %w", err)
				}

			}

			// ** Upload a new STH **
			rootHash, err := tlog.TreeHash(int64(updatedTreeSize), hashReader)
			if err != nil {
				return fmt.Errorf("failed to calculate new root hash: %w", err)
			}

			jsonBytes, err := sunlight.SignTreeHead(d.signingKey, updatedTreeSize, uint64(time.Now().UnixMilli()), rootHash)
			if err != nil {
				return fmt.Errorf("failed to generate a new STH: %w", err)
			}

			err = d.bucket.SetSth(ctx, jsonBytes)
			if err != nil {
				return fmt.Errorf("failed to upload new STH: %w", err)
			}

			// we also upload a checkpoint based on the STH
			checkpointBytes, err := sunlight.SignTreeHeadCheckpoint(d.checkpointOrigin, d.signingKey, int64(updatedTreeSize), time.Now().UnixMilli(), rootHash)
			if err != nil {
				return fmt.Errorf("failed to generate a new checkpoint: %w", err)
			}

			err = d.bucket.SetCheckpoint(ctx, checkpointBytes)
			if err != nil {
				return fmt.Errorf("failed to upload new checkpoint: %w", err)
			}

			// Update the tree size once the checkpoints are uploaded
			d.treeSize = updatedTreeSize

			// ** Upload the dedupe mappings **
			// TODO: This isn't the best cache key, because it fails to distinguish between
			// a certificate that is submitted with a different chain. This is a problem because
			// I think the specific chain the certificate was submitted with also matters.
			dedupeVals := make([]DedupeUpload, 0, len(pool))
			for _, e := range pool {
				hash := [16]byte(e.entry.CertificateFp[:16])
				dedupeVals = append(dedupeVals, DedupeUpload{
					hash:      hash,
					leafIndex: e.entry.LeafIndex,
					timestamp: e.entry.Timestamp,
				})
			}
			err = d.bucket.PutDedupeEntries(ctx, dedupeVals, d.maskSize)
			if err != nil {
				return fmt.Errorf("failed to upload dedupe mappings: %w", err)
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

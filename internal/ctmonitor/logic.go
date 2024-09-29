package ctmonitor

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"golang.org/x/mod/sumdb/tlog"
	"itko.dev/internal/sunlight"
)

// TODO: Evaluate if the context is actually needed
func Start(ctx context.Context, tileStoreDir string, tileStoreUrl string, maskSize int) (http.Handler, error) {
	var f Fetch
	maxGetEntry := 1024

	if tileStoreDir != "" {
		storage := &FsStorage{root: tileStoreDir}
		f = newFetch(storage, maskSize, maxGetEntry)
	} else {
		storage := &UrlStorage{urlPrefix: tileStoreUrl}
		f = newFetch(storage, maskSize, maxGetEntry)
	}

	// Wrap the HTTP handler function with OTel instrumentation
	wGetSth := otelhttp.NewHandler(http.HandlerFunc(wrapper(f.get_sth)), "get-sth")
	wGetSthConsistency := otelhttp.NewHandler(http.HandlerFunc(wrapper(f.get_sth_consistency)), "get-sth-consistency")
	wGetProofByHash := otelhttp.NewHandler(http.HandlerFunc(wrapper(f.get_proof_by_hash)), "get-proof-by-hash")
	wGetEntries := otelhttp.NewHandler(http.HandlerFunc(wrapper(f.get_entries)), "get-entries")
	wGetRoots := otelhttp.NewHandler(http.HandlerFunc(wrapper(f.get_roots)), "get-roots")
	wGetEntryAndProof := otelhttp.NewHandler(http.HandlerFunc(wrapper(f.get_entry_and_proof)), "get-entry-and-proof")

	// Create a new HTTP server mux and start listening
	mux := http.NewServeMux()
	mux.Handle("GET /ct/v1/get-sth", wGetSth)
	mux.Handle("GET /ct/v1/get-sth-consistency", wGetSthConsistency)
	mux.Handle("GET /ct/v1/get-proof-by-hash", wGetProofByHash)
	mux.Handle("GET /ct/v1/get-entries", wGetEntries)
	mux.Handle("GET /ct/v1/get-roots", wGetRoots)
	mux.Handle("GET /ct/v1/get-entry-and-proof", wGetEntryAndProof)

	return http.MaxBytesHandler(mux, 128*1024), nil
}

func wrapper(wrapped func(ctx context.Context, reqBody io.ReadCloser, query url.Values) (resp []byte, code int, err error)) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		resp, code, err := wrapped(r.Context(), r.Body, query)
		if err != nil {
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
}

func hashreader(ctx context.Context, f Fetch, fallbackTreeSize int64) tlog.HashReaderFunc {
	// Tree size is 1 greater than the index of the last entry
	finalTile := tlog.TileForIndex(sunlight.TileHeight, tlog.StoredHashIndex(0, fallbackTreeSize-1))
	// TODO: add some sort of cache here, this function is bound to be called a few times for the same tiles
	return func(indexes []int64) ([]tlog.Hash, error) {
		hashes := make([]tlog.Hash, 0, len(indexes))
		for _, index := range indexes {
			tile := tlog.TileForIndex(sunlight.TileHeight, index)
			// Special case the final tile to get the correct width
			if tile.N == finalTile.N {
				tile.W = finalTile.W
			}
			// This function will always first try and get the full width tile,
			// and then fall back to the width actually specified in the tile.
			data, err := f.getTile(ctx, tile)
			if err != nil {
				return nil, fmt.Errorf("failed to fetch tile %s: %w (fallback %s)", sunlight.Path(tile), err, sunlight.Path(finalTile))
			}
			hash, err := tlog.HashFromTile(tile, data, index)
			if err != nil {
				return nil, err
			}
			hashes = append(hashes, hash)
		}
		return hashes, nil
	}
}

type tileWithBytes struct {
	tile  tlog.Tile
	bytes []byte
}

// TODO: Remove the wrapper from this endpoint and have it instead stream the response
func (f Fetch) get_sth(ctx context.Context, reqBody io.ReadCloser, query url.Values) (resp []byte, code int, err error) {
	resp, err = f.get(ctx, "ct/v1/get-sth")
	if err != nil {
		return nil, 503, err
	}
	return resp, 200, nil
}

func (f Fetch) get_sth_consistency(ctx context.Context, reqBody io.ReadCloser, query url.Values) (resp []byte, code int, err error) {
	// Get and decode the first tree size parameter
	firstStr := query.Get("first")
	if firstStr == "" {
		return nil, 400, err
	}
	first, err := strconv.ParseInt(firstStr, 10, 64)
	if err != nil {
		return nil, 400, err
	}
	// Get and decode the second tree size parameter
	secondStr := query.Get("second")
	if secondStr == "" {
		return nil, 400, err
	}
	second, err := strconv.ParseInt(secondStr, 10, 64)
	if err != nil {
		return nil, 400, err
	}

	if first < 0 || second < 0 {
		return nil, 400, fmt.Errorf("parameters must be positive")
	}

	if first > second {
		return nil, 400, fmt.Errorf("first must be less than or equal to second")
	}

	sth, err := f.getSth(ctx)
	if err != nil {
		// TODO: Fix all the response status codes
		return nil, 521, err
	}

	if first > int64(sth.TreeSize) || second > int64(sth.TreeSize) {
		return nil, 400, fmt.Errorf("tree size out of range")
	}

	// Get the consistency proof
	var proof tlog.TreeProof

	// If the first tree size is 0, then the prove tree function returns an error.
	// However, as per the spec, in this case, an empty proof should be returned
	// TODO: this fails if the size of the first tree is greater than the actual number of records in the tree
	if first >= 1 {
		proof, err = tlog.ProveTree(second, first, hashreader(ctx, f, second))
		if err != nil {
			return nil, 523, err
		}
	}

	// why you make me do this golang
	proofBytes := make([][]byte, len(proof))
	for i, p := range proof {
		proofBytes[i] = p[:]
	}

	response := ct.GetSTHConsistencyResponse{
		Consistency: proofBytes,
	}

	jsonBytes, err := json.Marshal(response)
	if err != nil {
		return nil, 524, err
	}

	return jsonBytes, 200, nil
}

func (f Fetch) get_proof_by_hash(ctx context.Context, reqBody io.ReadCloser, query url.Values) (resp []byte, code int, err error) {
	// Get and decode the hash parameter
	hashBase64 := query.Get("hash")
	if hashBase64 == "" {
		return nil, 400, err
	}
	hash, err := base64.StdEncoding.DecodeString(hashBase64)
	if err != nil {
		return nil, 400, err
	}
	if len(hash) != 32 {
		return nil, 400, fmt.Errorf("hash must be 32 bytes")
	}

	// Get and parse the tree_size parameter
	treeSizeStr := query.Get("tree_size")
	if treeSizeStr == "" {
		return nil, 400, err

	}
	treeSize, err := strconv.ParseInt(treeSizeStr, 10, 64)
	if err != nil {
		return nil, 400, err
	}

	sth, err := f.getSth(ctx)
	if err != nil {
		return nil, 500, err
	}
	if treeSize > int64(sth.TreeSize) {
		return nil, 400, fmt.Errorf("tree size is larger than the current sth")
	}

	// Use the hash to fetch the index
	index, err := f.getIndexForHash(ctx, hash[:16])
	if err != nil {
		return nil, 404, err
	}

	if index < 0 || index >= treeSize {
		return nil, 400, fmt.Errorf("index out of range")
	}

	// Get the proof
	proof, err := tlog.ProveRecord(treeSize, index, hashreader(ctx, f, treeSize))
	if err != nil {
		log.Println(err)
		return nil, 511, err
	}

	// why you make me do this golang
	proofBytes := make([][]byte, len(proof))
	for i, p := range proof {
		proofBytes[i] = p[:]
	}

	response := ct.GetProofByHashResponse{
		LeafIndex: index,
		AuditPath: proofBytes,
	}

	jsonBytes, err := json.Marshal(response)
	if err != nil {
		return nil, 512, err
	}

	return jsonBytes, 200, nil
}

func (f Fetch) get_entries(ctx context.Context, reqBody io.ReadCloser, query url.Values) (resp []byte, code int, err error) {
	// Get and decode the start index parameter
	startStr := query.Get("start")
	if startStr == "" {
		return nil, 400, err
	}
	start, err := strconv.ParseInt(startStr, 10, 64)
	if err != nil {
		return nil, 400, err
	}
	// Get and decode the end index parameter
	endStr := query.Get("end")
	if endStr == "" {
		return nil, 400, err
	}
	end, err := strconv.ParseInt(endStr, 10, 64)
	if err != nil {
		return nil, 400, err
	}

	if start > end {
		return nil, 400, fmt.Errorf("start must be less than or equal to end")
	}

	if start < 0 || end < 0 {
		return nil, 400, fmt.Errorf("start and end must be positive")
	}

	// Limit the number of entries fetched at once
	limit := int64(f.maxGetEntry)
	if end-start > limit {
		end = start + limit
	}

	sth, err := f.getSth(ctx)
	if err != nil {
		return nil, 521, err
	}
	if end >= int64(sth.TreeSize) {
		end = int64(sth.TreeSize) - 1
	}

	// Get the first and last tiles, -1 signifies a data tile
	firstTile := tlog.TileForIndex(sunlight.TileHeight, tlog.StoredHashIndex(0, start))
	firstTile.L = -1
	lastTile := tlog.TileForIndex(sunlight.TileHeight, tlog.StoredHashIndex(0, end))
	lastTile.L = -1

	dataTiles := make([]tileWithBytes, 0)

	sthFinalTile := tlog.TileForIndex(sunlight.TileHeight, tlog.StoredHashIndex(0, int64(sth.TreeSize)-1))
	// Special case the final tile to ensure we always fetch a tile that exists
	if lastTile.N == sthFinalTile.N {
		lastTile.W = sthFinalTile.W
	}

	// In this case, the last tile is the same as the first tile so we only need to fetch one tile
	if firstTile.N == lastTile.N {
		data, err := f.getTile(ctx, lastTile)
		if err != nil {
			return nil, 513, err
		}
		dataTiles = append(dataTiles, tileWithBytes{lastTile, data})
	} else {
		{
			// If the index of the last tile is greater than the index of the first tile,
			// it means the first tile is complete
			firstTile.W = 256
			data, err := f.getTile(ctx, firstTile)
			if err != nil {
				return nil, 514, err
			}
			dataTiles = append(dataTiles, tileWithBytes{firstTile, data})
		}

		{
			// We also need to fetch all the tiles in middle. Here, we sort of just
			// need to define the tile ourselves and fetch it
			for i := firstTile.N + 1; i < lastTile.N; i++ {
				tile := tlog.Tile{
					H: sunlight.TileHeight,
					L: -1,
					N: i,
					W: 256,
				}

				data, err := f.getTile(ctx, tile)
				if err != nil {
					return nil, 515, err
				}
				dataTiles = append(dataTiles, tileWithBytes{tile, data})
			}

		}

		{
			// Finally, fetch the last tile
			data, err := f.getTile(ctx, lastTile)
			if err != nil {
				return nil, 516, err
			}
			dataTiles = append(dataTiles, tileWithBytes{lastTile, data})
		}
	}

	// Now we need to parse the data tiles into entries
	var entries []*sunlight.LogEntry
	for _, tile := range dataTiles {
		rest := tile.bytes
		for len(rest) > 0 {
			entry, nextRest, err := sunlight.ReadTileLeaf(rest)
			if err != nil {
				return nil, 517, err
			}
			if entry.LeafIndex >= uint64(start) && entry.LeafIndex <= uint64(end) {
				entries = append(entries, entry)
			}
			rest = nextRest
		}
	}

	ctLeafEntries := make([]ct.LeafEntry, 0, len(entries))

outerloop:
	for _, entry := range entries {
		merkleTreeLeaf := entry.MerkleTreeLeaf()

		// TODO: add a cache here
		chain := make([]ct.ASN1Cert, 0, len(entry.ChainFp))
		for _, fp := range entry.ChainFp {
			if f.s.AvailableReqs() == 0 {
				break outerloop
			}

			data, err := f.get(ctx, fmt.Sprintf("issuer/%x", fp))
			if err != nil {
				return nil, 518, err
			}
			chain = append(chain, ct.ASN1Cert{Data: data})
		}

		var extra interface{}
		if entry.IsPrecert {
			extra = ct.PrecertChainEntry{
				PreCertificate:   ct.ASN1Cert{Data: entry.PreCertificate},
				CertificateChain: chain,
			}
		} else {
			extra = ct.CertificateChain{Entries: chain}
		}

		extraData, err := tls.Marshal(extra)
		if err != nil {
			return nil, 519, err
		}

		leafEntry := ct.LeafEntry{
			LeafInput: merkleTreeLeaf,
			ExtraData: extraData,
		}
		ctLeafEntries = append(ctLeafEntries, leafEntry)
	}

	response := ct.GetEntriesResponse{
		Entries: ctLeafEntries,
	}

	jsonBytes, err := json.Marshal(response)
	if err != nil {
		return nil, 520, err
	}

	return jsonBytes, 200, nil
}

// TODO: Remove the wrapper from this endpoint and have it instead stream the response
func (f Fetch) get_roots(ctx context.Context, reqBody io.ReadCloser, query url.Values) (resp []byte, code int, err error) {
	resp, err = f.get(ctx, "ct/v1/get-roots")
	if err != nil {
		return nil, 503, err
	}
	return resp, 200, nil
}

func (f Fetch) get_entry_and_proof(ctx context.Context, reqBody io.ReadCloser, query url.Values) (resp []byte, code int, err error) {
	// Get and decode the leaf index parameter
	leafIndexStr := query.Get("leaf_index")
	if leafIndexStr == "" {
		return nil, 400, err
	}
	leafIndex, err := strconv.ParseInt(leafIndexStr, 10, 64)
	if err != nil {
		return nil, 400, err
	}
	// Get and decode the tree size parameter
	treeSizeStr := query.Get("tree_size")
	if treeSizeStr == "" {
		return nil, 400, err
	}
	treeSize, err := strconv.ParseInt(treeSizeStr, 10, 64)
	if err != nil {
		return nil, 400, err
	}

	if leafIndex < 0 || leafIndex >= treeSize {
		return nil, 400, fmt.Errorf("index out of range")
	}

	sth, err := f.getSth(ctx)
	if err != nil {
		return nil, 500, err
	}
	if treeSize > int64(sth.TreeSize) {
		return nil, 400, fmt.Errorf("tree size is larger than the current sth")
	}

	// Get the entry
	tile := tlog.TileForIndex(sunlight.TileHeight, tlog.StoredHashIndex(0, leafIndex))
	tile.L = -1

	// TODO: add a cache
	data, err := f.getTile(ctx, tile)
	if err != nil {
		return nil, 500, err
	}

	var leafEntry *sunlight.LogEntry

	rest := data
	for len(rest) > 0 {
		entry, nextRest, err := sunlight.ReadTileLeaf(rest)
		if err != nil {
			return nil, 500, err
		}
		if entry.LeafIndex == uint64(leafIndex) {
			leafEntry = entry
			break
		}
		rest = nextRest
	}

	if leafEntry == nil {
		return nil, 404, fmt.Errorf("entry not found")
	}

	merkleTreeLeaf := leafEntry.MerkleTreeLeaf()

	// TODO: add a cache here
	chain := make([]ct.ASN1Cert, 0, len(leafEntry.ChainFp))
	for _, fp := range leafEntry.ChainFp {
		data, err := f.get(ctx, fmt.Sprintf("issuer/%x", fp))
		if err != nil {
			return nil, 500, err
		}
		chain = append(chain, ct.ASN1Cert{Data: data})
	}

	var extra interface{}
	if leafEntry.IsPrecert {
		extra = ct.PrecertChainEntry{
			PreCertificate:   ct.ASN1Cert{Data: leafEntry.PreCertificate},
			CertificateChain: chain,
		}
	} else {
		extra = ct.CertificateChain{Entries: chain}
	}

	extraData, err := tls.Marshal(extra)
	if err != nil {
		return nil, 500, err
	}

	// Get the proof
	proof, err := tlog.ProveRecord(treeSize, leafIndex, hashreader(ctx, f, treeSize))
	if err != nil {
		return nil, 500, err
	}

	// why you make me do this golang
	proofBytes := make([][]byte, len(proof))
	for i, p := range proof {
		proofBytes[i] = p[:]
	}

	response := ct.GetEntryAndProofResponse{
		LeafInput: merkleTreeLeaf,
		ExtraData: extraData,
		AuditPath: proofBytes,
	}

	jsonBytes, err := json.Marshal(response)
	if err != nil {
		return nil, 500, err
	}

	return jsonBytes, 200, nil
}

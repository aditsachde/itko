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
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"golang.org/x/mod/sumdb/tlog"
	"itko.dev/internal/sunlight"
)

// TODO: Evaluate if the context is actually needed
func Start(ctx context.Context, tileStoreUrl string) (http.Handler, error) {
	f := newFetch(tileStoreUrl)

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

func hashreader(ctx context.Context, f Fetch) tlog.HashReaderFunc {
	// TODO: add some sort of cache here, this function is bound to be called a few times for the same tiles
	return func(indexes []int64) ([]tlog.Hash, error) {
		hashes := make([]tlog.Hash, 0, len(indexes))
		for _, index := range indexes {
			tile := tlog.TileForIndex(sunlight.TileHeight, index)
			data, err := f.get(ctx, tile.Path())
			if err != nil {
				return nil, err
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

func (f Fetch) get_sth(ctx context.Context, reqBody io.ReadCloser, query url.Values) (resp []byte, code int, err error) {
	resp, err = f.get(ctx, "ct/v1/get-sth")
	if err != nil {
		return nil, 503, err
	}
	return resp, 200, nil
}

func (f Fetch) get_sth_consistency(ctx context.Context, reqBody io.ReadCloser, query url.Values) (resp []byte, code int, err error) {
	return nil, 403, nil
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

	// print the hash
	log.Printf("hash: %x", hash)

	// Get and parse the tree_size parameter
	treeSizeStr := query.Get("tree_size")
	if treeSizeStr == "" {
		return nil, 400, err

	}
	treeSize, err := strconv.ParseInt(treeSizeStr, 10, 64)
	if err != nil {
		return nil, 400, err
	}

	index := int64(0)

	if index < 0 || index >= treeSize {
		return nil, 400, fmt.Errorf("index out of range")
	}

	proof, err := tlog.ProveRecord(treeSize, index, hashreader(ctx, f))
	if err != nil {
		return nil, 500, err
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
		return nil, 500, err
	}

	return jsonBytes, 200, nil
}

func (f Fetch) get_entries(ctx context.Context, reqBody io.ReadCloser, query url.Values) (resp []byte, code int, err error) {
	return nil, 403, nil
}

func (f Fetch) get_roots(ctx context.Context, reqBody io.ReadCloser, query url.Values) (resp []byte, code int, err error) {
	resp, err = f.get(ctx, "ct/v1/get-roots")
	if err != nil {
		return nil, 503, err
	}
	return resp, 200, nil
}

func (f Fetch) get_entry_and_proof(ctx context.Context, reqBody io.ReadCloser, query url.Values) (resp []byte, code int, err error) {
	return nil, 403, nil
}

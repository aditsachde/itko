package ctmonitor

import (
	"context"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

// TODO: Evaluate if the context is actually needed
func Start(ctx context.Context, tileStore string) (http.Handler, error) {
	// Wrap the HTTP handler function with OTel instrumentation
	wGetSth := otelhttp.NewHandler(http.HandlerFunc(wrapper(get_sth)), "get-sth")
	wGetSthConsistency := otelhttp.NewHandler(http.HandlerFunc(wrapper(get_sth_consistency)), "get-sth-consistency")
	wGetProofByHash := otelhttp.NewHandler(http.HandlerFunc(wrapper(get_proof_by_hash)), "get-proof-by-hash")
	wGetEntries := otelhttp.NewHandler(http.HandlerFunc(wrapper(get_entries)), "get-entries")
	wGetRoots := otelhttp.NewHandler(http.HandlerFunc(wrapper(get_roots)), "get-roots")
	wGetEntryAndProof := otelhttp.NewHandler(http.HandlerFunc(wrapper(get_entry_and_proof)), "get-entry-and-proof")

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

func wrapper(wrapped func(ctx context.Context, reqBody io.ReadCloser) (resp []byte, code int, err error)) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		resp, code, err := wrapped(r.Context(), r.Body)
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

func get_sth(ctx context.Context, reqBody io.ReadCloser) (resp []byte, code int, err error) {
	return nil, 403, nil
}

func get_sth_consistency(ctx context.Context, reqBody io.ReadCloser) (resp []byte, code int, err error) {
	return nil, 403, nil
}

func get_proof_by_hash(ctx context.Context, reqBody io.ReadCloser) (resp []byte, code int, err error) {
	return nil, 403, nil
}

func get_entries(ctx context.Context, reqBody io.ReadCloser) (resp []byte, code int, err error) {
	return nil, 403, nil
}

func get_roots(ctx context.Context, reqBody io.ReadCloser) (resp []byte, code int, err error) {
	return nil, 403, nil
}

func get_entry_and_proof(ctx context.Context, reqBody io.ReadCloser) (resp []byte, code int, err error) {
	return nil, 403, nil
}

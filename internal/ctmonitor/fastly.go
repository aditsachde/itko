package ctmonitor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/url"

	"github.com/fastly/compute-sdk-go/configstore"
	"github.com/fastly/compute-sdk-go/fsthttp"
)

// The log needs two configs, the backend service name and the mask size.
// These can be fetched from edge config but for now we will hard code them.
const configStoreName = "hostmap"
const maskSize = 5

func FastlyServe(ctx context.Context, w fsthttp.ResponseWriter, r *fsthttp.Request) {
	if r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH" || r.Method == "DELETE" {
		w.WriteHeader(fsthttp.StatusMethodNotAllowed)
		fmt.Fprintf(w, "This method is not allowed\n")
		return
	}

	config, err := configstore.Open(configStoreName)
	if err != nil {
		w.WriteHeader(fsthttp.StatusInternalServerError)
		log.Println("Error opening config store: %v\n", err)
		return
	}

	backend, err := config.Get(r.Host)
	if err != nil {
		w.WriteHeader(fsthttp.StatusNotFound)
		fmt.Fprintln(w, "Not found")
		return
	}

	s := &FastlyStorage{backend}
	f := newFetch(s, maskSize)

	if r.URL.Path == "/ct/v1/get-sth-consistency" {
		FastlyWrapper(f.get_sth_consistency)(ctx, w, r)
	} else if r.URL.Path == "/ct/v1/get-proof-by-hash" {
		FastlyWrapper(f.get_proof_by_hash)(ctx, w, r)
	} else if r.URL.Path == "/ct/v1/get-entries" {
		FastlyWrapper(f.get_entries)(ctx, w, r)
	} else if r.URL.Path == "/ct/v1/get-entry-and-proof" {
		FastlyWrapper(f.get_entry_and_proof)(ctx, w, r)
	} else if r.URL.Path == "/" {
		w.WriteHeader(fsthttp.StatusOK)
		fmt.Fprintln(w, "OK\nhttps://github.com/aditsachde/itko?tab=readme-ov-file#public-instance")
	} else {
		path := r.URL.Path
		if len(path) > 0 && path[0] == '/' {
			path = path[1:]
		}

		data, notfound, err := s.Get(ctx, r.URL.Path)

		if notfound {
			w.WriteHeader(fsthttp.StatusNotFound)
			fmt.Fprintln(w, "Not found")
			return
		}
		if err != nil {
			w.WriteHeader(fsthttp.StatusInternalServerError)
			fmt.Fprintln(w, "Error fetching data")
			return
		}

		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(data)
	}
}

func FastlyWrapper(wrapped func(ctx context.Context, reqBody io.ReadCloser, query url.Values) (resp []byte, code int, err error)) func(c context.Context, w fsthttp.ResponseWriter, r *fsthttp.Request) {
	return func(c context.Context, w fsthttp.ResponseWriter, r *fsthttp.Request) {
		log.Println("Path:", r.URL.Path, "Method:", r.Method, "Query:", r.URL.Query())

		query := r.URL.Query()
		resp, code, err := wrapped(c, r.Body, query)

		if err != nil {
			if code == fsthttp.StatusServiceUnavailable {
				w.Header().Set("Retry-After", fmt.Sprintf("%d", 30+rand.Intn(60)))
				fsthttp.Error(w, "pool full", code)
			} else {
				fsthttp.Error(w, err.Error(), code)
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

type FastlyStorage struct {
	backend string
}

func (f *FastlyStorage) Get(ctx context.Context, key string) (data []byte, notfounderr bool, err error) {
	url := fmt.Sprintf("https://%s/%s", f.backend, key)

	req, err := fsthttp.NewRequest("GET", url, nil)
	if err != nil {
		return nil, false, err
	}
	resp, err := req.Send(ctx, f.backend)
	if err != nil {
		return nil, false, err
	}
	if resp.StatusCode != 200 {
		if resp.StatusCode == 404 {
			return nil, true, errors.New(fsthttp.StatusText(resp.StatusCode))
		} else {
			return nil, false, errors.New(fsthttp.StatusText(resp.StatusCode))
		}
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, false, err
	}
	return body, false, nil
}

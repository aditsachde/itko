package ctmonitor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/fastly/compute-sdk-go/cache/simple"
	"github.com/fastly/compute-sdk-go/configstore"
	"github.com/fastly/compute-sdk-go/fsthttp"
)

// The log needs two configs, the backend service name and the mask size.
// These can be fetched from edge config but for now we will hard code them.
const configStoreName = "hostmap"
const maskSize = 5
const requestLimit = 10

func FastlyServe(ctx context.Context, w fsthttp.ResponseWriter, r *fsthttp.Request) {
	if r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH" || r.Method == "DELETE" {
		w.WriteHeader(fsthttp.StatusMethodNotAllowed)
		fmt.Fprintf(w, "This method is not allowed\n")
		return
	}

	config, err := configstore.Open(configStoreName)
	if err != nil {
		w.WriteHeader(fsthttp.StatusInternalServerError)
		log.Printf("Error opening config store: %v\n", err)
		return
	}

	backend, err := config.Get(r.Host)
	if err != nil {
		w.WriteHeader(fsthttp.StatusNotFound)
		fmt.Fprintln(w, "Backend not found!!!")
		return
	}

	s := &FastlyStorage{
		backend:  backend,
		cache:    make(map[string]*CacheEntry),
		requests: 0,
	}
	f := newFetch(s, maskSize, 75) // Limit get-entries to 75

	if r.URL.Path == "/ct/v1/get-sth-consistency" {
		FastlyWrapper(f.get_sth_consistency)(ctx, w, r)
	} else if r.URL.Path == "/ct/v1/get-proof-by-hash" {
		FastlyWrapper(f.get_proof_by_hash)(ctx, w, r)
	} else if r.URL.Path == "/ct/v1/get-entries" {
		FastlyWrapper(f.get_entries)(ctx, w, r)
	} else if r.URL.Path == "/ct/v1/get-entry-and-proof" {
		FastlyWrapper(f.get_entry_and_proof)(ctx, w, r)
	} else {
		w.WriteHeader(fsthttp.StatusNotFound)
		fmt.Fprintln(w, "Not found!!!")
		return
	}
}

func FastlyWrapper(wrapped func(ctx context.Context, reqBody io.ReadCloser, query url.Values) (resp []byte, code int, err error)) func(c context.Context, w fsthttp.ResponseWriter, r *fsthttp.Request) {
	return func(c context.Context, w fsthttp.ResponseWriter, r *fsthttp.Request) {
		query := r.URL.Query()
		resp, code, err := wrapped(c, r.Body, query)

		if err != nil {
			if code == fsthttp.StatusServiceUnavailable {
				w.Header().Set("Retry-After", fmt.Sprintf("%d", 30+rand.Intn(60)))
				fsthttp.Error(w, "pool full", code)
			} else {
				fsthttp.Error(w, err.Error(), code)
			}

			log.Println("Error:", err, "Code:", code, "URL:", r.URL)

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
	backend  string
	cache    map[string]*CacheEntry
	requests int
}

type CacheEntry struct {
	status int
	body   []byte
}

func (f *FastlyStorage) AvailableReqs() int {
	return requestLimit - f.requests
}

func (f *FastlyStorage) Get(ctx context.Context, key string) (data []byte, notfounderr bool, err error) {
	if data, ok := f.cache[key]; ok {
		if data.status == 404 {
			return nil, true, errors.New(fsthttp.StatusText(data.status))
		} else if data.status != 200 {
			return nil, false, errors.New(fsthttp.StatusText(data.status))
		}
		return data.body, false, nil
	}

	url := fmt.Sprintf("https://%s/%s", f.backend, key)

	notFound := false

	cacheFunc := func() (simple.CacheEntry, error) {
		f.requests++

		req, err := fsthttp.NewRequest("GET", url, nil)
		req.CacheOptions = fsthttp.CacheOptions{
			Pass: true,
		}
		if err != nil {
			return simple.CacheEntry{}, err
		}
		resp, err := req.Send(ctx, f.backend)
		if err != nil {
			return simple.CacheEntry{}, err
		}

		if resp.StatusCode != 200 {
			if resp.StatusCode == 404 {
				notFound = true
			}

			f.cache[key] = &CacheEntry{
				status: resp.StatusCode,
				body:   nil,
			}
			return simple.CacheEntry{}, errors.New(fsthttp.StatusText(resp.StatusCode))
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return simple.CacheEntry{}, err
		}

		f.cache[key] = &CacheEntry{
			status: resp.StatusCode,
			body:   body,
		}

		// Parse TTL from cache-control header
		ttl := 43200 // 12 hours in seconds as default

		// This is normalized to lower case
		cacheControl := resp.Header.Get("cache-control")
		if cacheControl != "" {
			directives := strings.Split(cacheControl, ",")
			for _, directive := range directives {
				directive = strings.TrimSpace(directive)
				if strings.HasPrefix(directive, "max-age=") {
					parsed, err := strconv.Atoi(directive[8:])
					if err != nil {
						log.Println("Error parsing max-age directive:", err)
						break
					}
					ttl = parsed
					break
				}
			}
		} else {
			log.Println("No cache-control header found")
		}

		return simple.CacheEntry{
			Body: bytes.NewReader(body),
			TTL:  time.Duration(ttl) * time.Second,
		}, nil
	}

	LOCAL := (os.Getenv("FASTLY_HOSTNAME") == "localhost")

	var reader io.Reader

	if !LOCAL {
		version := os.Getenv("FASTLY_SERVICE_VERSION")
		ireader, err := simple.GetOrSet([]byte(version+url), cacheFunc)
		if err != nil {
			if notFound {
				return nil, true, err
			}
			return nil, false, err
		}
		defer ireader.Close()
		reader = ireader
	} else {
		entry, err := cacheFunc()
		if err != nil {
			return nil, false, err
		}
		reader = entry.Body
		if notFound {
			return nil, true, errors.New("not found")
		}
	}

	body, err := io.ReadAll(reader)
	if err != nil {
		return nil, false, err
	}

	return body, false, nil
}

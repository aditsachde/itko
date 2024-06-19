package integration

import (
	"net/http"
	"net/http/httputil"
	"net/url"
)

func proxy(listenaddr, monitoraddr, submitaddr string) {
	monitorPaths := map[string]struct{}{
		"/ct/v1/get-sth":             {},
		"/ct/v1/get-sth-consistency": {},
		"/ct/v1/get-proof-by-hash":   {},
		"/ct/v1/get-entries":         {},
		"/ct/v1/get-roots":           {},
		"/ct/v1/get-entry-and-proof": {},
	}

	submitPaths := map[string]struct{}{
		"/ct/v1/add-chain":     {},
		"/ct/v1/add-pre-chain": {},
	}

	// Create a reverse proxy for monitoraddr
	monitorURL, _ := url.Parse("http://" + monitoraddr)
	monitorProxy := httputil.NewSingleHostReverseProxy(monitorURL)

	// Create a reverse proxy for submitaddr
	submitURL, _ := url.Parse("http://" + submitaddr)
	submitProxy := httputil.NewSingleHostReverseProxy(submitURL)

	// Create a new HTTP handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if the request path should be proxied to monitoraddr
		if _, ok := monitorPaths[r.URL.Path]; ok {
			monitorProxy.ServeHTTP(w, r)
			return
		}

		// Check if the request path should be proxied to submitaddr
		if _, ok := submitPaths[r.URL.Path]; ok {
			submitProxy.ServeHTTP(w, r)
			return
		}

		// If the request path doesn't match any paths in the sets, return a 404 Not Found
		http.NotFound(w, r)
	})

	// Start the HTTP server
	http.ListenAndServe(listenaddr, handler)
}

package ctlog

import (
	"fmt"
	"log"
	"net/http"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

func httpHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello, World")
}

func httpMux() http.Handler {
	// Create the HTTP Mux
	mux := http.NewServeMux()

	mux.HandleFunc("/hello", httpHandler)

	// Register the HTTP handler function
	handler := http.HandlerFunc(mux.ServeHTTP)
	wrappedHandler := otelhttp.NewHandler(handler, "hello")

	return wrappedHandler
}

func (l *Log) Start() error {
	// Start the log object
	log.Printf("Starting log object with config: %+v", l.config)

	// Initialize HTTP handler instrumentation
	return http.ListenAndServe("localhost:3030", httpMux())
}

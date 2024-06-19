package ctmonitor

import (
	"context"
	"log"
	"net"
	"net/http"
)

// This is seperated so we can run this in the integration test.
// Tests don't need to export Otel to Honeycomb.
func MainMain(listener net.Listener, storeAddress string, startSignal chan<- struct{}) {
	if storeAddress == "" {
		log.Fatal("Must provide a tile storage backend address")
	}

	mux, err := Start(context.Background(), storeAddress)
	if err != nil {
		log.Fatalf("Failed to get log handler: %v", err)
	}

	if startSignal != nil {
		startSignal <- struct{}{}
	}

	// Start the log
	log.Fatal(http.Serve(listener, mux))
}

package ctmonitor

import (
	"context"
	"log"
	"net"
	"net/http"
)

// This is seperated so we can run this in the integration test.
// Tests don't need to export Otel to Honeycomb.
func MainMain(listener net.Listener, storeDirectory string, storeAddress string, maskSize int, startSignal chan<- struct{}) {
	if storeDirectory == "" && storeAddress == "" {
		log.Fatal("Must provide a tile storage backend address")
	}

	mux, err := Start(context.Background(), storeDirectory, storeAddress, maskSize)
	if err != nil {
		log.Fatalf("Failed to get log handler: %v", err)
	}

	if startSignal != nil {
		startSignal <- struct{}{}
	}

	// Start the log
	log.Fatal(http.Serve(listener, mux))
}

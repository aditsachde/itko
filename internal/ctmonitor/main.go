package ctmonitor

import (
	"context"
	"log"
	"net"
	"net/http"

	"itko.dev/internal/ctsubmit"
)

// This is seperated so we can run this in the integration test.
// Tests don't need to export Otel to Honeycomb.
func MainMain(listener net.Listener, kvpath, consulAddress string, startSignal chan<- struct{}) {
	if kvpath == "" {
		log.Fatal("Must provide a Consul KV path")
	}

	// Create a new log object
	ctloghandle, err := ctsubmit.NewLog(kvpath, consulAddress)
	if err != nil {
		log.Fatalf("Failed to create log object: %v", err)
	}

	if startSignal != nil {
		startSignal <- struct{}{}
	}

	mux, err := ctloghandle.Start(context.Background())
	if err != nil {
		log.Fatalf("Failed to get log handler: %v", err)
	}

	// Start the log
	log.Fatal(http.Serve(listener, mux))
}

package submitmain

import (
	"context"
	"log"

	"itko.dev/internal/ctlog"
)

// This is seperated so we can run this in the integration test.
// Tests don't need to export Otel to Honeycomb.
func MainMain(kvpath, consulAddress string, startSignal chan<- struct{}) {
	if kvpath == "" {
		log.Fatal("Must provide a Consul KV path")
	}

	// Create a new log object
	ctloghandle, err := ctlog.NewLog(kvpath, consulAddress)
	if err != nil {
		log.Fatalf("Failed to create log object: %v", err)
	}

	if startSignal != nil {
		startSignal <- struct{}{}
	}

	// Start the log
	log.Fatal(ctloghandle.Start(context.Background()))
}

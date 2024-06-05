package main

import (
	"context"
	"flag"
	"log"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/trace"

	"itko.dev/internal/ctlog"
)

func main() {
	// Setup OpenTelemetry
	shutdownOtel := configureOtel()
	defer shutdownOtel()

	// Parse the command-line flags
	kvpath := flag.String("kv-path", "", "Consul KV path")
	flag.Parse()

	if kvpath == nil || *kvpath == "" {
		log.Fatal("Must provide a Consul KV path")
	}

	// Create a new log object
	ctloghandle, err := ctlog.NewLog(*kvpath)
	if err != nil {
		log.Fatalf("Failed to create log object: %v", err)
	}

	// Start the log
	log.Fatal(ctloghandle.Start())
}

func configureOtel() func() {
	ctx := context.Background()

	// Configure a new OTLP exporter using environment variables for sending data to Honeycomb over gRPC
	client := otlptracegrpc.NewClient()
	exp, err := otlptrace.New(ctx, client)
	if err != nil {
		log.Fatalf("failed to initialize exporter: %e", err)
	}

	// Create a new tracer provider with a batch span processor and the otlp exporter
	tp := trace.NewTracerProvider(
		trace.WithBatcher(exp),
	)

	// Register the global Tracer provider
	otel.SetTracerProvider(tp)

	// Register the W3C trace context and baggage propagators so data is propagated across services/processes
	otel.SetTextMapPropagator(
		propagation.NewCompositeTextMapPropagator(
			propagation.TraceContext{},
			propagation.Baggage{},
		),
	)

	// Return a function to handle shutdown
	// Handle shutdown to ensure all sub processes are closed correctly and telemetry is exported
	return func() {
		_ = exp.Shutdown(ctx)
		_ = tp.Shutdown(ctx)
	}
}
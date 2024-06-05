package ctlog

import (
	"context"
	"log"
	"net/http"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"itko.dev/internal/sunlight"
)

// TODO: Evaluate if the context is actually needed
func (l *Log) Start(ctx context.Context) error {
	// Start the log
	log.Printf("Starting log with config: %+v", l.config)

	// Create the channels for the stages
	stageOneRx := make(chan UnsequencedEntryWithReturnPath)
	stageTwoTx := make(chan []LogEntryWithReturnPath)

	// Start the stages
	go stageOne(ctx, stageOneRx, stageTwoTx, l.startingSequence)
	go stageTwo(ctx, stageTwoTx)

	// Wrap the HTTP handler function with OTel instrumentation
	addChain := otelhttp.NewHandler(http.HandlerFunc(stageZero), "add-chain")
	addPreChain := otelhttp.NewHandler(http.HandlerFunc(stageZero), "add-pre-chain")

	// Create a new HTTP server mux and start listening
	mux := http.NewServeMux()
	mux.Handle("POST /ct/v1/add-chain", addChain)
	mux.Handle("POST /ct/v1/add-pre-chain", addPreChain)

	return http.ListenAndServe("localhost:3030", http.MaxBytesHandler(mux, 128*1024))
}

type UnsequencedEntryWithReturnPath struct {
	entry      sunlight.UnsequencedEntry
	returnPath chan<- sunlight.LogEntry
}

type LogEntryWithReturnPath struct {
	entry      sunlight.LogEntry
	returnPath chan<- sunlight.LogEntry
}

func stageZero(w http.ResponseWriter, r *http.Request) {

}

func stageOne(
	ctx context.Context,
	stageOneRx <-chan UnsequencedEntryWithReturnPath,
	stageTwoTx chan<- []LogEntryWithReturnPath,
	startingSequence uint64,
) {
	const MAX_POOL_SIZE = 255
	const FLUSH_INTERVAL = time.Second

	// This variable will be incremented for each log entry
	sequence := startingSequence
	// Create a vector to store the pool
	pool := make([]LogEntryWithReturnPath, 0, MAX_POOL_SIZE)
	// Create a time variable to track the last flush
	lastFlushTime := time.Now()

	// Loop over the channel and context
	for {
		select {

		// Wait for the next log entry
		case entry, ok := <-stageOneRx:
			if !ok {
				return
			}

			// Sequence the unsequenced entry
			logEntry := LogEntryWithReturnPath{
				entry.entry.Sequence(sequence),
				entry.returnPath,
			}
			// Increment the sequence
			sequence++
			// Append the log entry to the pool
			pool = append(pool, logEntry)

			// Conditions to flush the pool
			if len(pool) >= MAX_POOL_SIZE || sequence%256 == 0 || time.Since(lastFlushTime) >= FLUSH_INTERVAL {
				// Create a copy of the pool
				closedPool := make([]LogEntryWithReturnPath, len(pool))
				copy(closedPool, pool)

				// Clear the original pool
				pool = pool[:0]
				stageTwoTx <- closedPool

				// Update the last flush time
				lastFlushTime = time.Now()
			}

		// If the flush interval has passed, flush the pool
		case <-time.After(FLUSH_INTERVAL):
			if len(pool) > 0 {
				// Create a copy of the pool
				closedPool := make([]LogEntryWithReturnPath, len(pool))
				copy(closedPool, pool)

				// Clear the original pool
				pool = pool[:0]
				stageTwoTx <- closedPool
			}
			// Update the last flush time
			lastFlushTime = time.Now()

		case <-ctx.Done():
			return
		}
	}
}

func stageTwo(
	ctx context.Context,
	stageTwoRx <-chan []LogEntryWithReturnPath,
) {
	// Loop over the channel and context
	for {
		select {
		case pool, ok := <-stageTwoRx:
			if !ok {
				return
			}

			// TODO: Process the pool
			for _, entry := range pool {
				entry.returnPath <- entry.entry
			}

		case <-ctx.Done():
			return
		}
	}
}

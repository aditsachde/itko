package integration

import (
	"context"
	"flag"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"testing"
	"time"

	"github.com/google/certificate-transparency-go/trillian/ctfe"
	"github.com/google/certificate-transparency-go/trillian/ctfe/configpb"
	"github.com/google/certificate-transparency-go/trillian/integration"
	"itko.dev/internal/ctsubmit"
)

var partialConfig ctsubmit.GlobalConfig = ctsubmit.GlobalConfig{
	KeyPath:       "./testdata/ct-http-server.privkey.plaintext.pem",
	LogID:         "lrviNpCI/wLGL5VTfK25b8cOdbP0YA7tGoQak5jST9o=",
	ListenAddress: "localhost:3030",
	MaskSize:      5,

	NotAfterStart: "2020-01-01T00:00:00Z",
	NotAfterLimit: "2030-01-01T00:00:00Z",
	FlushMs:       50,
}

func TestCTIntegration(t *testing.T) {
	// pprof endpoint
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()

	startSignal := make(chan struct{})
	configChan := make(chan ctsubmit.GlobalConfig)

	go setup(partialConfig, startSignal, configChan)
	c := <-configChan
	var config configpb.LogConfig

	<-startSignal // Once for monitor
	<-startSignal // Once for submit
	log.Println()
	log.Println()
	log.Println("🔔 Starting integration test")

	// This function takes the following arguments
	// cfg *configpb.LogConfig,
	//     This is a special format of configuration that Trillan uses, so GlobalConfig must be adapted
	//     A read through the integration test source code shows only the PublicKey and Prefix need to be set.
	// servers string,
	//     Trillian can run in HA mode so this takes a list of servers from which one is randomly selected
	//     for every request. We just have one so its just the connection string.
	// metricsServers string,
	//     Trillian runs a metric server that this integration test tests, but we skip that
	//     so this is just set to the server string
	// testdir string,
	//     This is a directory that is copied over from the Trillian test suite
	// mmd time.Duration,
	//     We set it to 1 sec, as Itko has no MMD
	// stats *integration.logStats
	//     This is set to nil to disable the metrics check because we don't have a metrics server
	err := integration.RunCTIntegrationForLog(&config, c.ListenAddress, c.ListenAddress, "./testdata", time.Second, nil)
	if err != nil {
		log.Fatalln("🛑 Integration test failed:", err)
	}
}

var longFlag = flag.Bool("long", false, "Run the hammer test with a large number of operations")

func TestCTHammer(t *testing.T) {
	// pprof endpoint
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()

	startSignal := make(chan struct{})
	configChan := make(chan ctsubmit.GlobalConfig)

	go setup(partialConfig, startSignal, configChan)
	c := <-configChan
	var config configpb.LogConfig

	<-startSignal // Once for monitor
	<-startSignal // Once for submit
	log.Println()
	log.Println()
	log.Println("🔔 Starting hammer test")

	pool, err := integration.NewRandomPool(c.ListenAddress, config.PublicKey, config.Prefix)
	if err != nil {
		log.Fatalf("Failed to create client pool: %v", err)
	}

	generatorFactory, err := integration.SyntheticGeneratorFactory("./testdata", c.NotAfterStart)
	if err != nil {
		log.Fatalf("Failed to make cert generator factory: %v", err)
	}
	generator, err := generatorFactory(&config)
	if err != nil {
		log.Fatalf("Failed to make cert generator: %v", err)
	}

	// Default values from certificate-transparency-go
	bias := integration.HammerBias{
		Bias: map[ctfe.EntrypointName]int{
			ctfe.AddChainName:          20,
			ctfe.AddPreChainName:       20,
			ctfe.GetSTHName:            2,
			ctfe.GetSTHConsistencyName: 2,
			ctfe.GetProofByHashName:    2,
			ctfe.GetEntriesName:        2,
			ctfe.GetRootsName:          1,
			ctfe.GetEntryAndProofName:  0, // hammering entrypoint GetEntryAndProof not yet implemented upstream
		},
		InvalidChance: map[ctfe.EntrypointName]int{
			ctfe.AddChainName:          10,
			ctfe.AddPreChainName:       10,
			ctfe.GetSTHName:            0,
			ctfe.GetSTHConsistencyName: 10,
			ctfe.GetProofByHashName:    10,
			ctfe.GetEntriesName:        10,
			ctfe.GetRootsName:          0,
			ctfe.GetEntryAndProofName:  10,
		},
	}

	hammerConfig := integration.HammerConfig{
		LogCfg:              &config,
		MetricFactory:       nil,
		MMD:                 time.Second * 20, // We should have no MMD
		ChainGenerator:      generator,
		ClientPool:          pool,
		EPBias:              bias,
		MinGetEntries:       1,
		MaxGetEntries:       1000,
		OversizedGetEntries: true,
		Operations:          250,
		Limiter:             nil,
		MaxParallelChains:   20,
		IgnoreErrors:        false,
		MaxRetryDuration:    time.Second * 10, // Doesn't matter since IgnoreErrors is false
		RequestDeadline:     time.Second * 5,
		DuplicateChance:     10, // Default value from certificate-transparency-go
		// This is set to true because although we can produce a valid consistency proof between any two STH values,
		// this will result in failures at times. Consider a tree with a size of 250, but entires 240 to 250 were added
		// together. Then, a partial tile for entry 245 would not have been stored. We could instead retrieve the tile for 250,
		// but realistically we would rather just want to wait until 256 entries were stored and the full tile could be retrieved,
		// as RFC6962 doesn't require us to be able to produce arbitrary proofs on demand.
		StrictSTHConsistencySize: true,
	}

	flag.Parse()
	if *longFlag {
		hammerConfig.Operations = 50000
	}

	err = integration.HammerCTLog(context.Background(), hammerConfig)
	if err != nil {
		log.Fatalln("🛑 Hammer test failed:", err)
	}
}

// ------------------------------------------------------------
// These are the same integration tests as above, but run on a filesystem storage backend instead of S3.

func TestCTFsIntegration(t *testing.T) {
	// pprof endpoint
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()

	// Create a temporary directory
	tempDir, err := os.MkdirTemp("", "testdata")
	if err != nil {
		t.Fatalf("Failed to create temporary directory: %v", err)
	}
	// Clean up the temporary directory after the test
	defer os.RemoveAll(tempDir)

	partialConfig := partialConfig
	partialConfig.RootDirectory = tempDir

	startSignal := make(chan struct{})
	configChan := make(chan ctsubmit.GlobalConfig)

	go setup(partialConfig, startSignal, configChan)
	c := <-configChan
	var config configpb.LogConfig

	<-startSignal // Once for monitor
	<-startSignal // Once for submit
	log.Println()
	log.Println()
	log.Println("🔔 Starting integration test")

	// This function takes the following arguments
	// cfg *configpb.LogConfig,
	//     This is a special format of configuration that Trillan uses, so GlobalConfig must be adapted
	//     A read through the integration test source code shows only the PublicKey and Prefix need to be set.
	// servers string,
	//     Trillian can run in HA mode so this takes a list of servers from which one is randomly selected
	//     for every request. We just have one so its just the connection string.
	// metricsServers string,
	//     Trillian runs a metric server that this integration test tests, but we skip that
	//     so this is just set to the server string
	// testdir string,
	//     This is a directory that is copied over from the Trillian test suite
	// mmd time.Duration,
	//     We set it to 1 sec, as Itko has no MMD
	// stats *integration.logStats
	//     This is set to nil to disable the metrics check because we don't have a metrics server
	err = integration.RunCTIntegrationForLog(&config, c.ListenAddress, c.ListenAddress, "./testdata", time.Second, nil)
	if err != nil {
		log.Fatalln("🛑 Integration test failed:", err)
	}
}

func TestCTFsHammer(t *testing.T) {
	// pprof endpoint
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()

	// Create a temporary directory
	tempDir, err := os.MkdirTemp("", "testdata")
	if err != nil {
		t.Fatalf("Failed to create temporary directory: %v", err)
	}
	// Clean up the temporary directory after the test
	defer os.RemoveAll(tempDir)

	partialConfig := partialConfig
	partialConfig.RootDirectory = tempDir

	startSignal := make(chan struct{})
	configChan := make(chan ctsubmit.GlobalConfig)

	go setup(partialConfig, startSignal, configChan)
	c := <-configChan
	var config configpb.LogConfig

	<-startSignal // Once for monitor
	<-startSignal // Once for submit
	log.Println()
	log.Println()
	log.Println("🔔 Starting hammer test")

	pool, err := integration.NewRandomPool(c.ListenAddress, config.PublicKey, config.Prefix)
	if err != nil {
		log.Fatalf("Failed to create client pool: %v", err)
	}

	generatorFactory, err := integration.SyntheticGeneratorFactory("./testdata", c.NotAfterStart)
	if err != nil {
		log.Fatalf("Failed to make cert generator factory: %v", err)
	}
	generator, err := generatorFactory(&config)
	if err != nil {
		log.Fatalf("Failed to make cert generator: %v", err)
	}

	// Default values from certificate-transparency-go
	bias := integration.HammerBias{
		Bias: map[ctfe.EntrypointName]int{
			ctfe.AddChainName:          20,
			ctfe.AddPreChainName:       20,
			ctfe.GetSTHName:            2,
			ctfe.GetSTHConsistencyName: 2,
			ctfe.GetProofByHashName:    2,
			ctfe.GetEntriesName:        2,
			ctfe.GetRootsName:          1,
			ctfe.GetEntryAndProofName:  0, // hammering entrypoint GetEntryAndProof not yet implemented upstream
		},
		InvalidChance: map[ctfe.EntrypointName]int{
			ctfe.AddChainName:          10,
			ctfe.AddPreChainName:       10,
			ctfe.GetSTHName:            0,
			ctfe.GetSTHConsistencyName: 10,
			ctfe.GetProofByHashName:    10,
			ctfe.GetEntriesName:        10,
			ctfe.GetRootsName:          0,
			ctfe.GetEntryAndProofName:  10,
		},
	}

	hammerConfig := integration.HammerConfig{
		LogCfg:              &config,
		MetricFactory:       nil,
		MMD:                 time.Second * 20, // We should have no MMD
		ChainGenerator:      generator,
		ClientPool:          pool,
		EPBias:              bias,
		MinGetEntries:       1,
		MaxGetEntries:       1000,
		OversizedGetEntries: true,
		Operations:          250,
		Limiter:             nil,
		MaxParallelChains:   20,
		IgnoreErrors:        false,
		MaxRetryDuration:    time.Second * 10, // Doesn't matter since IgnoreErrors is false
		RequestDeadline:     time.Second * 5,
		DuplicateChance:     10, // Default value from certificate-transparency-go
		// This is set to true because although we can produce a valid consistency proof between any two STH values,
		// this will result in failures at times. Consider a tree with a size of 250, but entires 240 to 250 were added
		// together. Then, a partial tile for entry 245 would not have been stored. We could instead retrieve the tile for 250,
		// but realistically we would rather just want to wait until 256 entries were stored and the full tile could be retrieved,
		// as RFC6962 doesn't require us to be able to produce arbitrary proofs on demand.
		StrictSTHConsistencySize: true,
	}

	flag.Parse()
	if *longFlag {
		hammerConfig.Operations = 50000
	}

	err = integration.HammerCTLog(context.Background(), hammerConfig)
	if err != nil {
		log.Fatalln("🛑 Hammer test failed:", err)
	}
}

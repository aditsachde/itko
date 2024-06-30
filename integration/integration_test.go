package integration

import (
	"log"
	"net/http"
	_ "net/http/pprof"
	"testing"
	"time"

	"github.com/google/certificate-transparency-go/trillian/ctfe/configpb"
	"github.com/google/certificate-transparency-go/trillian/integration"
	"itko.dev/internal/ctsubmit"
)

func TestLiveCTIntegration(t *testing.T) {
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()

	startSignal := make(chan struct{})
	configChan := make(chan ctsubmit.GlobalConfig)

	go setup(startSignal, configChan)
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

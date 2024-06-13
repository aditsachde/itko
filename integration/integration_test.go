package integration

import (
	"testing"
)

func TestLiveCTIntegration(t *testing.T) {
	startSignal := make(chan struct{})
	go setup(startSignal)
	<-startSignal
	select {}
}

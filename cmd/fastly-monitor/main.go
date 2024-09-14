package main

import (
	"log"
	"os"

	"github.com/fastly/compute-sdk-go/fsthttp"
	"itko.dev/internal/ctmonitor"
)

func main() {
	log.Println("FASTLY_SERVICE_VERSION:", os.Getenv("FASTLY_SERVICE_VERSION"))
	fsthttp.ServeFunc(ctmonitor.FastlyServe)
}

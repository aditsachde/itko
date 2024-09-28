package main

import (
	"github.com/fastly/compute-sdk-go/fsthttp"
	"itko.dev/internal/ctmonitor"
)

func main() {
	fsthttp.ServeFunc(ctmonitor.FastlyServe)
}

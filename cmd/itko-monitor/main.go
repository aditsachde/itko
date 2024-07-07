package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"

	"itko.dev/internal/ctmonitor"
)

func main() {
	// Parse the command-line flags
	storeAddress := flag.String("store-address", "", "Tile storage url. Must end with a trailing slash.")
	maskSize := flag.Int("mask-size", 0, "Mask size for the quadtree.")
	flag.Parse()

	if *storeAddress == "" {
		fmt.Println("Error: -store-address flag must be set")
		flag.Usage() // Print the usage message
		os.Exit(1)   // Exit with a non-zero status
	}

	if *maskSize == 0 {
		fmt.Println("Error: -mask-size flag must be set")
		flag.Usage() // Print the usage message
		os.Exit(1)   // Exit with a non-zero status
	}

	listener, err := net.Listen("tcp", "localhost:8080")
	if err != nil {
		log.Fatalf("failed to bind to address: %v", err)
	}

	ctmonitor.MainMain(listener, *storeAddress, *maskSize, nil)
}

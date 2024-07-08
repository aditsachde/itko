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
	listenAddress := flag.String("listen-address", "", "IP and port to listen on for incoming connections.")
	maskSize := flag.Int("mask-size", 0, "Mask size for the quadtree.")
	flag.Parse()

	if *storeAddress == "" {
		fmt.Println("Error: -store-address flag must be set")
		flag.Usage() // Print the usage message
		os.Exit(1)   // Exit with a non-zero status
	}

	if *listenAddress == "" {
		fmt.Println("Error: -listen-address flag must be set")
		flag.Usage() // Print the usage message
		os.Exit(1)   // Exit with a non-zero status
	}

	if *maskSize == 0 {
		fmt.Println("Error: -mask-size flag must be set")
		flag.Usage() // Print the usage message
		os.Exit(1)   // Exit with a non-zero status
	}

	listener, err := net.Listen("tcp", *listenAddress)
	if err != nil {
		log.Fatalf("failed to bind to address: %v", err)
	}

	ctmonitor.MainMain(listener, *storeAddress, *maskSize, nil)
}

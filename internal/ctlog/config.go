package ctlog

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"

	consul "github.com/hashicorp/consul/api"
)

type GlobalConfig struct {
	Name      string `json:"name"`
	KeyPath   string `json:"keyPath"`
	KeySha256 string `json:"keySha256"`
	RootPath  string `json:"rootPath"`
	S3Bucket  string `json:"s3Bucket"`
}

type Log struct {
	config GlobalConfig
	eStop  *consul.Lock
}

func NewLog(kvpath string) (*Log, error) {
	var lock *consul.Lock
	var config GlobalConfig

	{
		lockpath := kvpath + "/lock"
		configpath := kvpath + "/config"

		// Start by creating a new Consul client
		client, err := consul.NewClient(consul.DefaultConfig())
		if err != nil {
			return nil, err
		}

		// Create a new lock struct for the key
		lock, err = client.LockKey(lockpath)
		if err != nil {
			return nil, err
		}

		// Lock the key and get a channel to listen for lock loss
		eStopChan, err := lock.Lock(nil)
		if err != nil {
			return nil, err
		}

		// If the lock is lost, log a fatal message and fail fast
		go func(eStopChan <-chan struct{}) {
			<-eStopChan
			log.Fatal("Consul lock lost")
		}(eStopChan)

		// If the program recieves a Ctrl-C, release the lock
		// This will cause the lock loss handler to fire
		// Not really the best place to handle this, but
		// we need to release the lock somewhere and other cleanup is
		// not implemented yet
		interruptChan := make(chan os.Signal, 1)
		signal.Notify(interruptChan, os.Interrupt)
		go func(interruptChan chan os.Signal, lock *consul.Lock) {
			<-interruptChan
			log.Println("Interrupted, releasing lock")
			lock.Unlock()
		}(interruptChan, lock)

		// Once the lock is acquired, fetch the configuration from Consul
		kv := client.KV()
		rawConfig, _, err := kv.Get(configpath, &consul.QueryOptions{
			RequireConsistent: true,
		})
		if err != nil {
			return nil, err
		}
		if rawConfig == nil {
			return nil, fmt.Errorf("no configuration found at %s", configpath)
		}

		// Unmarshal the configuration into a struct
		if err := json.Unmarshal(rawConfig.Value, &config); err != nil {
			return nil, err
		}
	}

	// Log the configuration
	log.Printf("Loaded configuration: %+v", config)

	// Now, we can continue by actually setting up the log

	return &Log{config: config, eStop: lock}, nil
}

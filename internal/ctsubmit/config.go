package ctsubmit

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/google/certificate-transparency-go/x509util"
	consul "github.com/hashicorp/consul/api"
)

type GlobalConfig struct {
	Name          string `json:"name"`
	KeyPath       string `json:"keyPath"`
	KeySha256     string `json:"keySha256"`
	RootPath      string `json:"rootPath"`
	ListenAddress string `json:"listenAddress"`

	S3Bucket                   string `json:"s3Bucket"`
	S3Region                   string `json:"s3Region"`
	S3EndpointUrl              string `json:"s3EndpointUrl"`
	S3StaticCredentialUserName string `json:"s3StaticCredentialUserName"`
	S3StaticCredentialPassword string `json:"s3StaticCredentialPassword"`
}

type Log struct {
	config GlobalConfig
	eStop  *consul.Lock

	startingSequence uint64

	stageZeroData
}

type stageZeroData struct {
	roots         *x509util.PEMCertPool
	stageOneTx    chan<- UnsequencedEntryWithReturnPath
	notAfterStart time.Time
	notAfterLimit time.Time
	logID         [32]byte

	signingKey *ecdsa.PrivateKey
}

type stageTwoData struct {
	bucket Bucket

	tree_size        int64
	timestamp        uint64
	sha256_root_hash [32]byte

	signingKey *ecdsa.PrivateKey
}

func NewLog(kvpath, consulAddress string) (*Log, error) {
	var lock *consul.Lock
	var config GlobalConfig

	{
		lockpath := kvpath + "/lock"
		configpath := kvpath + "/config"

		// Start by creating a new Consul client
		config := consul.DefaultConfig()
		config.Address = consulAddress
		client, err := consul.NewClient(config)
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
		// This will happen in two cases, either we perform cleanup and unlock the lock
		// or the lock is lost due to reasons out of our control.
		// Either way, without the lock, we are not allowed to do any more tasks.
		go func(eStopChan <-chan struct{}) {
			<-eStopChan
			log.Fatal("Consul lock lost, exiting now!")
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
	log.Printf("✅ Loaded configuration: %+v", config)

	// Now, we can continue by actually setting up the log

	return &Log{config: config, eStop: lock}, nil
}

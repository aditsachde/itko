package ctsubmit

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509util"
	consul "github.com/hashicorp/consul/api"
	"itko.dev/internal/sunlight"
)

type GlobalConfig struct {
	Name          string `json:"name"`
	KeyPath       string `json:"keyPath"`
	LogID         string `json:"logID"`
	RootPath      string `json:"rootPath"`
	ListenAddress string `json:"listenAddress"`

	S3Bucket                   string `json:"s3Bucket"`
	S3Region                   string `json:"s3Region"`
	S3EndpointUrl              string `json:"s3EndpointUrl"`
	S3StaticCredentialUserName string `json:"s3StaticCredentialUserName"`
	S3StaticCredentialPassword string `json:"s3StaticCredentialPassword"`

	NotAfterStart string `json:"notAfterStart"`
	NotAfterLimit string `json:"notAfterLimit"`
}

type Log struct {
	config GlobalConfig
	eStop  *consul.Lock

	stageZeroData
	stageOneData
	stageTwoData
}

type UnsequencedEntryWithReturnPath struct {
	entry      sunlight.UnsequencedEntry
	returnPath chan<- sunlight.LogEntry
}

type LogEntryWithReturnPath struct {
	entry      sunlight.LogEntry
	returnPath chan<- sunlight.LogEntry
}

type stageZeroData struct {
	stageOneTx chan<- UnsequencedEntryWithReturnPath

	roots         *x509util.PEMCertPool
	notAfterStart time.Time
	notAfterLimit time.Time
	logID         [32]byte

	signingKey *ecdsa.PrivateKey
}

type stageOneData struct {
	stageOneRx <-chan UnsequencedEntryWithReturnPath
	stageTwoTx chan<- []LogEntryWithReturnPath

	startingSequence uint64
}

type stageTwoData struct {
	stageTwoRx <-chan []LogEntryWithReturnPath

	bucket Bucket

	tree_size        int64
	timestamp        uint64
	sha256_root_hash [32]byte

	signingKey *ecdsa.PrivateKey
}

func LoadLog(ctx context.Context, kvpath, consulAddress string) (*Log, error) {
	var lock *consul.Lock
	var gc GlobalConfig

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
		if err := json.Unmarshal(rawConfig.Value, &gc); err != nil {
			return nil, err
		}
	}

	// Now, we can continue by actually setting up the log

	// First, check that the private key we have is actually valid, because
	// we can't do anything without it.
	var key *ecdsa.PrivateKey

	{
		keyPEM, err := os.ReadFile(gc.KeyPath)
		if err != nil {
			return nil, fmt.Errorf("unable to read key: %v", err)
		}
		keyBlock, _ := pem.Decode(keyPEM)

		key, err = x509.ParseECPrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("unable to parse key: %v", err)
		}

		pkix, err := x509.MarshalPKIXPublicKey(key.Public())
		if err != nil {
			return nil, fmt.Errorf("unable to marshal public key: %v", err)
		}
		logSha := sha256.Sum256(pkix)
		logID := base64.StdEncoding.EncodeToString(logSha[:])

		// sanity check to make sure wrong private key is not accidentally used
		if logID != gc.LogID {
			return nil, fmt.Errorf("log ID does not match: %s != %s", logID, gc.LogID)
		}
	}

	// Create the channels for the stages
	// TODO: This will cause problems if the channel is full and an unbuffered channel here
	// isn't really the right thing to have either.
	// It seems that go doesn't have a simple way to send to a buffered channel but
	// return an error if the channel is full instead of blocking.

	stageOneCommChan := make(chan UnsequencedEntryWithReturnPath)
	stageTwoCommChan := make(chan []LogEntryWithReturnPath)

	// Stage zero setup
	var stageZero stageZeroData

	{
		notAfterStart, err := time.Parse(time.RFC3339, gc.NotAfterStart)
		if err != nil {
			return nil, fmt.Errorf("unable to parse NotAfterStart: %v", err)
		}
		notAfterLimit, err := time.Parse(time.RFC3339, gc.NotAfterLimit)
		if err != nil {
			return nil, fmt.Errorf("unable to parse NotAfterLimit: %v", err)
		}

		bucket := NewBucket(gc.S3Region, gc.S3Bucket, gc.S3EndpointUrl, gc.S3StaticCredentialUserName, gc.S3StaticCredentialPassword)

		var res struct {
			Certificates [][]byte `json:"certificates"`
		}
		roots, err := bucket.Get(ctx, "/ct/v1/get-roots")
		if err != nil {
			return nil, fmt.Errorf("unable to fetch roots: %v", err)
		}
		err = json.Unmarshal(roots, &res)
		if err != nil {
			return nil, fmt.Errorf("unable to unmarshal roots: %v", err)
		}

		// iterate over the certificates and add them to the pool
		r := x509util.NewPEMCertPool()
		for _, certBytes := range res.Certificates {
			cert, err := x509.ParseCertificate(certBytes)
			if err != nil {
				return nil, fmt.Errorf("unable to parse certificate: %v", err)
			}
			r.AddCert(cert)
		}

		stageZero = stageZeroData{
			stageOneTx: stageOneCommChan,

			roots:         r,
			notAfterStart: notAfterStart,
			notAfterLimit: notAfterLimit,

			signingKey: key,
		}
	}

	var stageOne stageOneData
	{
		stageOne = stageOneData{
			stageOneRx: stageOneCommChan,
			stageTwoTx: stageTwoCommChan,

			startingSequence: 0,
		}
	}

	var stageTwo stageTwoData
	{
		bucket := NewBucket(gc.S3Region, gc.S3Bucket, gc.S3EndpointUrl, gc.S3StaticCredentialUserName, gc.S3StaticCredentialPassword)

		stageTwo = stageTwoData{
			stageTwoRx: stageTwoCommChan,

			bucket: bucket,

			signingKey: key,
		}
	}

	return &Log{
		config: gc,
		eStop:  lock,

		stageZeroData: stageZero,
		stageOneData:  stageOne,
		stageTwoData:  stageTwo,
	}, nil
}

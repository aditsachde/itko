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

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509util"
	consul "github.com/hashicorp/consul/api"
	"golang.org/x/mod/sumdb/tlog"
	"itko.dev/internal/sunlight"
)

type GlobalConfig struct {
	Name          string `json:"name"`
	KeyPath       string `json:"keyPath"`
	LogID         string `json:"logID"`
	ListenAddress string `json:"listenAddress"`
	MaskSize      int    `json:"maskSize"`

	// If this is set, the log will write to the filesystem instead of S3
	// This value is prefered over the S3 values
	RootDirectory string `json:"rootDirectory"`

	S3Bucket                   string `json:"s3Bucket"`
	S3Region                   string `json:"s3Region"`
	S3EndpointUrl              string `json:"s3EndpointUrl"`
	S3StaticCredentialUserName string `json:"s3StaticCredentialUserName"`
	S3StaticCredentialPassword string `json:"s3StaticCredentialPassword"`

	NotAfterStart string `json:"notAfterStart"`
	NotAfterLimit string `json:"notAfterLimit"`
	FlushMs       int    `json:"flushMs"`
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

type tileWithBytes struct {
	tlog.Tile
	Bytes []byte
}

type stageZeroData struct {
	stageOneTx chan<- UnsequencedEntryWithReturnPath

	roots         *x509util.PEMCertPool
	notAfterStart time.Time
	notAfterLimit time.Time
	logID         [32]byte
	bucket        Bucket
	maskSize      int

	signingKey *ecdsa.PrivateKey
}

type stageOneData struct {
	stageOneRx <-chan UnsequencedEntryWithReturnPath
	stageTwoTx chan<- []LogEntryWithReturnPath

	startingSequence uint64
	flushMs          int
}

type stageTwoData struct {
	stageTwoRx <-chan []LogEntryWithReturnPath

	bucket           Bucket
	edgeTiles        map[int]tileWithBytes
	maskSize         int
	checkpointOrigin string

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

	stageOneCommChan := make(chan UnsequencedEntryWithReturnPath, 200)
	stageTwoCommChan := make(chan []LogEntryWithReturnPath, 2)

	var bucket Bucket

	if gc.RootDirectory != "" {
		log.Println("Using filesystem storage")
		fsStorage := NewFsStorage(gc.RootDirectory)
		bucket = Bucket{S: &fsStorage}
	} else {
		log.Println("Using S3 storage")
		s3Storage := NewS3Storage(gc.S3Region, gc.S3Bucket, gc.S3EndpointUrl, gc.S3StaticCredentialUserName, gc.S3StaticCredentialPassword)
		bucket = Bucket{S: &s3Storage}
	}

	// Get the latest STH
	var sth ct.SignedTreeHead
	{
		log.Println("Fetching latest STH")
		sthBytes, err := bucket.S.Get(ctx, "ct/v1/get-sth")
		if err != nil {
			return nil, fmt.Errorf("unable to fetch STH: %v", err)
		}
		err = json.Unmarshal(sthBytes, &sth)
		if err != nil {
			return nil, fmt.Errorf("unable to unmarshal STH: %v", err)
		}
	}

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

		var res struct {
			Certificates [][]byte `json:"certificates"`
		}
		roots, err := bucket.S.Get(ctx, "ct/v1/get-roots")
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

		logID, err := base64.StdEncoding.DecodeString(gc.LogID)
		if err != nil {
			return nil, fmt.Errorf("unable to decode log ID: %v", err)
		}
		if len(logID) != 32 {
			return nil, fmt.Errorf("logID must be exactly 32 bytes long")
		}

		// Convert []byte to [32]byte
		var logIDArray [32]byte
		copy(logIDArray[:], logID)

		stageZero = stageZeroData{
			stageOneTx: stageOneCommChan,

			roots:         r,
			notAfterStart: notAfterStart,
			notAfterLimit: notAfterLimit,
			logID:         logIDArray,
			bucket:        bucket,
			maskSize:      gc.MaskSize,

			signingKey: key,
		}
	}

	var stageOne stageOneData
	{
		stageOne = stageOneData{
			stageOneRx: stageOneCommChan,
			stageTwoTx: stageTwoCommChan,

			// Starting index is zero indexed, so we don't need to add one
			startingSequence: sth.TreeSize,
			flushMs:          gc.FlushMs,
		}
	}

	var stageTwo stageTwoData
	{
		edgeTiles := make(map[int]tileWithBytes)

		if sth.TreeSize == 0 {
			// If there are no tiles, then initialize an empty data tile
			edgeTiles[-1] = tileWithBytes{
				Tile: tlog.Tile{
					H: sunlight.TileHeight,
					L: -1,
					N: 0,
					W: 0,
				},
				Bytes: []byte{},
			}
		} else {
			// Fetch the edge tiles
			// This technique was taken from Sunlight. The idea is that the TileHashReader has the ability
			// to fetch, verify, and save the tiles once verified using a custom function. We set this up,
			// and then use it to fetch the level zero tile of the current tree size. This causes it to
			// fetch all the parent tiles up until the root hash in order to verify the level zero tile.
			_, err := tlog.TileHashReader(tlog.Tree{
				N:    int64(sth.TreeSize),
				Hash: tlog.Hash(sth.SHA256RootHash),
			}, &sunlight.TileReader{
				Fetch: func(key string) ([]byte, error) {
					log.Println("Fetching tile", key)
					return bucket.S.Get(ctx, key)
				}, SaveTilesInt: func(tiles []tlog.Tile, data [][]byte) {
					for i, tile := range tiles {
						if t, ok := edgeTiles[tile.L]; !ok || t.N < tile.N || (t.N == tile.N && t.W < tile.W) {
							edgeTiles[tile.L] = tileWithBytes{
								Tile:  tile,
								Bytes: data[i],
							}
						}
					}
				},
			}).ReadHashes([]int64{tlog.StoredHashIndex(0, int64(sth.TreeSize)-1)})
			if err != nil {
				return nil, fmt.Errorf("unable to fetch and verify edge tiles: %v", err)
			}

			// Verify the data tile
			dataTile := edgeTiles[0]
			// the data tile is the same as the level zero tile, with L -1
			dataTile.Tile.L = -1

			dataTileBytes, err := bucket.S.Get(ctx, dataTile.Path())
			if err != nil {
				return nil, fmt.Errorf("unable to fetch data tile: %v", err)
			}
			dataTile.Bytes = dataTileBytes
			edgeTiles[-1] = dataTile

			// TODO: verify the data tile against the L0 tile
		}

		stageTwo = stageTwoData{
			stageTwoRx: stageTwoCommChan,

			bucket:           bucket,
			edgeTiles:        edgeTiles,
			maskSize:         gc.MaskSize,
			checkpointOrigin: gc.Name,

			signingKey: key,
		}
	}

	log.Println("Log loaded successfully")

	return &Log{
		config: gc,
		eStop:  lock,

		stageZeroData: stageZero,
		stageOneData:  stageOne,
		stageTwoData:  stageTwo,
	}, nil
}

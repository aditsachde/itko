package ctsetup

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"log"
	"os"
	"time"

	"github.com/google/certificate-transparency-go/x509util"
	consul "github.com/hashicorp/consul/api"

	"itko.dev/internal/ctsubmit"
	"itko.dev/internal/sunlight"
)

func MainMain(ctx context.Context, consulAddress, consulKey, rootCerts, signingKey string, gc ctsubmit.GlobalConfig) {
	err := uploadRoots(ctx, rootCerts, gc)
	if err != nil {
		log.Fatalf("Failed to upload root certificates to S3: %v", err)
	}

	err = uploadConfig(consulAddress, consulKey, gc)
	if err != nil {
		log.Fatalf("Failed to upload config to Consul: %v", err)
	}

	err = uploadEmptySth(ctx, signingKey, gc)
	if err != nil {
		log.Fatalf("Failed to upload empty STH to S3: %v", err)
	}
}

func uploadConfig(consulAddress, consulKey string, globalConfig ctsubmit.GlobalConfig) error {
	// Upload config to Consul
	globalConfigBytes, err := json.Marshal(globalConfig)
	if err != nil {
		return err
	}

	config := consul.DefaultConfig()
	config.Address = consulAddress
	client, err := consul.NewClient(config)
	if err != nil {
		return err
	}
	kv := client.KV()
	_, err = kv.Put(&consul.KVPair{
		Key:   consulKey + "/config",
		Value: globalConfigBytes,
	}, nil)

	return err
}

func uploadRoots(ctx context.Context, rootCerts string, gc ctsubmit.GlobalConfig) error {
	r := x509util.NewPEMCertPool()
	err := r.AppendCertsFromPEMFile(rootCerts)
	if err != nil {
		return err
	}

	roots := r.RawCertificates()
	var res struct {
		Certificates [][]byte `json:"certificates"`
	}

	res.Certificates = make([][]byte, 0, len(roots))
	for _, r := range roots {
		res.Certificates = append(res.Certificates, r.Raw)
	}

	rootBytes, err := json.Marshal(res)
	if err != nil {
		return err
	}

	var storage ctsubmit.Storage
	if gc.RootDirectory != "" {
		s := ctsubmit.NewFsStorage(gc.RootDirectory)
		storage = &s
	} else {
		s := ctsubmit.NewS3Storage(gc.S3Region, gc.S3Bucket, gc.S3EndpointUrl, gc.S3StaticCredentialUserName, gc.S3StaticCredentialPassword)
		storage = &s
	}
	return storage.Set(ctx, "ct/v1/get-roots", rootBytes)

}

func uploadEmptySth(ctx context.Context, signingKey string, gc ctsubmit.GlobalConfig) error {
	keyPEM, err := os.ReadFile(signingKey)
	if err != nil {
		return err
	}
	keyBlock, _ := pem.Decode(keyPEM)

	// keyDecrypted, err := x509.DecryptPEMBlock(keyBlock, []byte("dirk"))
	// if err != nil {
	// 	return err
	// }

	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return err
	}

	jsonBytes, err := sunlight.SignTreeHead(key, 0, uint64(time.Now().UnixMilli()), sha256.Sum256([]byte("")))
	if err != nil {
		return err
	}

	var storage ctsubmit.Storage
	if gc.RootDirectory != "" {
		s := ctsubmit.NewFsStorage(gc.RootDirectory)
		storage = &s
	} else {
		s := ctsubmit.NewS3Storage(gc.S3Region, gc.S3Bucket, gc.S3EndpointUrl, gc.S3StaticCredentialUserName, gc.S3StaticCredentialPassword)
		storage = &s
	}
	return storage.Set(ctx, "ct/v1/get-sth", jsonBytes)
}

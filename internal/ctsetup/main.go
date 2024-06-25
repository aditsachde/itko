package ctsetup

import (
	"context"
	"encoding/json"
	"log"

	"github.com/google/certificate-transparency-go/x509util"
	consul "github.com/hashicorp/consul/api"

	"itko.dev/internal/ctsubmit"
)

func MainMain(ctx context.Context, consulAddress, consulKey string, rootCerts string, gc ctsubmit.GlobalConfig) {
	err := uploadRoots(ctx, rootCerts, gc)
	if err != nil {
		log.Fatalf("Failed to upload root certificates to S3: %v", err)
	}

	err = uploadConfig(consulAddress, consulKey, gc)
	if err != nil {
		log.Fatalf("Failed to upload config to Consul: %v", err)
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

	bucket := ctsubmit.NewBucket(ctx, gc.S3Region, gc.S3Bucket, gc.S3EndpointUrl, gc.S3StaticCredentialUserName, gc.S3StaticCredentialPassword)
	return bucket.Set(ctx, "/ct/v1/get-roots", rootBytes)

}

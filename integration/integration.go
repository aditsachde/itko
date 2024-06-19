package integration

import (
	"context"
	"encoding/json"
	"log"
	"net"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	consul "github.com/hashicorp/consul/api"
	"github.com/testcontainers/testcontainers-go"
	tcConsul "github.com/testcontainers/testcontainers-go/modules/consul"
	"github.com/testcontainers/testcontainers-go/modules/minio"

	"itko.dev/internal/ctmonitor"
	"itko.dev/internal/ctsubmit"
)

func setup(startSignal chan<- struct{}, configChan chan<- ctsubmit.GlobalConfig) {
	ctx := context.Background()

	// Testcontainers is nice, but consul and minio run nativily on macos.
	// The main benefit is isolation between parallel unit tests.
	// To use with colima, some env vars need to be set,
	// or just use the testcontainers desktop app.

	consulEndpoint, consulCleanup := consulSetup(ctx)
	defer consulCleanup()

	minioEndpoint, minioUsername, minioPassword, minioBucket, minioRegion, minioCleanup := minioSetup(ctx)
	defer minioCleanup()

	// Upload config to Consul
	logName := "testlog"

	config := ctsubmit.GlobalConfig{
		Name:          logName,
		KeyPath:       "",
		KeySha256:     "",
		RootPath:      "",
		ListenAddress: "localhost:3030",

		S3Bucket:                   minioBucket,
		S3Region:                   minioRegion,
		S3EndpointUrl:              minioEndpoint,
		S3StaticCredentialUserName: minioUsername,
		S3StaticCredentialPassword: minioPassword,
	}

	err := uploadConfig(consulEndpoint, logName, config)
	if err != nil {
		log.Fatalf("failed to upload config: %s", err)
	}

	configChan <- config

	submitListener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		log.Fatalf("failed to create listener: %s", err)
	}

	monitorListener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		log.Fatalf("failed to create listener: %s", err)
	}

	go ctsubmit.MainMain(submitListener, logName, consulEndpoint, startSignal)
	go ctmonitor.MainMain(monitorListener, minioEndpoint, startSignal)
	proxy(config.ListenAddress, monitorListener.Addr().String(), submitListener.Addr().String())
}

func consulSetup(ctx context.Context) (string, func()) {
	// Consul
	consulContainer, err := tcConsul.RunContainer(ctx,
		testcontainers.WithImage("docker.io/hashicorp/consul:1.15"),
	)
	if err != nil {
		log.Fatalf("failed to start container: %s", err)
	}

	consulEndpoint, err := consulContainer.ApiEndpoint(ctx)
	if err != nil {
		log.Fatalf("failed to get consul endpoint: %s", err)
	}

	return consulEndpoint, func() {
		if err := consulContainer.Terminate(ctx); err != nil {
			log.Fatalf("failed to terminate container: %s", err)
		}
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

func minioSetup(ctx context.Context) (string, string, string, string, string, func()) {
	// Minio is used as the S3 provider for integration testing
	minioContainer, err := minio.RunContainer(ctx, testcontainers.WithImage("minio/minio:RELEASE.2024-01-16T16-07-38Z"))
	if err != nil {
		log.Fatalf("failed to start container: %s", err)
	}

	minioEndpoint, err := minioContainer.ConnectionString(ctx)
	if err != nil {
		log.Fatalf("failed to get connection string: %s", err)
	}

	minioEndpoint = "http://" + minioEndpoint
	minioUsername, minioPassword := minioContainer.Username, minioContainer.Password

	// We could do this by adding to the ctlog.Bucket, but this will never be used otherwise
	bucketName := "testbucket"
	bucketRegion := "us-east-1"

	s3Config := aws.Config{
		Credentials:  credentials.NewStaticCredentialsProvider(minioUsername, minioPassword, ""),
		BaseEndpoint: aws.String(minioEndpoint),
		Region:       bucketRegion,
	}
	client := s3.NewFromConfig(s3Config)
	_, err = client.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		log.Fatalf("failed to create bucket: %s", err)
	}

	return minioEndpoint, minioContainer.Username, minioContainer.Password, bucketName, bucketRegion, func() {
		if err := minioContainer.Terminate(ctx); err != nil {
			log.Fatalf("failed to terminate container: %s", err)
		}
	}
}

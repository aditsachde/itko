package ctsubmit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	// s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

type Storage interface {
	Get(ctx context.Context, key string) ([]byte, error)
	Set(ctx context.Context, key string, data []byte) error
	Exists(ctx context.Context, key string) (bool, error)
}

// ------------------------------------------------------------

type S3Storage struct {
	client *s3.Client
	bucket string
}

func NewS3Storage(region, bucket, endpoint, username, password string) S3Storage {
	s3Config := aws.Config{
		Credentials:  credentials.NewStaticCredentialsProvider(username, password, ""),
		BaseEndpoint: aws.String(endpoint),
		Region:       region,
	}

	client := s3.NewFromConfig(s3Config, func(o *s3.Options) {
		o.UsePathStyle = true
	})

	return S3Storage{
		client: client,
		bucket: bucket,
	}
}

func (b *S3Storage) Get(ctx context.Context, key string) ([]byte, error) {
	output, err := b.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(b.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, err
	}
	defer output.Body.Close()
	data, err := io.ReadAll(output.Body)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (b *S3Storage) Set(ctx context.Context, key string, data []byte) error {
	_, err := b.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(b.bucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader(data),
	})
	return err
}

func (b *S3Storage) Exists(ctx context.Context, key string) (bool, error) {
	_, err := b.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(b.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		var responseError *awshttp.ResponseError
		if errors.As(err, &responseError) && responseError.ResponseError.HTTPStatusCode() == http.StatusNotFound {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// ------------------------------------------------------------

type FsStorage struct {
	root string
}

func NewFsStorage(rootDirectory string) FsStorage {
	return FsStorage{
		root: rootDirectory,
	}
}

func (f *FsStorage) Get(ctx context.Context, key string) ([]byte, error) {
	filePath := f.root + "/" + key

	// try and read the file using os.Readfile
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (f *FsStorage) Set(ctx context.Context, key string, data []byte) error {
	filePath := f.root + "/" + key

	// Attempt to write the file
	err := os.WriteFile(filePath, data, 0644)
	if err == nil {
		// No error, file written successfully
		return nil
	}

	// Check if the error is related to missing directories
	if os.IsNotExist(err) {
		// Extract the directory path from the file path
		dir := filepath.Dir(filePath)

		// Create the directory and any necessary parent directories
		mkdirErr := os.MkdirAll(dir, 0755)
		if mkdirErr != nil {
			return fmt.Errorf("failed to create directories: %w", mkdirErr)
		}

		// Retry writing the file after creating directories
		return os.WriteFile(filePath, data, 0644)
	}

	// Return the original error if it's not related to missing directories
	return err
}

func (f *FsStorage) Exists(ctx context.Context, key string) (bool, error) {
	filePath := f.root + "/" + key

	_, err := os.Stat(filePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

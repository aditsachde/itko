package ctmonitor

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
)

type Storage interface {
	Get(ctx context.Context, key string) (data []byte, notfounderr bool, err error)
	AvailableReqs() int
}

// ------------------------------------------------------------

type UrlStorage struct {
	urlPrefix string
}

func (f *UrlStorage) Get(ctx context.Context, key string) (data []byte, notfounderr bool, err error) {
	req, err := http.NewRequestWithContext(ctx, "GET", f.urlPrefix+key, nil)
	if err != nil {
		return nil, false, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, false, err
	}
	if resp.StatusCode != 200 {
		if resp.StatusCode == 404 {
			return nil, true, errors.New(resp.Status)
		} else {
			return nil, false, errors.New(resp.Status)
		}
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, false, err
	}
	return body, false, nil
}

func (f *UrlStorage) AvailableReqs() int {
	return 1
}

// ------------------------------------------------------------

type FsStorage struct {
	root string
}

func (f *FsStorage) Get(ctx context.Context, key string) (data []byte, notfounderr bool, err error) {
	filePath := f.root + "/" + key

	// try and read the file using os.Readfile
	data, err = os.ReadFile(filePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, true, err
		}
		return nil, false, err
	}
	return data, false, nil
}

func (f *FsStorage) AvailableReqs() int {
	return 1
}

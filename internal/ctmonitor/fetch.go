package ctmonitor

import (
	"context"
	"errors"
	"io"
	"net/http"
)

type Fetch struct {
	urlPrefix string
}

func newFetch(urlPrefix string) Fetch {
	return Fetch{
		urlPrefix: urlPrefix,
	}
}

func (f *Fetch) get(ctx context.Context, key string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", f.urlPrefix+key, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, errors.New(resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}

func (f *Fetch) getMulti(ctx context.Context, keys []string) ([][]byte, error) {
	var bodies [][]byte
	for _, key := range keys {
		body, err := f.get(ctx, key)
		if err != nil {
			return nil, err
		}
		bodies = append(bodies, body)
	}
	return bodies, nil
}

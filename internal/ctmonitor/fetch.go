package ctmonitor

import (
	"context"
	"errors"
	"io"
	"net/http"

	"golang.org/x/mod/sumdb/tlog"
	"itko.dev/internal/sunlight"
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
	resp, err, _ := f.getWithStatus(ctx, key)
	return resp, err
}

func (f *Fetch) getWithStatus(ctx context.Context, key string) ([]byte, error, int) {
	req, err := http.NewRequestWithContext(ctx, "GET", f.urlPrefix+key, nil)
	if err != nil {
		return nil, err, 500
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err, 500
	}
	if resp.StatusCode != 200 {
		return nil, errors.New(resp.Status), resp.StatusCode
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err, 500
	}
	return body, nil, 200
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

func (f *Fetch) getTile(ctx context.Context, tile tlog.Tile) ([]byte, error) {
	resp, err, status := f.getWithStatus(ctx, tile.Path())
	// In case the tile is not found and its a partial, try to fetch the full width tile
	if status == 404 {
		if tile.W != sunlight.TileWidth {
			tile.W = sunlight.TileWidth
			return f.get(ctx, tile.Path())
		}
	}
	return resp, err

}

// TODO: there has *got* to be a better way to do this
func (f *Fetch) getTileAAAA(ctx context.Context, tile tlog.Tile, finalTile tlog.Tile) ([]byte, error) {
	resp, err, status := f.getWithStatus(ctx, tile.Path())
	// In case the tile is not found and its a partial, try to fetch the full width tile
	if status == 404 {
		if tile.W != sunlight.TileWidth {
			tile.W = sunlight.TileWidth
			resp2, err2, status2 := f.getWithStatus(ctx, tile.Path())
			if status2 == 404 {
				return f.get(ctx, finalTile.Path())
			}
			return resp2, err2
		}
	}
	return resp, err
}

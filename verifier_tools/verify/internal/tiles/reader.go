// Package tiles contains methods to work with tlog based verifiable logs.
package tiles

import (
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"

	"golang.org/x/mod/sumdb/tlog"
)

// HashReader implements tlog.HashReader, reading from tlog-based log located at
// URL.
type HashReader struct {
	URL        string
	TileHeight int
	TreeSize   int64
}

// Domain separation prefix for Merkle tree hashing with second preimage
// resistance similar to that used in RFC 6962.
const (
	leafHashPrefix = 0
)

// ReadHashes implements tlog.HashReader's ReadHashes.
// See: https://pkg.go.dev/golang.org/x/mod/sumdb/tlog#HashReader.
func (h HashReader) ReadHashes(indices []int64) ([]tlog.Hash, error) {
	tiles := make(map[string][]byte) // cache tile path -> content
	hashes := make([]tlog.Hash, 0, len(indices))
	for _, index := range indices {
		// A tlog index is a pointer to a hash at a given level in the tree.
		// SplitStoredHashIndex returns the level and offset n for this index.
		level, n := tlog.SplitStoredHashIndex(index)

		// The tile metadata is calculated here.
		// See https://pkg.go.dev/golang.org/x/mod/sumdb/tlog#Tile for explanations
		// of H, L, N, and W.
		tile := tlog.Tile{H: h.TileHeight}
		// A tile of height H covers levels [L*H, (L+1)*H).
		// tile.L is the tile level which contains nodes at level `level`.
		tile.L = level / h.TileHeight
		// levelInTile is level of node `n` within its tile level L.
		levelInTile := level % h.TileHeight
		// tile.N is node index in tile level L.
		tile.N = n << uint(levelInTile) >> uint(h.TileHeight)
		// tile.W is tile width, initialized to maximum width.
		tile.W = 1 << uint(h.TileHeight)

		// Partial tile check based on tlog's tileParent logic
		// A tile might be partial if it's on the right edge of tree.
		// If tile extends beyond TreeSize, reduce tile.W to TreeSize limit.
		max := h.TreeSize >> uint(tile.L*h.TileHeight)
		if tile.N<<uint(h.TileHeight)+int64(tile.W) > max {
			if tile.N<<uint(h.TileHeight) >= max {
				tile.W = 0
			} else {
				tile.W = int(max - tile.N<<uint(h.TileHeight))
			}
		}

		if tile.W == 0 {
			hashes = append(hashes, tlog.Hash{})
			continue
		}

		pathForLookup := tile.Path()
		content, exists := tiles[pathForLookup]
		var err error

		if !exists {
			// If tile is not in cache, read it from URL.
			content, err = readFromURL(h.URL, pathForLookup)
			if err != nil {
				return nil, fmt.Errorf("tile fetch error for index %d: %v", index, err)
			}
			tiles[pathForLookup] = content
		}

		// Extract hash for `index` from downloaded tile content.
		hash, err := tlog.HashFromTile(tile, content, index)
		if err != nil {
			return nil, fmt.Errorf("failed to read data from tile for index %d: %v", index, err)
		}
		slog.Debug("Extracted hash", "index", fmt.Sprintf("%x", index), "hash", fmt.Sprintf("%x", hash))
		hashes = append(hashes, hash)
	}
	return hashes, nil
}

// BinaryInfosIndex returns a map from payload to its index in the
// transparency log according to the `binaryInfoFilename` value.
func BinaryInfosIndex(logBaseURL string, binaryInfoFilename string) (map[string]int64, error) {
	b, err := readFromURL(logBaseURL, binaryInfoFilename)
	if err != nil {
		return nil, err
	}

	binaryInfos := string(b)
	return parseBinaryInfosIndex(binaryInfos, binaryInfoFilename)
}

func parseBinaryInfosIndex(binaryInfos string, binaryInfoFilename string) (map[string]int64, error) {
	m := make(map[string]int64)

	infosStr := strings.Split(binaryInfos, "\n\n")
	for _, infoStr := range infosStr {
		pieces := strings.SplitN(infoStr, "\n", 2)
		if len(pieces) != 2 {
			return nil, fmt.Errorf("missing newline, malformed %s", binaryInfoFilename)
		}

		idx, err := strconv.ParseInt(pieces[0], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("failed to convert %q to int64", pieces[0])
		}

		// Ensure that each log entry does not have extraneous whitespace, but
		// also terminates with a newline.
		logEntry := strings.TrimSpace(pieces[1]) + "\n"
		m[logEntry] = idx
	}

	return m, nil
}

func readFromURL(base, suffix string) ([]byte, error) {
	u, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("invalid URL %s: %v", base, err)
	}
	u.Path = path.Join(u.Path, suffix)

	resp, err := http.Get(u.String())
	if err != nil {
		return nil, fmt.Errorf("http.Get(%s): %v", u.String(), err)
	}
	defer resp.Body.Close()
	if code := resp.StatusCode; code != 200 {
		return nil, fmt.Errorf("http.Get(%s): %s", u.String(), http.StatusText(code))
	}

	return io.ReadAll(resp.Body)
}

// PayloadHash returns the hash of the payload.
func PayloadHash(p []byte) (tlog.Hash, error) {
	l := append([]byte{leafHashPrefix}, p...)
	h := sha256.Sum256(l)

	var hash tlog.Hash
	copy(hash[:], h[:])
	return hash, nil
}

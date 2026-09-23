// Package tiles contains methods to work with tlog based verifiable logs.
package tiles

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/mod/sumdb/tlog"
)

// HashReader implements tlog.HashReader, reading from tlog-based log located at
// URL.
type HashReader struct {
	URL        string
	TileHeight int
	TreeSize   int64
	IsTessera  bool
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
		if h.IsTessera {
			// Tessera / c2sp tile path format is tile/<L>/<N>[.p/<W>], omitting the height <H>.
			pathForLookup = "tile/" + strings.TrimPrefix(pathForLookup, fmt.Sprintf("tile/%d/", h.TileHeight))
		}
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
func BinaryInfosIndex(logBaseURL string, binaryInfoFilename string, treeSize int64) (map[string]int64, error) {
	b, err := readCachedInfoFile(logBaseURL, binaryInfoFilename, treeSize)
	if err != nil {
		return nil, err
	}

	binaryInfos := string(b)
	return parseBinaryInfosIndex(binaryInfos, binaryInfoFilename)
}

const (
	defaultHTTPTimeout           = 5 * time.Minute
	defaultResponseHeaderTimeout = 30 * time.Second
	defaultDialTimeout           = 10 * time.Second
	defaultTLSHandshakeTimeout   = 10 * time.Second
)

var httpClient = &http.Client{
	// Timeout covers the entire request including reading large legacy binary info
	// response bodies (e.g. ~210 MB package_info.txt), while Transport timeouts bound
	// connection establishment and waiting for response headers.
	Timeout: defaultHTTPTimeout,
	Transport: &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   defaultDialTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   32,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   defaultTLSHandshakeTimeout,
		ResponseHeaderTimeout: defaultResponseHeaderTimeout,
		ExpectContinueTimeout: 1 * time.Second,
	},
}

var (
	customCacheDirMu sync.RWMutex
	customCacheDir   string
)

// SetCacheDir configures a custom root directory for the local cache.
// If dir is empty, the default user cache directory scheme is used.
func SetCacheDir(dir string) {
	customCacheDirMu.Lock()
	defer customCacheDirMu.Unlock()
	customCacheDir = dir
}

// CacheDir returns the active root directory used for caching.
// If a custom directory was set via SetCacheDir, it is returned.
// Otherwise, it returns <os.UserCacheDir>/android-binary-transparency.
func CacheDir() (string, error) {
	customCacheDirMu.RLock()
	defer customCacheDirMu.RUnlock()
	if customCacheDir != "" {
		return customCacheDir, nil
	}
	userCacheDir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(userCacheDir, "android-binary-transparency"), nil
}

// LogDirFromURL derives a clean relative directory path for the cache based on the log's base URL.
// It uses the URL path, removing any redundant "android/binary_transparency" prefix.
// If the path is empty (e.g. Pixel root or localhost test servers), it provides a sensible fallback.
func LogDirFromURL(logBaseURL string) string {
	u, err := url.Parse(logBaseURL)
	if err != nil {
		h := sha256.Sum256([]byte(logBaseURL))
		return fmt.Sprintf("%x", h[:8])
	}
	p := strings.Trim(u.Path, "/")
	p = strings.TrimPrefix(p, "android/binary_transparency")
	p = strings.Trim(p, "/")
	if p == "" {
		if strings.Contains(logBaseURL, "developers.google.com") || strings.Contains(logBaseURL, "binary_transparency") {
			return "pixel"
		}
		if u.Host != "" {
			return strings.ReplaceAll(u.Host, ":", "_")
		}
		return "default"
	}
	return filepath.FromSlash(p)
}

func readCachedInfoFile(logBaseURL string, binaryInfoFilename string, treeSize int64) ([]byte, error) {
	return readCachedInfoFileContext(context.Background(), logBaseURL, binaryInfoFilename, treeSize)
}

func readCachedInfoFileContext(ctx context.Context, logBaseURL string, binaryInfoFilename string, treeSize int64) ([]byte, error) {
	abtCacheDir, err := CacheDir()
	if err != nil {
		slog.Warn("Failed to get cache dir, falling back to direct download", "error", err)
		return readFromURLContext(ctx, logBaseURL, binaryInfoFilename)
	}

	logDir := LogDirFromURL(logBaseURL)
	targetDir := filepath.Join(abtCacheDir, logDir)
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		slog.Warn("Failed to create cache dir, falling back to direct download", "error", err)
		return readFromURLContext(ctx, logBaseURL, binaryInfoFilename)
	}

	cacheFilename := fmt.Sprintf("%s_%d", binaryInfoFilename, treeSize)
	cachePath := filepath.Join(targetDir, cacheFilename)

	// Try reading from cache
	if b, err := os.ReadFile(cachePath); err == nil {
		slog.Debug("Loaded info file from local cache", "path", cachePath)
		return b, nil
	}

	// Cache miss, download from URL
	slog.Info("Downloading new info file", "url", logBaseURL+"/"+binaryInfoFilename)
	b, err := readFromURLContext(ctx, logBaseURL, binaryInfoFilename)
	if err != nil {
		return nil, err
	}

	// Save to cache atomically
	tmpFile, err := os.CreateTemp(targetDir, cacheFilename+".*.tmp")
	if err != nil {
		slog.Warn("Failed to create cache tmp file", "error", err)
		return b, nil
	}
	tmpPath := tmpFile.Name()

	// Clean up tmp file on exit if it hasn't been renamed
	defer os.Remove(tmpPath)

	slog.Info("Writing info file to cache", "path", tmpPath)
	if _, err := tmpFile.Write(b); err != nil {
		slog.Warn("Failed to write to cache tmp file", "error", err)
		tmpFile.Close()
		return b, nil
	}
	if err := tmpFile.Close(); err != nil {
		slog.Warn("Failed to close cache tmp file", "error", err)
		return b, nil
	}

	slog.Info("Renaming cache file", "from", tmpPath, "to", cachePath)
	if err := os.Rename(tmpPath, cachePath); err != nil {
		slog.Warn("Failed to move cache file to final destination", "error", err)
		return b, nil
	}

	slog.Debug("Saved info file to local cache", "path", cachePath)

	// Cleanup old cache files for this specific binaryInfoFilename safely
	slog.Info("Cleaning up old cache files", "prefix", binaryInfoFilename)
	if entries, err := os.ReadDir(targetDir); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}

			// Only process files that match our specific binaryInfoFilename prefix
			if !strings.HasPrefix(entry.Name(), binaryInfoFilename+"_") {
				continue
			}

			f := filepath.Join(targetDir, entry.Name())
			if f == cachePath {
				continue
			}

			info, err := entry.Info()
			if err != nil {
				continue
			}

			// Delete old temp files (older than 1 hour) left over from hard crashes.
			// Otherwise, keep current temp files to avoid breaking active concurrent downloads.
			if strings.HasSuffix(entry.Name(), ".tmp") {
				if time.Since(info.ModTime()) > time.Hour {
					if err := os.Remove(f); err == nil {
						slog.Debug("Cleaned up orphaned cache temp file", "path", f)
					}
				}
				continue
			}

			// Delete old cache files (older than 24 hours to prevent cache invalidation storms)
			if time.Since(info.ModTime()) > 24*time.Hour {
				if err := os.Remove(f); err == nil {
					slog.Debug("Cleaned up old cache file", "path", f)
				}
			}
		}
	}

	return b, nil
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
	return readFromURLContext(context.Background(), base, suffix)
}

func readFromURLContext(ctx context.Context, base, suffix string) ([]byte, error) {
	u, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("invalid URL %s: %v", base, err)
	}
	u.Path = path.Join(u.Path, suffix)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("http.NewRequestWithContext(%s): %w", u.String(), err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("httpClient.Do(%s): %w", u.String(), err)
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

// EntryTilePath returns the relative path for an entry tile given its index N and width W.
func EntryTilePath(tileN int64, w int) string {
	t := tlog.Tile{H: 8, L: 0, N: tileN, W: w}
	p := t.Path()
	return "tile/entries/" + strings.TrimPrefix(p, "tile/8/0/")
}

// ParseEntryBundle parses an entry bundle encoded according to the tlog-tiles spec:
// a sequence of 2-byte big-endian length-prefixed entries.
func ParseEntryBundle(data []byte) ([][]byte, error) {
	var entries [][]byte
	r := bytes.NewReader(data)
	for r.Len() > 0 {
		var length uint16
		if err := binary.Read(r, binary.BigEndian, &length); err != nil {
			return nil, fmt.Errorf("failed to read entry length: %w", err)
		}
		if int(length) > r.Len() {
			return nil, fmt.Errorf("entry length %d exceeds remaining data length %d", length, r.Len())
		}
		entry := make([]byte, length)
		if _, err := io.ReadFull(r, entry); err != nil {
			return nil, fmt.Errorf("failed to read entry data: %w", err)
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func readCachedEntryTile(logBaseURL string, tileN int64, w int) ([]byte, error) {
	return readCachedEntryTileContext(context.Background(), logBaseURL, tileN, w)
}

func readCachedEntryTileContext(ctx context.Context, logBaseURL string, tileN int64, w int) ([]byte, error) {
	entryPath := EntryTilePath(tileN, w)

	abtCacheDir, err := CacheDir()
	if err != nil {
		slog.Warn("Failed to get cache dir, falling back to direct download", "error", err)
		b, err := readFromURLContext(ctx, logBaseURL, entryPath)
		if err != nil {
			// Fallback to tiles/entries/ if tile/entries/ fails
			altPath := "tiles/entries/" + strings.TrimPrefix(entryPath, "tile/entries/")
			return readFromURLContext(ctx, logBaseURL, altPath)
		}
		return b, nil
	}

	logDir := LogDirFromURL(logBaseURL)
	cachePath := filepath.Join(abtCacheDir, logDir, filepath.FromSlash(entryPath))

	// Try reading from cache
	if b, err := os.ReadFile(cachePath); err == nil {
		slog.Debug("Loaded entry tile from local cache", "path", cachePath)
		return b, nil
	}

	// Cache miss, download from URL
	slog.Debug("Downloading entry tile", "url", logBaseURL+"/"+entryPath)
	b, err := readFromURLContext(ctx, logBaseURL, entryPath)
	if err != nil {
		altPath := "tiles/entries/" + strings.TrimPrefix(entryPath, "tile/entries/")
		slog.Debug("Trying alternative entry tile path", "url", logBaseURL+"/"+altPath)
		b, err = readFromURLContext(ctx, logBaseURL, altPath)
		if err != nil {
			return nil, err
		}
	}

	// Save to cache atomically
	cacheDir := filepath.Dir(cachePath)
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		slog.Warn("Failed to create cache dir, falling back to direct download", "error", err)
		return b, nil
	}

	tmpFile, err := os.CreateTemp(cacheDir, filepath.Base(cachePath)+".*.tmp")
	if err != nil {
		slog.Warn("Failed to create cache tmp file", "error", err)
		return b, nil
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if _, err := tmpFile.Write(b); err != nil {
		slog.Warn("Failed to write to cache tmp file", "error", err)
		tmpFile.Close()
		return b, nil
	}
	if err := tmpFile.Close(); err != nil {
		slog.Warn("Failed to close cache tmp file", "error", err)
		return b, nil
	}

	if err := os.Rename(tmpPath, cachePath); err != nil {
		slog.Warn("Failed to move cache file to final destination", "error", err)
		return b, nil
	}

	// When a full tile is written, clean up any stale partial tile directory for this tile index.
	// Partial tiles for index N reside in "<cachePath>.p" (e.g. tile/entries/000.p/15).
	// Removing the directory is an O(1) targeted eviction that avoids scanning the parent directory.
	if w == 256 {
		_ = os.RemoveAll(cachePath + ".p")
	}

	return b, nil
}

func isEntryTileCached(logBaseURL string, tileN int64, w int) bool {
	abtCacheDir, err := CacheDir()
	if err != nil {
		return false
	}
	logDir := LogDirFromURL(logBaseURL)
	cachePath := filepath.Join(abtCacheDir, logDir, filepath.FromSlash(EntryTilePath(tileN, w)))
	info, err := os.Stat(cachePath)
	return err == nil && !info.IsDir() && info.Size() > 0
}

// DefaultTesseraFetchConcurrency is the default number of concurrent workers used by FetchAllTesseraEntries.
const DefaultTesseraFetchConcurrency = 16

// FetchAllLegacyEntries downloads and caches all specified legacy binary info files
// (e.g. package_info.txt, package_info2.txt) for the given log URL and tree size.
// Files already present in the local cache are loaded without re-downloading.
func FetchAllLegacyEntries(ctx context.Context, logBaseURL string, filenames []string, treeSize int64) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if treeSize <= 0 {
		return fmt.Errorf("invalid treeSize %d for legacy entries", treeSize)
	}
	for _, filename := range filenames {
		slog.Info("Fetching legacy info file", "url", logBaseURL, "file", filename, "treeSize", treeSize)
		_, err := readCachedInfoFileContext(ctx, logBaseURL, filename, treeSize)
		if err != nil {
			return fmt.Errorf("failed to fetch legacy info file %s: %w", filename, err)
		}
	}
	return nil
}

// FetchAllTesseraEntries concurrently downloads all entry tiles up to treeSize into the local cache.
// Tiles already cached locally are skipped, making incremental runs fast and idempotent.
// If concurrency <= 0, DefaultTesseraFetchConcurrency is used.
func FetchAllTesseraEntries(ctx context.Context, logBaseURL string, treeSize int64, concurrency int) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if treeSize <= 0 {
		return nil
	}
	if concurrency <= 0 {
		concurrency = DefaultTesseraFetchConcurrency
	}

	numTiles := (treeSize + 255) / 256

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type tileTask struct {
		tileN int64
		w     int
	}

	taskChan := make(chan tileTask, concurrency*2)
	var wg sync.WaitGroup
	var firstErr error
	var errOnce sync.Once
	var downloadedCount atomic.Int64
	var cachedCount atomic.Int64

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for task := range taskChan {
				select {
				case <-ctx.Done():
					return
				default:
				}

				if isEntryTileCached(logBaseURL, task.tileN, task.w) {
					cachedCount.Add(1)
					continue
				}

				_, err := readCachedEntryTileContext(ctx, logBaseURL, task.tileN, task.w)
				if err != nil {
					errOnce.Do(func() {
						firstErr = fmt.Errorf("failed to fetch entry tile %d (width %d): %w", task.tileN, task.w, err)
						cancel()
					})
					return
				}
				downloaded := downloadedCount.Add(1)
				if numTiles > 50 && downloaded%100 == 0 {
					slog.Info("Fetching Tessera entry tiles...", "downloaded", downloaded, "total", numTiles)
				}
			}
		}()
	}

	for tileN := int64(0); tileN < numTiles; tileN++ {
		if ctx.Err() != nil {
			break
		}

		w := 256
		if (tileN+1)*256 > treeSize {
			w = int(treeSize - tileN*256)
		}

		select {
		case <-ctx.Done():
		case taskChan <- tileTask{tileN: tileN, w: w}:
		}
		if ctx.Err() != nil {
			break
		}
	}
	close(taskChan)
	wg.Wait()

	if firstErr != nil {
		return firstErr
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	slog.Info("Completed Tessera entry tiles fetch", "totalTiles", numTiles, "downloaded", downloadedCount.Load(), "alreadyCached", cachedCount.Load())
	return nil
}

// TesseraFindPayloadIndex searches the Tessera entry tiles in reverse order
// (newest to oldest) for targetPayload and returns its 0-based sequence index
// in the log. It returns the highest index if the payload appears more than once.
// Returns (index, true, nil) if found, (-1, false, nil) if not found.
func TesseraFindPayloadIndex(logBaseURL string, treeSize int64, targetPayload []byte) (int64, bool, error) {
	if treeSize <= 0 {
		return -1, false, nil
	}

	numTiles := (treeSize + 255) / 256
	target := bytes.TrimSpace(targetPayload)

	// Search in reverse (latest to oldest) to find recent packages with typically
	// fewer HTTP requests on cold caches.
	for tileN := numTiles - 1; tileN >= 0; tileN-- {
		w := 256
		if (tileN+1)*256 > treeSize {
			w = int(treeSize - tileN*256)
		}

		b, err := readCachedEntryTile(logBaseURL, tileN, w)
		if err != nil {
			return -1, false, fmt.Errorf("failed to fetch entry tile %d (width %d): %w", tileN, w, err)
		}

		entries, err := ParseEntryBundle(b)
		if err != nil {
			return -1, false, fmt.Errorf("failed to parse entry tile %d: %w", tileN, err)
		}

		for idx := len(entries) - 1; idx >= 0; idx-- {
			if bytes.Equal(bytes.TrimSpace(entries[idx]), target) {
				return tileN*256 + int64(idx), true, nil
			}
		}
	}

	return -1, false, nil
}

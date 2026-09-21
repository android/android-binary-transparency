package tiles

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/mod/sumdb/tlog"
)

const (
	tileHeight = 1
)

// mustHexDecode decodes its input string from hex and panics if this fails.
func mustHexDecode(b string) []byte {
	r, err := hex.DecodeString(b)
	if err != nil {
		log.Fatalf("unable to decode string %v", err)
	}
	return r
}

// nodeHashes is a structured slice of node hashes for all complete subtrees of a Merkle tree built from test data using the RFC 6962 hashing strategy. The first index in the slice is the tree level (zero being the leaves level), the second is the horizontal index within a level.
var nodeHashes = [][][]byte{{
	mustHexDecode("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"),
	mustHexDecode("96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7"),
	mustHexDecode("0298d122906dcfc10892cb53a73992fc5b9f493ea4c9badb27b791b4127a7fe7"),
	mustHexDecode("07506a85fd9dd2f120eb694f86011e5bb4662e5c415a62917033d4a9624487e7"),
	mustHexDecode("bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b"),
	mustHexDecode("4271a26be0d8a84f0bd54c8c302e7cb3a3b5d1fa6780a40bcce2873477dab658"),
	mustHexDecode("b08693ec2e721597130641e8211e7eedccb4c26413963eee6c1e2ed16ffb1a5f"),
	mustHexDecode("46f6ffadd3d06a09ff3c5860d2755c8b9819db7df44251788c7d8e3180de8eb1"),
}, {
	mustHexDecode("fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125"),
	mustHexDecode("5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e"),
	mustHexDecode("0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a"),
	mustHexDecode("ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0"),
}, {
	mustHexDecode("d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7"),
	mustHexDecode("6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4"),
}, {
	mustHexDecode("5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328"),
}}

// testServer serves a tile based log of height 1, using the test data in
// nodeHashes.
func testServer(ctx context.Context, t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// Parse the tile data out of r.URL.
		// Strip the leading `/` to get a valid tile path.
		tile, err := tlog.ParseTilePath(r.URL.String()[1:])
		if err != nil {
			t.Fatalf("ParseTilePath(%s): %v", r.URL.String(), err)
		}
		// Fill the response with the test nodeHashes ...
		io.Copy(w, bytes.NewReader(nodeHashes[tile.L][2*tile.N]))
		if tile.W == 2 {
			// ... with special handling when the width is 2
			io.Copy(w, bytes.NewReader(nodeHashes[tile.L][2*tile.N+1]))
		}
	}))
}

func TestReadHashesWithReadTileData(t *testing.T) {
	ctx := context.Background()
	s := testServer(ctx, t)
	defer s.Close()

	for _, tc := range []struct {
		desc string
		size uint64
		want [][]byte
	}{
		{desc: "empty-0", size: 0},
		{
			desc: "size-3",
			size: 3,
			want: [][]byte{
				nodeHashes[0][0],
				append(nodeHashes[0][0], nodeHashes[0][1]...),
				nodeHashes[1][0],
				nodeHashes[0][2],
			},
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			r := HashReader{URL: s.URL, TileHeight: tileHeight, TreeSize: int64(tc.size)}

			// Read hashes.
			for i, want := range tc.want {
				tile := tlog.TileForIndex(tileHeight, int64(i))
				got, err := tlog.ReadTileData(tile, r)
				if err != nil {
					t.Fatalf("ReadTileData: %v", err)
				}
				if !cmp.Equal(got, want) {
					t.Errorf("tile %+v: got %X, want %X", tile, got, want)
				}
			}
		})
	}
}

func TestReadHashesCachedTile(t *testing.T) {
	ctx := context.Background()
	s := testServer(ctx, t)
	defer s.Close()

	wantHash := nodeHashes[0][0]
	r := HashReader{URL: s.URL, TileHeight: tileHeight, TreeSize: 3}

	// Read hash at index 0 twice, to exercise the caching of tiles.
	// On the first pass, the read is fresh and readFromURL is called.
	// On the second pass, the tile is cached, so we skip readFromURL.
	// We don't explicitly check that readFromURL is only called once,
	// but we do check ReadHashes returns the correct values.
	indices := []int64{0, 0}
	hashes, err := r.ReadHashes(indices)
	if err != nil {
		t.Fatalf("ReadHashes: %v", err)
	}

	got := make([][]byte, 0, len(indices))
	for _, hash := range hashes {
		got = append(got, hash[:])
	}

	if !bytes.Equal(got[0], got[1]) {
		t.Errorf("expected the same hash: got %X, want %X", got[0], got[1])
	}
	if !bytes.Equal(got[0], wantHash) {
		t.Errorf("wrong ReadHashes result: got %X, want %X", got[0], wantHash)
	}
}

func TestParseImageInfosIndex(t *testing.T) {
	for _, tc := range []struct {
		desc       string
		imageInfos string
		want       map[string]int64
		wantErr    bool
	}{
		{
			desc:       "size 2",
			imageInfos: "0\nbuild_fingerprint0\nimage_digest0\n\n1\nbuild_fingerprint1\nimage_digest1\n",
			wantErr:    false,
			want: map[string]int64{
				"build_fingerprint0\nimage_digest0\n": 0,
				"build_fingerprint1\nimage_digest1\n": 1,
			},
		},
		{
			desc:       "invalid log entry (no newlines)",
			imageInfos: "0build_fingerprintimage_digest",
			wantErr:    true,
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := parseBinaryInfosIndex(tc.imageInfos, "image_info.txt")
			if err != nil && !tc.wantErr {
				t.Fatalf("parseBinaryInfosIndex(%s) received unexpected err %q", tc.imageInfos, err)
			}

			if err == nil && tc.wantErr {
				t.Fatalf("parseBinaryInfosIndex(%s) did not return err, expected err", tc.imageInfos)
			}

			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("parseBinaryInfosIndex returned unexpected diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestParsePackageInfosIndex(t *testing.T) {
	for _, tc := range []struct {
		desc         string
		packageInfos string
		want         map[string]int64
		wantErr      bool
	}{
		{
			desc:         "size 2",
			packageInfos: "0\nhash0\nhash_desc0\npackage_name0\npackage_version0\n\n1\nhash1\nhash_desc1\npackage_name1\npackage_version1\n",
			wantErr:      false,
			want: map[string]int64{
				"hash0\nhash_desc0\npackage_name0\npackage_version0\n": 0,
				"hash1\nhash_desc1\npackage_name1\npackage_version1\n": 1,
			},
		},
		{
			desc:         "package_info2 format with large indices",
			packageInfos: "1714861\nhash0\nhash_desc0\npackage_name0\npackage_version0\n\n1797151\nhash1\nhash_desc1\npackage_name1\npackage_version1\n",
			wantErr:      false,
			want: map[string]int64{
				"hash0\nhash_desc0\npackage_name0\npackage_version0\n": 1714861,
				"hash1\nhash_desc1\npackage_name1\npackage_version1\n": 1797151,
			},
		},
		{
			desc:         "invalid log entry (no newlines)",
			packageInfos: "0hashhash_descpackage_namepackage_version",
			wantErr:      true,
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := parseBinaryInfosIndex(tc.packageInfos, "package_info.txt")
			if err != nil && !tc.wantErr {
				t.Fatalf("parseBinaryInfosIndex(%s) received unexpected err %q", tc.packageInfos, err)
			}

			if err == nil && tc.wantErr {
				t.Fatalf("parseBinaryInfosIndex(%s) did not return err, expected err", tc.packageInfos)
			}

			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("parseBinaryInfosIndex returned unexpected diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestEntryTilePath(t *testing.T) {
	tests := []struct {
		tileN int64
		w     int
		want  string
	}{
		{
			tileN: 0,
			w:     256,
			want:  "tile/entries/000",
		},
		{
			tileN: 0,
			w:     15,
			want:  "tile/entries/000.p/15",
		},
		{
			tileN: 1,
			w:     256,
			want:  "tile/entries/001",
		},
		{
			tileN: 1234067,
			w:     8,
			want:  "tile/entries/x001/x234/067.p/8",
		},
	}

	for _, tt := range tests {
		got := EntryTilePath(tt.tileN, tt.w)
		if got != tt.want {
			t.Errorf("EntryTilePath(%d, %d) = %q, want %q", tt.tileN, tt.w, got, tt.want)
		}
	}
}

func TestParseEntryBundle(t *testing.T) {
	entry1 := []byte("entry one content\n")
	entry2 := []byte("entry two content\n")

	var buf bytes.Buffer
	buf.Write([]byte{0x00, byte(len(entry1))})
	buf.Write(entry1)
	buf.Write([]byte{0x00, byte(len(entry2))})
	buf.Write(entry2)

	entries, err := ParseEntryBundle(buf.Bytes())
	if err != nil {
		t.Fatalf("ParseEntryBundle failed: %v", err)
	}

	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	if !bytes.Equal(entries[0], entry1) {
		t.Errorf("entry[0] = %q, want %q", entries[0], entry1)
	}
	if !bytes.Equal(entries[1], entry2) {
		t.Errorf("entry[1] = %q, want %q", entries[1], entry2)
	}

	// Test invalid / truncated bundle
	_, err = ParseEntryBundle([]byte{0x00, 0x10, 'a'})
	if err == nil {
		t.Errorf("ParseEntryBundle on truncated data expected error, got nil")
	}
}

func TestTesseraFindPayloadIndex(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)
	t.Setenv("XDG_CACHE_HOME", tempDir)

	crossTileDupPayload := []byte("hash_dup_cross\nhash_desc_dup\npackage_name_dup\n999\n")
	intraTileDupPayload := []byte("hash_dup_intra\nhash_desc_dup\npackage_name_intra\n888\n")

	var tile0Entries [][]byte
	for i := 0; i < 256; i++ {
		switch i {
		case 10:
			tile0Entries = append(tile0Entries, crossTileDupPayload)
		case 20, 200:
			tile0Entries = append(tile0Entries, intraTileDupPayload)
		default:
			tile0Entries = append(tile0Entries, []byte(fmt.Sprintf("hash0_%d\nhash_desc0\npackage_name0\n%d\n", i, i)))
		}
	}
	tile0Data := createTestEntryBundle(tile0Entries)

	// Tile 1 contains crossTileDupPayload at index 256 (tile1[0]) and entry257 at index 257 (tile1[1]).
	entry257 := []byte("hash1_1\nhash_desc1\npackage_name1\n257\n")
	tile1Data := createTestEntryBundle([][]byte{crossTileDupPayload, entry257})

	var tile0Requests atomic.Int64
	var tile1Requests atomic.Int64

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/tile/entries/000":
			tile0Requests.Add(1)
			w.Write(tile0Data)
		case "/tile/entries/001.p/2":
			tile1Requests.Add(1)
			w.Write(tile1Data)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	// Searching for an entry in the latest tile (tile 1) should scan in reverse
	// and find it without downloading tile 0.
	idx, found, err := TesseraFindPayloadIndex(server.URL, 258, entry257)
	if err != nil {
		t.Fatalf("TesseraFindPayloadIndex error: %v", err)
	}
	if !found || idx != 257 {
		t.Errorf("got (%d, %v), want (257, true)", idx, found)
	}
	if tile1Requests.Load() != 1 {
		t.Errorf("expected 1 request for tile 1, got %d", tile1Requests.Load())
	}
	if tile0Requests.Load() != 0 {
		t.Errorf("expected 0 requests for tile 0 when target is in latest tile, got %d", tile0Requests.Load())
	}

	// Duplicate across tiles (present at index 10 in tile 0 and index 256 in tile 1)
	// must resolve to the highest index (256) without needing to fetch tile 0.
	idx, found, err = TesseraFindPayloadIndex(server.URL, 258, crossTileDupPayload)
	if err != nil {
		t.Fatalf("TesseraFindPayloadIndex cross-tile duplicate error: %v", err)
	}
	if !found || idx != 256 {
		t.Errorf("cross-tile duplicate payload got (%d, %v), want highest index (256, true)", idx, found)
	}
	if tile0Requests.Load() != 0 {
		t.Errorf("expected 0 requests for tile 0 when duplicate resolves in tile 1, got %d", tile0Requests.Load())
	}

	// Searching for an entry in an older tile (tile 0) should fall back to tile 0
	// while serving tile 1 from cache without re-downloading it.
	idx, found, err = TesseraFindPayloadIndex(server.URL, 258, tile0Entries[42])
	if err != nil {
		t.Fatalf("TesseraFindPayloadIndex error: %v", err)
	}
	if !found || idx != 42 {
		t.Errorf("got (%d, %v), want (42, true)", idx, found)
	}
	if tile1Requests.Load() != 1 {
		t.Errorf("expected tile 1 to be served from cache (1 request total), got %d", tile1Requests.Load())
	}
	if tile0Requests.Load() != 1 {
		t.Errorf("expected 1 request for tile 0, got %d", tile0Requests.Load())
	}

	// Duplicate within a single tile (present at indices 20 and 200 in tile 0)
	// must resolve to the higher index (200) via the reverse inner-loop scan.
	idx, found, err = TesseraFindPayloadIndex(server.URL, 258, intraTileDupPayload)
	if err != nil {
		t.Fatalf("TesseraFindPayloadIndex intra-tile duplicate error: %v", err)
	}
	if !found || idx != 200 {
		t.Errorf("intra-tile duplicate payload got (%d, %v), want highest index (200, true)", idx, found)
	}

	// Search for non-existent payload across all tiles; both tiles must be served
	// from cache with zero additional HTTP requests.
	idx, found, err = TesseraFindPayloadIndex(server.URL, 258, []byte("non_existent"))
	if err != nil {
		t.Fatalf("TesseraFindPayloadIndex error: %v", err)
	}
	if found {
		t.Errorf("expected found=false for non-existent payload, got %d", idx)
	}
	if tile1Requests.Load() != 1 || tile0Requests.Load() != 1 {
		t.Errorf("expected cached tiles to not be re-downloaded (want 1, 1), got (%d, %d)",
			tile1Requests.Load(), tile0Requests.Load())
	}
}

func createTestEntryBundle(entries [][]byte) []byte {
	var buf bytes.Buffer
	for _, entry := range entries {
		var length uint16 = uint16(len(entry))
		binary.Write(&buf, binary.BigEndian, length)
		buf.Write(entry)
	}
	return buf.Bytes()
}

func TestFetchAllLegacyEntries(t *testing.T) {
	// Isolate user cache directory across OSes (macOS uses $HOME/Library/Caches, while Linux uses
	// $XDG_CACHE_HOME). This ensures the test runs against a fresh, hermetic cache and does not
	// read from or mutate the developer's actual cache.
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)
	t.Setenv("XDG_CACHE_HOME", tempDir)

	file1Content := "0\nhash0\nhash_desc0\npkg0\n1\n\n1\nhash1\nhash_desc1\npkg1\n2\n"
	file2Content := "2\nhash2\nhash_desc2\npkg2\n3\n"

	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		switch r.URL.Path {
		case "/package_info.txt":
			w.Write([]byte(file1Content))
		case "/package_info2.txt":
			w.Write([]byte(file2Content))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	ctx := context.Background()

	// Error case: invalid treeSize <= 0
	if err := FetchAllLegacyEntries(ctx, server.URL, []string{"package_info.txt"}, 0); err == nil {
		t.Errorf("FetchAllLegacyEntries with treeSize 0 expected error, got nil")
	}

	// Error case: file not found (404)
	if err := FetchAllLegacyEntries(ctx, server.URL, []string{"missing.txt"}, 3); err == nil {
		t.Errorf("FetchAllLegacyEntries with missing file expected error, got nil")
	}

	// Success case: fetch two legacy files
	filenames := []string{"package_info.txt", "package_info2.txt"}
	if err := FetchAllLegacyEntries(ctx, server.URL, filenames, 3); err != nil {
		t.Fatalf("FetchAllLegacyEntries failed: %v", err)
	}

	if got := requests.Load(); got != 3 { // 1 for missing.txt + 2 for valid files
		t.Errorf("expected 3 server requests so far, got %d", got)
	}

	// Subsequent BinaryInfosIndex calls should hit local cache with NO additional network requests
	m1, err := BinaryInfosIndex(server.URL, "package_info.txt", 3)
	if err != nil {
		t.Fatalf("BinaryInfosIndex(package_info.txt) failed: %v", err)
	}
	if len(m1) != 2 || m1["hash0\nhash_desc0\npkg0\n1\n"] != 0 {
		t.Errorf("unexpected index map from package_info.txt: %+v", m1)
	}

	m2, err := BinaryInfosIndex(server.URL, "package_info2.txt", 3)
	if err != nil {
		t.Fatalf("BinaryInfosIndex(package_info2.txt) failed: %v", err)
	}
	if len(m2) != 1 || m2["hash2\nhash_desc2\npkg2\n3\n"] != 2 {
		t.Errorf("unexpected index map from package_info2.txt: %+v", m2)
	}

	// Request count must still be 3 (zero network calls for cache hits)
	if got := requests.Load(); got != 3 {
		t.Errorf("expected request count to remain 3 after cached index reads, got %d", got)
	}
}

func TestFetchAllTesseraEntries(t *testing.T) {
	// Isolate user cache directory across OSes (macOS uses $HOME/Library/Caches, while Linux uses
	// $XDG_CACHE_HOME). This ensures the test runs against a fresh, hermetic cache and does not
	// read from or mutate the developer's actual cache.
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)
	t.Setenv("XDG_CACHE_HOME", tempDir)

	// Build 2 tiles:
	// Tile 0: full tile of 256 entries
	// Tile 1: partial tile of 10 entries (treeSize = 266)
	var tile0Entries [][]byte
	for i := 0; i < 256; i++ {
		tile0Entries = append(tile0Entries, []byte(fmt.Sprintf("tile0_entry_%d\n", i)))
	}
	tile0Data := createTestEntryBundle(tile0Entries)

	var tile1Entries [][]byte
	for i := 0; i < 10; i++ {
		tile1Entries = append(tile1Entries, []byte(fmt.Sprintf("tile1_entry_%d\n", i)))
	}
	tile1Data := createTestEntryBundle(tile1Entries)

	var tile0Requests atomic.Int64
	var tile1Requests atomic.Int64

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/tile/entries/000":
			tile0Requests.Add(1)
			w.Write(tile0Data)
		case "/tile/entries/001.p/10":
			tile1Requests.Add(1)
			w.Write(tile1Data)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	ctx := context.Background()

	// treeSize 0: no-op
	if err := FetchAllTesseraEntries(ctx, server.URL, 0, 4); err != nil {
		t.Fatalf("FetchAllTesseraEntries with treeSize 0 returned error: %v", err)
	}

	// Fetch all tiles for treeSize 266 with concurrency 4
	if err := FetchAllTesseraEntries(ctx, server.URL, 266, 4); err != nil {
		t.Fatalf("FetchAllTesseraEntries(266) failed: %v", err)
	}

	if tile0Requests.Load() != 1 {
		t.Errorf("expected 1 request for tile 0, got %d", tile0Requests.Load())
	}
	if tile1Requests.Load() != 1 {
		t.Errorf("expected 1 request for tile 1, got %d", tile1Requests.Load())
	}

	// TesseraFindPayloadIndex should find payloads in both tiles using the cached tiles
	idx0, found0, err := TesseraFindPayloadIndex(server.URL, 266, []byte("tile0_entry_42\n"))
	if err != nil || !found0 || idx0 != 42 {
		t.Errorf("TesseraFindPayloadIndex tile 0 = (%d, %v, %v), want (42, true, nil)", idx0, found0, err)
	}

	idx1, found1, err := TesseraFindPayloadIndex(server.URL, 266, []byte("tile1_entry_5\n"))
	if err != nil || !found1 || idx1 != 256+5 {
		t.Errorf("TesseraFindPayloadIndex tile 1 = (%d, %v, %v), want (261, true, nil)", idx1, found1, err)
	}

	// Second run of FetchAllTesseraEntries for the same treeSize:
	// Tile 0 (w=256) is full and cached, so it MUST be skipped!
	if err := FetchAllTesseraEntries(ctx, server.URL, 266, 4); err != nil {
		t.Fatalf("second FetchAllTesseraEntries failed: %v", err)
	}

	if tile0Requests.Load() != 1 {
		t.Errorf("expected tile 0 to be skipped on second sync, but requests increased to %d", tile0Requests.Load())
	}

	// Cancellation test: cancelled context should return context error
	cancelCtx, cancel := context.WithCancel(context.Background())
	cancel()
	err = FetchAllTesseraEntries(cancelCtx, server.URL, 266, 4)
	if err == nil {
		t.Errorf("expected error on cancelled context, got nil")
	}

	// Server error handling: requesting a non-existent tile
	err = FetchAllTesseraEntries(ctx, server.URL, 600, 4) // needs tile 2 which is 404
	if err == nil {
		t.Errorf("expected error when tile is missing (404), got nil")
	}
}

func TestSetCacheDir(t *testing.T) {
	customDir := t.TempDir()
	SetCacheDir(customDir)
	defer SetCacheDir("")

	got, err := CacheDir()
	if err != nil {
		t.Fatalf("CacheDir() failed: %v", err)
	}
	if got != customDir {
		t.Errorf("CacheDir() = %q, want %q", got, customDir)
	}

	// Verify that FetchAllLegacyEntries writes directly to the custom directory
	fileContent := "0\nhash0\nhash_desc0\npkg0\n1\n"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(fileContent))
	}))
	defer server.Close()

	if err := FetchAllLegacyEntries(context.Background(), server.URL, []string{"test_pkg.txt"}, 1); err != nil {
		t.Fatalf("FetchAllLegacyEntries failed with custom cache dir: %v", err)
	}

	// Check that customDir contains the cached file
	entries, err := os.ReadDir(customDir)
	if err != nil {
		t.Fatalf("failed to read custom cache dir: %v", err)
	}
	if len(entries) == 0 {
		t.Errorf("expected cached file in custom directory %s, found none", customDir)
	}
}

func TestLogDirFromURL(t *testing.T) {
	tests := []struct {
		url  string
		want string
	}{
		{
			url:  "https://developers.google.com/android/binary_transparency",
			want: "pixel",
		},
		{
			url:  "https://developers.google.com/android/binary_transparency/google1p",
			want: "google1p",
		},
		{
			url:  "https://www.gstatic.com/android/binary_transparency/google1p/apk/2026/01",
			want: filepath.FromSlash("google1p/apk/2026/01"),
		},
		{
			url:  "https://www.gstatic.com/android/binary_transparency/google1p/apk/2026/02",
			want: filepath.FromSlash("google1p/apk/2026/02"),
		},
		{
			url:  "https://www.gstatic.com/android/binary_transparency/mainline/2026/01",
			want: filepath.FromSlash("mainline/2026/01"),
		},
		{
			url:  "https://www.gstatic.com/android/binary_transparency/mainline/2026/02",
			want: filepath.FromSlash("mainline/2026/02"),
		},
		{
			url:  "http://127.0.0.1:8080",
			want: "127.0.0.1_8080",
		},
		{
			url:  "https://example.com/custom/shard",
			want: filepath.FromSlash("custom/shard"),
		},
	}

	for _, tt := range tests {
		got := LogDirFromURL(tt.url)
		if got != tt.want {
			t.Errorf("LogDirFromURL(%q) = %q, want %q", tt.url, got, tt.want)
		}
	}
}

func TestTesseraCacheShardingAndTargetedEviction(t *testing.T) {
	customDir := t.TempDir()
	SetCacheDir(customDir)
	defer SetCacheDir("")

	tile0Data := createTestEntryBundle([][]byte{[]byte("tile0_item\n")})
	tile1PartialData := createTestEntryBundle([][]byte{[]byte("tile1_partial\n")})
	tile1FullData := createTestEntryBundle([][]byte{[]byte("tile1_full\n")})
	deepTileData := createTestEntryBundle([][]byte{[]byte("deep_tile_entry\n")})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/tile/entries/000":
			w.Write(tile0Data)
		case "/tile/entries/001.p/10":
			w.Write(tile1PartialData)
		case "/tile/entries/001":
			w.Write(tile1FullData)
		case "/tile/entries/x001/x234/067":
			w.Write(deepTileData)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	ctx := context.Background()
	logDir := LogDirFromURL(server.URL)

	// 1. Fetch with treeSize 266:
	// Tile 0 is full (w=256), Tile 1 is partial (w=10).
	if err := FetchAllTesseraEntries(ctx, server.URL, 266, 2); err != nil {
		t.Fatalf("FetchAllTesseraEntries(266) failed: %v", err)
	}

	// Verify Tile 0 is saved to sharded path: <customDir>/<logDir>/tile/entries/000
	tile0Path := filepath.Join(customDir, logDir, "tile", "entries", "000")
	if info, err := os.Stat(tile0Path); err != nil || info.IsDir() {
		t.Errorf("expected full tile 0 at %s, err: %v", tile0Path, err)
	}

	// Verify Tile 1 partial is saved to: <customDir>/<logDir>/tile/entries/001.p/10
	tile1PartialDir := filepath.Join(customDir, logDir, "tile", "entries", "001.p")
	tile1PartialFile := filepath.Join(tile1PartialDir, "10")
	if info, err := os.Stat(tile1PartialFile); err != nil || info.IsDir() {
		t.Errorf("expected partial tile 1 at %s, err: %v", tile1PartialFile, err)
	}

	// Verify Tile 1 full tile does NOT exist yet
	tile1FullPath := filepath.Join(customDir, logDir, "tile", "entries", "001")
	if _, err := os.Stat(tile1FullPath); !os.IsNotExist(err) {
		t.Errorf("expected full tile 1 to not exist yet at %s", tile1FullPath)
	}

	// 2. Fetch with treeSize 512:
	// Tile 1 is now full (w=256).
	if err := FetchAllTesseraEntries(ctx, server.URL, 512, 2); err != nil {
		t.Fatalf("FetchAllTesseraEntries(512) failed: %v", err)
	}

	// Verify Tile 1 full tile now exists
	if info, err := os.Stat(tile1FullPath); err != nil || info.IsDir() {
		t.Errorf("expected full tile 1 at %s, err: %v", tile1FullPath, err)
	}

	// Verify O(1) targeted eviction: partial tile directory 001.p MUST BE REMOVED!
	if _, err := os.Stat(tile1PartialDir); !os.IsNotExist(err) {
		t.Errorf("expected partial tile directory %s to be evicted, but it still exists", tile1PartialDir)
	}

	// 3. Test multi-level sharding (tileN = 1234067, w = 256):
	// Path should be tile/entries/x001/x234/067
	// Fetch just that tile directly
	b, err := readCachedEntryTileContext(ctx, server.URL, 1234067, 256)
	if err != nil {
		t.Fatalf("readCachedEntryTileContext for tile 1234067 failed: %v", err)
	}
	if len(b) == 0 {
		t.Fatalf("expected non-empty bytes for tile 1234067")
	}

	deepTilePath := filepath.Join(customDir, logDir, "tile", "entries", "x001", "x234", "067")
	if info, err := os.Stat(deepTilePath); err != nil || info.IsDir() {
		t.Errorf("expected deep sharded tile at %s, err: %v", deepTilePath, err)
	}
}

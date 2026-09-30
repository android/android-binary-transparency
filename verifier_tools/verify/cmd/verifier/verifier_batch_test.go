package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/android/android-binary-transparency/verifier_tools/verify/internal/tiles"
	"github.com/google/go-cmp/cmp"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

// fakeLog serves a small signed transparency log over HTTP: a checkpoint,
// hash tiles and either Tessera entry tiles or a legacy package_info.txt.
type fakeLog struct {
	t          *testing.T
	origin     string
	tessera    bool
	tileHeight int
	entries    [][]byte
	// corruptHashTiles serves zeroed hash tiles, so inclusion proofs fail.
	corruptHashTiles bool
	// failFirstEntryTile makes the oldest Tessera entry tile return HTTP 500.
	failFirstEntryTile bool

	server              *httptest.Server
	verifier            note.Verifier
	checkpointRequests  atomic.Int64
	infoFileRequests    atomic.Int64
	entryTileRequests   atomic.Int64
	hashes              []tlog.Hash
	signedCheckpointTxt []byte
}

func (l *fakeLog) readHashes(indices []int64) ([]tlog.Hash, error) {
	out := make([]tlog.Hash, len(indices))
	for i, idx := range indices {
		if idx >= int64(len(l.hashes)) {
			return nil, fmt.Errorf("no stored hash %d", idx)
		}
		out[i] = l.hashes[idx]
	}
	return out, nil
}

func (l *fakeLog) start() *fakeLog {
	l.t.Helper()
	for i, e := range l.entries {
		hs, err := tlog.StoredHashes(int64(i), e, tlog.HashReaderFunc(l.readHashes))
		if err != nil {
			l.t.Fatalf("StoredHashes: %v", err)
		}
		l.hashes = append(l.hashes, hs...)
	}
	root, err := tlog.TreeHash(int64(len(l.entries)), tlog.HashReaderFunc(l.readHashes))
	if err != nil {
		l.t.Fatalf("TreeHash: %v", err)
	}

	name := strings.TrimSuffix(l.origin, "\n")
	skey, vkey, err := note.GenerateKey(rand.Reader, name)
	if err != nil {
		l.t.Fatalf("GenerateKey: %v", err)
	}
	signer, err := note.NewSigner(skey)
	if err != nil {
		l.t.Fatalf("NewSigner: %v", err)
	}
	if l.verifier, err = note.NewVerifier(vkey); err != nil {
		l.t.Fatalf("NewVerifier: %v", err)
	}
	text := fmt.Sprintf("%s%d\n%s\n", l.origin, len(l.entries), base64.StdEncoding.EncodeToString(root[:]))
	if l.signedCheckpointTxt, err = note.Sign(&note.Note{Text: text}, signer); err != nil {
		l.t.Fatalf("Sign: %v", err)
	}

	l.server = httptest.NewServer(http.HandlerFunc(l.serve))
	l.t.Cleanup(l.server.Close)
	return l
}

func (l *fakeLog) serve(w http.ResponseWriter, r *http.Request) {
	p := strings.TrimPrefix(r.URL.Path, "/")
	switch {
	case p == "checkpoint":
		l.checkpointRequests.Add(1)
		w.Write(l.signedCheckpointTxt)
	case p == PackageInfoFilename && !l.tessera:
		l.infoFileRequests.Add(1)
		var records []string
		for i, e := range l.entries {
			records = append(records, fmt.Sprintf("%d\n%s", i, bytes.TrimSpace(e)))
		}
		w.Write([]byte(strings.Join(records, "\n\n")))
	case strings.HasPrefix(p, "tile/entries/") && l.tessera:
		l.entryTileRequests.Add(1)
		var n, width int
		rest := strings.TrimPrefix(p, "tile/entries/")
		if _, err := fmt.Sscanf(rest, "%03d.p/%d", &n, &width); err != nil {
			if _, err := fmt.Sscanf(rest, "%03d", &n); err != nil {
				http.NotFound(w, r)
				return
			}
			width = 256
		}
		if n == 0 && l.failFirstEntryTile {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		var buf bytes.Buffer
		for _, e := range l.entries[n*256 : n*256+width] {
			binary.Write(&buf, binary.BigEndian, uint16(len(e)))
			buf.Write(e)
		}
		w.Write(buf.Bytes())
	case strings.HasPrefix(p, "tile/"):
		if l.tessera {
			p = fmt.Sprintf("tile/%d/%s", l.tileHeight, strings.TrimPrefix(p, "tile/"))
		}
		tile, err := tlog.ParseTilePath(p)
		if err != nil || tile.H != l.tileHeight {
			http.NotFound(w, r)
			return
		}
		data, err := tlog.ReadTileData(tile, tlog.HashReaderFunc(l.readHashes))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if l.corruptHashTiles {
			data = make([]byte, len(data))
		}
		w.Write(data)
	default:
		http.NotFound(w, r)
	}
}

func (l *fakeLog) target(name string) logTarget {
	target := logTarget{
		name:           name,
		baseURL:        l.server.URL,
		checkpointPath: "checkpoint",
		verifier:       l.verifier,
		tileHeight:     l.tileHeight,
		isTessera:      l.tessera,
	}
	if !l.tessera {
		target.binaryInfoFilenames = []string{PackageInfoFilename}
	}
	return target
}

func testPayload(name string) []byte {
	return []byte(fmt.Sprintf("hash_%s\nSHA256(Signed APK)\n%s\n1\n", name, name))
}

// testLogs returns a Tessera log followed by a legacy log. "both" is in each;
// "new" only in the Tessera log (in its last, partial entry tile); "old" only
// in the legacy log.
func testLogs(t *testing.T, corruptTessera bool) (*fakeLog, *fakeLog) {
	t.Helper()
	tiles.SetCacheDir(t.TempDir())
	t.Cleanup(func() { tiles.SetCacheDir("") })

	var tesseraEntries [][]byte
	for i := 0; i < 300; i++ {
		switch i {
		case 10:
			tesseraEntries = append(tesseraEntries, testPayload("both"))
		case 290:
			tesseraEntries = append(tesseraEntries, testPayload("new"))
		default:
			tesseraEntries = append(tesseraEntries, testPayload(fmt.Sprintf("t%d", i)))
		}
	}
	tessera := (&fakeLog{
		t:                t,
		origin:           "android.transparency.goog/google1p/apk/2026/1\n",
		tessera:          true,
		tileHeight:       8,
		entries:          tesseraEntries,
		corruptHashTiles: corruptTessera,
	}).start()
	legacy := (&fakeLog{
		t:          t,
		origin:     "gstatic.com/android/binary_transparency/google1p/apk/2026/0\n",
		tileHeight: 2,
		entries:    [][]byte{testPayload("l0"), testPayload("both"), testPayload("l2"), testPayload("old"), testPayload("l4")},
	}).start()
	return tessera, legacy
}

func collect(t *testing.T, ctx context.Context, targets []logTarget, payloads [][]byte) (map[int]payloadResult, error) {
	t.Helper()
	got := make(map[int]payloadResult)
	err := verifyPayloads(ctx, targets, payloads, func(r payloadResult) {
		if _, dup := got[r.Index]; dup {
			t.Errorf("result for payload %d emitted twice", r.Index)
		}
		got[r.Index] = r
	})
	return got, err
}

func TestVerifyPayloads(t *testing.T) {
	tessera, legacy := testLogs(t, false)
	targets := []logTarget{tessera.target("tessera"), legacy.target("legacy")}

	payloads := [][]byte{
		normalizePayload(testPayload("both")),
		normalizePayload(testPayload("missing")),
		normalizePayload(testPayload("old")),
		normalizePayload(append([]byte("\n  "), testPayload("new")...)),
	}
	got, err := collect(t, context.Background(), targets, payloads)
	if err != nil {
		t.Fatalf("verifyPayloads: %v", err)
	}
	want := map[int]payloadResult{
		// The first log that contains a payload decides.
		0: {Index: 0, Verified: true, Log: "tessera"},
		1: {Index: 1},
		2: {Index: 2, Verified: true, Log: "legacy"},
		3: {Index: 3, Verified: true, Log: "tessera"},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("verifyPayloads mismatch (-want +got):\n%s", diff)
	}

	// Each log is consulted once for all payloads.
	if n := tessera.checkpointRequests.Load(); n != 1 {
		t.Errorf("Tessera checkpoint fetched %d times, want 1", n)
	}
	if n := legacy.checkpointRequests.Load(); n != 1 {
		t.Errorf("legacy checkpoint fetched %d times, want 1", n)
	}
	if n := legacy.infoFileRequests.Load(); n != 1 {
		t.Errorf("legacy info file fetched %d times, want 1", n)
	}
	if n := tessera.entryTileRequests.Load(); n != 2 {
		t.Errorf("Tessera entry tiles fetched %d times, want 2", n)
	}
}

func TestVerifyPayloadsSkipsLaterLogsWhenAllFound(t *testing.T) {
	tessera, legacy := testLogs(t, false)
	targets := []logTarget{tessera.target("tessera"), legacy.target("legacy")}

	got, err := collect(t, context.Background(), targets, [][]byte{normalizePayload(testPayload("new"))})
	if err != nil {
		t.Fatalf("verifyPayloads: %v", err)
	}
	if want := (payloadResult{Index: 0, Verified: true, Log: "tessera"}); got[0] != want {
		t.Errorf("got %+v, want %+v", got[0], want)
	}
	if n := legacy.checkpointRequests.Load(); n != 0 {
		t.Errorf("legacy checkpoint fetched %d times, want 0", n)
	}
	// "new" is in the last entry tile, so the first tile is never read.
	if n := tessera.entryTileRequests.Load(); n != 1 {
		t.Errorf("Tessera entry tiles fetched %d times, want 1", n)
	}
}

func TestVerifyPayloadsEntryTileErrorMatchesSinglePayloadRuns(t *testing.T) {
	tessera, legacy := testLogs(t, false)
	tessera.failFirstEntryTile = true // Tile 0 holds "both"; tile 1 holds "new".
	targets := []logTarget{tessera.target("tessera"), legacy.target("legacy")}

	names := []string{"new", "both", "old", "missing"}
	var payloads [][]byte
	for _, name := range names {
		payloads = append(payloads, normalizePayload(testPayload(name)))
	}
	got, err := collect(t, context.Background(), targets, payloads)
	if err != nil {
		t.Fatalf("verifyPayloads: %v", err)
	}
	want := map[int]payloadResult{
		// Found in tile 1, before the failing tile: kept.
		0: {Index: 0, Verified: true, Log: "tessera"},
		// Its Tessera search fails, so it is found in the next log.
		1: {Index: 1, Verified: true, Log: "legacy"},
		2: {Index: 2, Verified: true, Log: "legacy"},
		3: {Index: 3},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("verifyPayloads mismatch (-want +got):\n%s", diff)
	}

	// Each result is what verifying that payload alone gives.
	for i, p := range payloads {
		single, err := collect(t, context.Background(), targets, [][]byte{p})
		if err != nil {
			t.Fatalf("verifyPayloads(%s): %v", names[i], err)
		}
		r := single[0]
		r.Index = i
		if r != got[i] {
			t.Errorf("%s: batch result %+v, single-payload result %+v", names[i], got[i], r)
		}
	}
}

func TestVerifyPayloadsFailedProofIsFinal(t *testing.T) {
	tessera, legacy := testLogs(t, true)
	targets := []logTarget{tessera.target("tessera"), legacy.target("legacy")}

	got, err := collect(t, context.Background(), targets, [][]byte{
		normalizePayload(testPayload("both")),
		normalizePayload(testPayload("old")),
	})
	if err != nil {
		t.Fatalf("verifyPayloads: %v", err)
	}
	// "both" is found in the Tessera log, whose proof fails; like a
	// single-payload run, the legacy log is not tried for it.
	if r := got[0]; r.Verified || r.Error == "" || r.Log != "" {
		t.Errorf("payload 0 = %+v, want unverified with an error", r)
	}
	if want := (payloadResult{Index: 1, Verified: true, Log: "legacy"}); got[1] != want {
		t.Errorf("payload 1 = %+v, want %+v", got[1], want)
	}
}

func TestVerifyPayloadsCancelled(t *testing.T) {
	tessera, legacy := testLogs(t, false)
	targets := []logTarget{tessera.target("tessera"), legacy.target("legacy")}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, err := collect(t, ctx, targets, [][]byte{normalizePayload(testPayload("missing"))})
	if err == nil {
		t.Errorf("verifyPayloads with cancelled context returned nil error")
	}
	if len(got) != 0 {
		t.Errorf("verifyPayloads with cancelled context emitted %v, want nothing", got)
	}
}

func TestReadPayloads(t *testing.T) {
	for _, tc := range []struct {
		desc    string
		input   string
		want    [][]byte
		wantErr bool
	}{
		{desc: "empty", input: ""},
		{
			desc:  "normalized, blank lines and unknown fields ignored",
			input: "{\"payload\": \"a\\nb\"}\n\n{\"payload\": \"  c\\n\\n\", \"label\": \"x\"}\n",
			want:  [][]byte{[]byte("a\nb\n"), []byte("c\n")},
		},
		{desc: "missing payload", input: "{\"payload\": \"a\"}\n{\"label\": \"x\"}\n", wantErr: true},
		{desc: "malformed", input: "{\"payload\": \"a\"}\nnot json\n", wantErr: true},
		{desc: "wrong type", input: "{\"payload\": 1}\n", wantErr: true},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := readPayloads(strings.NewReader(tc.input))
			if (err != nil) != tc.wantErr {
				t.Fatalf("readPayloads error = %v, wantErr %v", err, tc.wantErr)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("readPayloads mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestRunBatch(t *testing.T) {
	tessera, legacy := testLogs(t, false)
	targets := []logTarget{tessera.target("tessera"), legacy.target("legacy")}

	dir := t.TempDir()
	path := filepath.Join(dir, "payloads.jsonl")
	var in bytes.Buffer
	enc := json.NewEncoder(&in)
	for _, name := range []string{"missing", "old", "new"} {
		enc.Encode(map[string]string{"payload": string(testPayload(name))})
	}
	if err := os.WriteFile(path, in.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if code := runBatch(context.Background(), targets, path, &out); code != 0 {
		t.Fatalf("runBatch exit code = %d, want 0", code)
	}
	got := make(map[int]payloadResult)
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var r payloadResult
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("output line %q: %v", line, err)
		}
		got[r.Index] = r
	}
	want := map[int]payloadResult{
		0: {Index: 0},
		1: {Index: 1, Verified: true, Log: "legacy"},
		2: {Index: 2, Verified: true, Log: "tessera"},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("runBatch results mismatch (-want +got):\n%s", diff)
	}
	// Optional fields are omitted when empty.
	if !strings.Contains(out.String(), `{"index":0,"verified":false}`) {
		t.Errorf("runBatch output %q lacks compact not-found result", out.String())
	}

	malformed := filepath.Join(dir, "malformed.jsonl")
	os.WriteFile(malformed, []byte("nope\n"), 0o600)
	for _, p := range []string{malformed, filepath.Join(dir, "absent.jsonl")} {
		out.Reset()
		if code := runBatch(context.Background(), targets, p, &out); code != 1 || out.Len() != 0 {
			t.Errorf("runBatch(%s) = %d with output %q, want 1 and no output", filepath.Base(p), code, out.String())
		}
	}
}

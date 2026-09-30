// Binary `verifier` checks the inclusion of a particular Pixel Factory Image,
// identified by its build_fingerprint and vbmeta_digest (the payload), in the
// Transparency Log.
//
// Inputs to the tool are:
//   - the log leaf index of the image of interest, from the Pixel Binary
//     Transparency Log, see:
//     https://developers.google.com/android/binary_transparency/image_info.txt
//   - the path to a file containing the payload, see this page for instructions
//     https://developers.google.com/android/binary_transparency/pixel_verification#construct-the-payload-for-verification.
//   - the log's base URL, if different from the default provided.
//
// Outputs:
//   - "OK" if the image is included in the log,
//   - "FAILURE" if it isn't.
//
// Usage: See README.md.
// For more details on inclusion proofs, see:
// https://developers.google.com/android/binary_transparency/pixel_verification#verifying-image-inclusion-inclusion-proof
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"os"
	"os/signal"
	"slices"
	"syscall"

	"github.com/android/android-binary-transparency/verifier_tools/verify/internal/checkpoint"
	"github.com/android/android-binary-transparency/verifier_tools/verify/internal/tiles"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"

	_ "embed"
)

// Domain separation prefix for Merkle tree hashing with second preimage
// resistance similar to that used in RFC 6962.
const (
	LeafHashPrefix                   = 0
	KeyNameForVerifierPixel          = "pixel_transparency_log"
	KeyNameForVerifierG1PJWT         = "developers.google.com/android/binary_transparency/google1p/0"
	KeyNameForVerifierG1PJWT202601   = "gstatic.com/android/binary_transparency/google1p/jwt/0"
	KeyNameForVerifierG1PAPK         = "gstatic.com/android/binary_transparency/google1p/apk/2026/0"
	KeyNameForVerifierMainlineModule = "gstatic.com/android/binary_transparency/mainline/modules/2026/0"
	LogBaseURLPixel                  = "https://developers.google.com/android/binary_transparency"
	LogBaseURLG1PJWT                 = "https://developers.google.com/android/binary_transparency/google1p"
	LogBaseURLG1PJWT202601           = "https://www.gstatic.com/android/binary_transparency/google1p/jwt/2026/01"
	LogBaseURLG1PAPK202601           = "https://www.gstatic.com/android/binary_transparency/google1p/apk/2026/01"
	LogBaseURLG1PAPK202602           = "https://www.gstatic.com/android/binary_transparency/google1p/apk/2026/02"
	NoteVerifierG1PAPK202602         = "android.transparency.goog/google1p/apk/2026/1+fc654374+ATr9NQE0gvOtVfj5cCStUzdlflEp3oZoNHD8pImzPj5O"
	LogBaseURLMainlineModule202601   = "https://www.gstatic.com/android/binary_transparency/mainline/2026/01"
	LogBaseURLMainlineModule202602   = "https://www.gstatic.com/android/binary_transparency/mainline/2026/02"
	NoteVerifierMainlineModule202602 = "android.transparency.goog/mainline/modules/2026/1+1a8e4064+AfwnHm59rNQTJICchMd7a2W5PQa7nC5h2gTEfq3fhCEI"
	ImageInfoFilename                = "image_info.txt"
	PackageInfoFilename              = "package_info.txt"
	PackageInfo2Filename             = "package_info2.txt"
	ModuleInfoFilename               = "module_info.txt"
)

// See https://developers.google.com/android/binary_transparency/pixel_tech_details#log_implementation.
//
//go:embed log_pub_key.pixel.pem
var pixelLogPubKey []byte

// See https://developers.google.com/android/binary_transparency/google1p/log_details#log_implementation.
//
//go:embed log_pub_key.google_system_apk.pem
var googleSystemAppLogPubKey []byte

// See https://developers.google.com/android/binary_transparency/google_apk/log_details#log_implementation.
//
//go:embed log_pub_key.google_apk.pem
var googleAPKLogPubKey []byte

// See https://developers.google.com/android/binary_transparency/mainline_modules/log_details#log_implementation.
//
//go:embed log_pub_key.mainline_module.pem
var mainlineModuleLogPubKey []byte

var (
	payloadPath  = flag.String("payload_path", "", "Path to the payload describing the binary of interest.")
	payloadsPath = flag.String("payloads_path", "", "Path to a JSON Lines file of payloads to verify in one run, one {\"payload\": \"...\"} object per line. Writes one JSON result per payload to stdout.")
	logType      = flag.String("log_type", "", "Which log: 'pixel' or 'google_1p_code' or 'google_1p_apk' or 'mainline_module'.")
	fetchEntries = flag.Bool("fetch_entries", false, "Pre-fetch and cache all entries/tiles locally for the specified --log_type, without performing an inclusion proof.")
	concurrency  = flag.Int("concurrency", tiles.DefaultTesseraFetchConcurrency, "Number of concurrent workers for fetching Tessera entry tiles.")
	cacheDir     = flag.String("cache_dir", "", "Custom root directory for local cache. If unspecified, defaults to system cache directory.")
)

func init() {
	flag.StringVar(logType, "log-type", "", "Alias for --log_type.")
	flag.StringVar(payloadPath, "payload-path", "", "Alias for --payload_path.")
	flag.StringVar(payloadsPath, "payloads-path", "", "Alias for --payloads_path.")
	flag.StringVar(cacheDir, "cache-dir", "", "Alias for --cache_dir.")
	flag.BoolVar(fetchEntries, "fetch-entries", false, "Alias for --fetch_entries.")

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), `Usage of %s:

Modes:
  1. Verify binary inclusion in transparency log:
     %s --log_type=<log_type> --payload_path=<path_to_payload> [--cache_dir=<path>]

  2. Verify many binaries in one run (JSON Lines in, JSON Lines out):
     %s --log_type=<log_type> --payloads_path=<path_to_payloads.jsonl> [--cache_dir=<path>]

  3. Pre-fetch and cache entries locally for offline verification:
     %s --log_type=<log_type> --fetch_entries [--concurrency=16] [--cache_dir=<path>]

Supported log types:
  pixel, google_1p_code, google_1p_apk, mainline_module

Flags:
`, os.Args[0], os.Args[0], os.Args[0], os.Args[0])
		flag.PrintDefaults()
	}
}

type logTarget struct {
	name                string
	baseURL             string
	checkpointPath      string
	verifier            note.Verifier
	tileHeight          int
	isTessera           bool
	binaryInfoFilenames []string
}

func resolveTargets(logType string) ([]logTarget, error) {
	var targets []logTarget
	switch logType {
	case "":
		return nil, fmt.Errorf("must specify which log to target using '--log_type' flag: {pixel, google_1p_code, google_1p_apk, mainline_module}")
	case "pixel":
		v, err := checkpoint.NewVerifier(pixelLogPubKey, KeyNameForVerifierPixel)
		if err != nil {
			return nil, fmt.Errorf("error creating verifier for pixel log: %w", err)
		}
		targets = append(targets, logTarget{
			name:                "pixel",
			baseURL:             LogBaseURLPixel,
			checkpointPath:      "checkpoint.txt",
			verifier:            v,
			tileHeight:          1,
			isTessera:           false,
			binaryInfoFilenames: []string{ImageInfoFilename},
		})
	case "google_1p_code":
		// Shard 2026/01: Latest sharded log
		v202601, err := checkpoint.NewVerifier(googleSystemAppLogPubKey, KeyNameForVerifierG1PJWT202601)
		if err != nil {
			return nil, fmt.Errorf("error creating verifier for 2026/01 google_1p_code log: %w", err)
		}
		targets = append(targets, logTarget{
			name:                "google_1p_code (2026/01)",
			baseURL:             LogBaseURLG1PJWT202601,
			checkpointPath:      "checkpoint.txt",
			verifier:            v202601,
			tileHeight:          8,
			isTessera:           false,
			binaryInfoFilenames: []string{PackageInfoFilename},
		})

		// Legacy log continuation fallback
		vLegacy, err := checkpoint.NewVerifier(googleSystemAppLogPubKey, KeyNameForVerifierG1PJWT)
		if err != nil {
			return nil, fmt.Errorf("error creating verifier for legacy google_1p_code log: %w", err)
		}
		targets = append(targets, logTarget{
			name:                "google_1p_code (legacy)",
			baseURL:             LogBaseURLG1PJWT,
			checkpointPath:      "checkpoint.txt",
			verifier:            vLegacy,
			tileHeight:          1,
			isTessera:           false,
			binaryInfoFilenames: []string{PackageInfoFilename},
		})
	case "google_1p_apk":
		// Shard 2026/02: Tessera log
		v2, err := note.NewVerifier(NoteVerifierG1PAPK202602)
		if err != nil {
			return nil, fmt.Errorf("error creating verifier for 2026/02 Tessera log: %w", err)
		}
		targets = append(targets, logTarget{
			name:           "google_1p_apk (2026/02 Tessera)",
			baseURL:        LogBaseURLG1PAPK202602,
			checkpointPath: "checkpoint",
			verifier:       v2,
			tileHeight:     8,
			isTessera:      true,
		})

		// Shard 2026/01: Legacy log continuation fallback
		v1, err := checkpoint.NewVerifier(googleAPKLogPubKey, KeyNameForVerifierG1PAPK)
		if err != nil {
			return nil, fmt.Errorf("error creating verifier for 2026/01 log: %w", err)
		}
		targets = append(targets, logTarget{
			name:                "google_1p_apk (2026/01)",
			baseURL:             LogBaseURLG1PAPK202601,
			checkpointPath:      "checkpoint.txt",
			verifier:            v1,
			tileHeight:          8,
			isTessera:           false,
			binaryInfoFilenames: []string{PackageInfo2Filename, PackageInfoFilename},
		})
	case "mainline_module":
		// Shard 2026/02: Tessera log
		v2, err := note.NewVerifier(NoteVerifierMainlineModule202602)
		if err != nil {
			return nil, fmt.Errorf("error creating verifier for 2026/02 Tessera log: %w", err)
		}
		targets = append(targets, logTarget{
			name:           "mainline_module (2026/02 Tessera)",
			baseURL:        LogBaseURLMainlineModule202602,
			checkpointPath: "checkpoint",
			verifier:       v2,
			tileHeight:     8,
			isTessera:      true,
		})

		// Shard 2026/01: Legacy log continuation fallback
		v1, err := checkpoint.NewVerifier(mainlineModuleLogPubKey, KeyNameForVerifierMainlineModule)
		if err != nil {
			return nil, fmt.Errorf("error creating verifier for 2026/01 log: %w", err)
		}
		targets = append(targets, logTarget{
			name:                "mainline_module (2026/01)",
			baseURL:             LogBaseURLMainlineModule202601,
			checkpointPath:      "checkpoint.txt",
			verifier:            v1,
			tileHeight:          8,
			isTessera:           false,
			binaryInfoFilenames: []string{ModuleInfoFilename},
		})
	default:
		return nil, fmt.Errorf("unsupported log type %q", logType)
	}
	return targets, nil
}

func runFetchEntries(ctx context.Context, targets []logTarget, concurrency int) error {
	for _, target := range targets {
		slog.Info("Syncing entries for log", "log", target.name, "url", target.baseURL)
		root, err := checkpoint.FromURLWithPathContext(ctx, target.baseURL, target.checkpointPath, target.verifier)
		if err != nil {
			return fmt.Errorf("failed to read checkpoint for %s: %w", target.name, err)
		}

		treeSize := int64(root.Size)
		slog.Info("Resolved checkpoint tree size", "log", target.name, "treeSize", treeSize)

		if target.isTessera {
			slog.Info("Fetching Tessera entry tiles", "log", target.name, "treeSize", treeSize, "concurrency", concurrency)
			if err := tiles.FetchAllTesseraEntries(ctx, target.baseURL, treeSize, concurrency); err != nil {
				return fmt.Errorf("failed fetching Tessera entry tiles for %s: %w", target.name, err)
			}
		} else {
			slog.Info("Fetching legacy info files", "log", target.name, "files", target.binaryInfoFilenames, "treeSize", treeSize)
			if err := tiles.FetchAllLegacyEntries(ctx, target.baseURL, target.binaryInfoFilenames, treeSize); err != nil {
				return fmt.Errorf("failed fetching legacy entries for %s: %w", target.name, err)
			}
		}
	}
	return nil
}

func main() {
	flag.Parse()

	if *cacheDir != "" {
		tiles.SetCacheDir(*cacheDir)
		slog.Info("Using custom cache directory", "path", *cacheDir)
	}

	targets, err := resolveTargets(*logType)
	if err != nil {
		slog.Error(err.Error())
		flag.Usage()
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if *fetchEntries {
		if err := runFetchEntries(ctx, targets, *concurrency); err != nil {
			slog.Error("FAILURE: error fetching entries", "error", err)
			os.Exit(1)
		}
		activeCacheDir, _ := tiles.CacheDir()
		slog.Info("SUCCESS: all entries fetched and cached locally.", "cache_dir", activeCacheDir)
		return
	}

	if *payloadsPath != "" {
		if *payloadPath != "" {
			slog.Error("specify only one of '--payload_path' and '--payloads_path'")
			flag.Usage()
			os.Exit(1)
		}
		os.Exit(runBatch(ctx, targets, *payloadsPath, os.Stdout))
	}

	if *payloadPath == "" {
		slog.Error("must specify '--payload_path' or '--payloads_path' to verify binaries, or '--fetch_entries' to pre-fetch log entries")
		flag.Usage()
		os.Exit(1)
	}
	b, err := os.ReadFile(*payloadPath)
	if err != nil {
		slog.Error("Unable to open file", "path", *payloadPath, "error", err)
		os.Exit(1)
	}
	payloadBytes := normalizePayload(b)
	if string(b) != string(payloadBytes) {
		slog.Info("Reformatted payload content", "from", b, "to", payloadBytes)
	}

	var result payloadResult
	if err := verifyPayloads(ctx, targets, [][]byte{payloadBytes}, func(r payloadResult) { result = r }); err != nil {
		slog.Error("FAILURE: verification interrupted", "error", err)
		os.Exit(1)
	}
	switch {
	case result.Verified:
		slog.Info("OK. inclusion check success!", "log", result.Log)
	case result.Error != "":
		slog.Error("FAILURE: " + result.Error)
		os.Exit(1)
	default:
		slog.Error("FAILURE: payload not verified in any log")
		os.Exit(1)
	}
}

// normalizePayload trims excessive leading or trailing whitespace from a
// payload and terminates it with a single newline, as it appears in the logs.
func normalizePayload(b []byte) []byte {
	p := append([]byte(nil), bytes.TrimSpace(b)...)
	return append(p, '\n')
}

// payloadResult is the outcome for one payload; in --payloads_path mode it is
// written to stdout as one JSON line.
type payloadResult struct {
	// Index is the payload's 0-based record number in the input.
	Index int `json:"index"`
	// Verified is true if the payload's inclusion proof succeeded.
	Verified bool `json:"verified"`
	// Log names the log the payload was verified in, if Verified.
	Log string `json:"log,omitempty"`
	// Error is set if the payload was found in a log but could not be proven
	// included. A payload that is simply not in any log has no error.
	Error string `json:"error,omitempty"`
}

// readPayloads reads a JSON Lines file of {"payload": "..."} objects. Blank
// lines are ignored, as are unknown fields.
func readPayloads(r io.Reader) ([][]byte, error) {
	var payloads [][]byte
	dec := json.NewDecoder(r)
	for {
		var rec struct {
			Payload *string `json:"payload"`
		}
		if err := dec.Decode(&rec); err == io.EOF {
			return payloads, nil
		} else if err != nil {
			return nil, fmt.Errorf("record %d: %w", len(payloads), err)
		}
		if rec.Payload == nil {
			return nil, fmt.Errorf("record %d: missing \"payload\"", len(payloads))
		}
		payloads = append(payloads, normalizePayload([]byte(*rec.Payload)))
	}
}

// runBatch verifies every payload in the JSON Lines file at path and writes
// one payloadResult per payload to out. Results are written as soon as they
// are known, so they are not necessarily in input order.
//
// Returns the process exit code: 0 once every result has been written,
// whether or not the payloads were verified; 1 if the input cannot be read,
// the results cannot be written, or ctx is cancelled first (in which case
// some payloads have no result).
func runBatch(ctx context.Context, targets []logTarget, path string, out io.Writer) int {
	f, err := os.Open(path)
	if err != nil {
		slog.Error("Unable to open file", "path", path, "error", err)
		return 1
	}
	payloads, err := readPayloads(f)
	f.Close()
	if err != nil {
		slog.Error("Malformed payloads file", "path", path, "error", err)
		return 1
	}

	enc := json.NewEncoder(out)
	var writeErr error
	verified := 0
	err = verifyPayloads(ctx, targets, payloads, func(r payloadResult) {
		if r.Verified {
			verified++
		}
		if writeErr == nil {
			writeErr = enc.Encode(r)
		}
	})
	if err != nil {
		slog.Error("FAILURE: verification interrupted", "error", err)
		return 1
	}
	if writeErr != nil {
		slog.Error("FAILURE: unable to write results", "error", writeErr)
		return 1
	}
	slog.Info("Verified payloads", "total", len(payloads), "verified", verified)
	return 0
}

// verifyPayloads checks each (normalized) payload against targets, in order,
// and calls emit exactly once per payload.
//
// A payload's outcome is the same as verifying it alone: the first log that
// contains it decides, and a failed proof there is final. But each checkpoint
// is fetched, and each log searched, once for all payloads.
//
// If ctx is cancelled, verifyPayloads returns ctx.Err() without calling emit
// for payloads it has not finished, rather than reporting them as not found.
func verifyPayloads(ctx context.Context, targets []logTarget, payloads [][]byte, emit func(payloadResult)) error {
	pending := make(map[int]bool, len(payloads))
	for i := range payloads {
		pending[i] = true
	}

	for _, target := range targets {
		if len(pending) == 0 {
			break
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		slog.Info("Checking log", "log", target.name, "url", target.baseURL, "payloads", len(pending))
		root, err := checkpoint.FromURLWithPathContext(ctx, target.baseURL, target.checkpointPath, target.verifier)
		if err != nil {
			slog.Warn("Failed to read checkpoint", "log", target.name, "error", err)
			continue
		}

		logSize := int64(root.Size)
		found := findPayloads(target, logSize, payloads, slices.Sorted(maps.Keys(pending)))
		if missing := len(pending) - len(found); missing > 0 {
			slog.Info("Payload not found in log", "log", target.name, "count", missing)
		}

		var th tlog.Hash
		copy(th[:], root.Hash)
		r := tiles.HashReader{
			URL:        target.baseURL,
			TileHeight: target.tileHeight,
			TreeSize:   logSize,
			IsTessera:  target.isTessera,
			TileCache:  make(map[string][]byte),
		}
		for _, i := range slices.Sorted(maps.Keys(found)) {
			if err := ctx.Err(); err != nil {
				return err
			}
			delete(pending, i)
			emit(proveInclusion(target, r, logSize, th, i, payloads[i], found[i]))
		}
	}

	// A cancelled checkpoint fetch above is only logged, so check again before
	// declaring the remaining payloads not found.
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, i := range slices.Sorted(maps.Keys(pending)) {
		emit(payloadResult{Index: i})
	}
	return nil
}

// findPayloads returns the leaf index in target of each payloads[i], for i in
// indices, that the log contains.
func findPayloads(target logTarget, logSize int64, payloads [][]byte, indices []int) map[int]int64 {
	found := make(map[int]int64)
	if target.isTessera {
		wanted := make([][]byte, 0, len(indices))
		for _, i := range indices {
			wanted = append(wanted, payloads[i])
		}
		m, err := tiles.TesseraFindPayloadIndices(target.baseURL, logSize, wanted)
		if err != nil {
			// m still holds the exact matches found before the error; the
			// other payloads move on to the next log, as in a single-payload
			// run that hits the same error.
			slog.Warn("Failed to search Tessera entry tiles", "log", target.name, "found", len(m), "error", err)
		}
		for _, i := range indices {
			if idx, ok := m[string(bytes.TrimSpace(payloads[i]))]; ok {
				found[i] = idx
			}
		}
		return found
	}

	// Load each info file only if some payloads are still not found, like a
	// single-payload run does.
	remaining := indices
	for _, filename := range target.binaryInfoFilenames {
		if len(remaining) == 0 {
			break
		}
		m, err := tiles.BinaryInfosIndex(target.baseURL, filename, logSize)
		if err != nil {
			slog.Warn("Failed to load binary info map", "log", target.name, "file", filename, "error", err)
			continue
		}
		var next []int
		for _, i := range remaining {
			if idx, ok := m[string(payloads[i])]; ok {
				found[i] = idx
			} else {
				next = append(next, i)
			}
		}
		remaining = next
	}
	return found
}

// proveInclusion proves that payload is the leaf at leafIndex in target's tree
// of size logSize and root hash rootHash.
func proveInclusion(target logTarget, r tiles.HashReader, logSize int64, rootHash tlog.Hash, index int, payload []byte, leafIndex int64) payloadResult {
	result := payloadResult{Index: index}
	slog.Debug("tlog.ProveRecord", "log", target.name, "logSize", logSize, "binaryInfoIndex", leafIndex)
	rp, err := tlog.ProveRecord(logSize, leafIndex, r)
	if err != nil {
		result.Error = fmt.Sprintf("error in tlog.ProveRecord for log %s: %v", target.name, err)
		return result
	}
	leafHash, err := tiles.PayloadHash(payload)
	if err != nil {
		result.Error = fmt.Sprintf("error hashing payload: %v", err)
		return result
	}
	if err := tlog.CheckRecord(rp, logSize, rootHash, leafIndex, leafHash); err != nil {
		result.Error = fmt.Sprintf("inclusion check error in tlog.CheckRecord for log %s: %v", target.name, err)
		return result
	}
	result.Verified = true
	result.Log = target.name
	return result
}

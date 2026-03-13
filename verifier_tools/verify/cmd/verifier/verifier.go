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
	"flag"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/android/android-binary-transparency/verifier_tools/verify/internal/checkpoint"
	"github.com/android/android-binary-transparency/verifier_tools/verify/internal/tiles"
	"golang.org/x/mod/sumdb/tlog"

	_ "embed"
)

// Domain separation prefix for Merkle tree hashing with second preimage
// resistance similar to that used in RFC 6962.
const (
	LeafHashPrefix           = 0
	KeyNameForVerifierPixel  = "pixel_transparency_log"
	KeyNameForVerifierG1PJWT = "developers.google.com/android/binary_transparency/google1p/0"
	KeyNameForVerifierG1PAPK = "gstatic.com/android/binary_transparency/google1p/apk/2026/0"
	LogBaseURLPixel          = "https://developers.google.com/android/binary_transparency"
	LogBaseURLG1PJWT         = "https://developers.google.com/android/binary_transparency/google1p"
	LogBaseURLG1PAPK         = "https://www.gstatic.com/android/binary_transparency/google1p/apk/2026/01/"
	ImageInfoFilename        = "image_info.txt"
	PackageInfoFilename      = "package_info.txt"
)

// See https://developers.google.com/android/binary_transparency/pixel_tech_details#log_implementation.
//
//go:embed log_pub_key.pixel.pem
var pixelLogPubKey []byte

// See https://developers.google.com/android/binary_transparency/google1p/log_details#log_implementation.
//
//go:embed log_pub_key.google_system_apk.pem
var googleSystemAppLogPubKey []byte

//go:embed log_pub_key.google_apk.pem
var googleAPKLogPubKey []byte

var (
	payloadPath = flag.String("payload_path", "", "Path to the payload describing the binary of interest.")
	logType     = flag.String("log_type", "", "Which log: 'pixel' or 'google_1p_code' or 'google_1p_apk'.")
)

func main() {
	flag.Parse()

	if *payloadPath == "" {
		slog.Error("must specify the payload_path for the binary payload")
		os.Exit(1)
	}
	b, err := os.ReadFile(*payloadPath)
	if err != nil {
		slog.Error("unable to open file", "path", *payloadPath, "error", err)
		os.Exit(1)
	}
	// Payload should not contain excessive leading or trailing whitespace.
	payloadBytes := bytes.TrimSpace(b)
	payloadBytes = append(payloadBytes, '\n')
	if string(b) != string(payloadBytes) {
		slog.Info("Reformatted payload content", "from", b, "to", payloadBytes)
	}

	var logPubKey []byte
	var logBaseURL string
	var keyNameForVerifier string
	var binaryInfoFilename string
	var tileHeight int
	switch *logType {
	case "":
		slog.Error("must specify which log to verify against: 'pixel' or 'google_1p_code' or 'google_1p_apk'")
		os.Exit(1)
	case "pixel":
		logPubKey = pixelLogPubKey
		logBaseURL = LogBaseURLPixel
		keyNameForVerifier = KeyNameForVerifierPixel
		binaryInfoFilename = ImageInfoFilename
		tileHeight = 1
	case "google_1p_code":
		logPubKey = googleSystemAppLogPubKey
		logBaseURL = LogBaseURLG1PJWT
		keyNameForVerifier = KeyNameForVerifierG1PJWT
		binaryInfoFilename = PackageInfoFilename
		tileHeight = 1
	case "google_1p_apk":
		logPubKey = googleAPKLogPubKey
		logBaseURL = LogBaseURLG1PAPK
		keyNameForVerifier = KeyNameForVerifierG1PAPK
		binaryInfoFilename = PackageInfoFilename
		tileHeight = 8
	default:
		slog.Error("unsupported log type")
		os.Exit(1)
	}

	v, err := checkpoint.NewVerifier(logPubKey, keyNameForVerifier)
	if err != nil {
		slog.Error("error creating verifier", "error", err)
		os.Exit(1)
	}
	root, err := checkpoint.FromURL(logBaseURL, v)
	if err != nil {
		slog.Error("error reading checkpoint", "log", logBaseURL, "error", err)
		os.Exit(1)
	}

	m, err := tiles.BinaryInfosIndex(logBaseURL, binaryInfoFilename)
	if err != nil {
		slog.Error("failed to load binary info map to find log index", "error", err)
		os.Exit(1)
	}
	binaryInfoIndex, ok := m[string(payloadBytes)]
	if !ok {
		slog.Error("failed to find payload", "payload", string(payloadBytes), "file", filepath.Join(logBaseURL, binaryInfoFilename))
		os.Exit(1)
	}

	var th tlog.Hash
	copy(th[:], root.Hash)

	logSize := int64(root.Size)
	r := tiles.HashReader{URL: logBaseURL, TileHeight: tileHeight, TreeSize: logSize}
	slog.Debug("tlog.ProveRecord", "logSize", logSize, "binaryInfoIndex", binaryInfoIndex)
	rp, err := tlog.ProveRecord(logSize, binaryInfoIndex, r)
	if err != nil {
		slog.Error("error in tlog.ProveRecord", "error", err)
		os.Exit(1)
	}

	leafHash, err := tiles.PayloadHash(payloadBytes)
	if err != nil {
		slog.Error("error hashing payload", "error", err)
		os.Exit(1)
	}

	if err := tlog.CheckRecord(rp, logSize, th, binaryInfoIndex, leafHash); err != nil {
		slog.Error("FAILURE: inclusion check error in tlog.CheckRecord", "error", err)
		os.Exit(1)
	} else {
		slog.Info("OK. inclusion check success!")
	}
}

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
	"log"
	"os"
	"path/filepath"

	"android.googlesource.com/platform/external/avb.git/tools/transparency/verify/internal/checkpoint"
	"android.googlesource.com/platform/external/avb.git/tools/transparency/verify/internal/tiles"
	"golang.org/x/mod/sumdb/tlog"

	_ "embed"
)

// Domain separation prefix for Merkle tree hashing with second preimage
// resistance similar to that used in RFC 6962.
const (
	LeafHashPrefix          = 0
	KeyNameForVerifierPixel = "pixel_transparency_log"
	KeyNameForVerifierG1P   = "developers.google.com/android/binary_transparency/google1p/0"
	LogBaseURLPixel         = "https://developers.google.com/android/binary_transparency"
	LogBaseURLG1P           = "https://developers.google.com/android/binary_transparency/google1p"
	ImageInfoFilename       = "image_info.txt"
	PackageInfoFilename     = "package_info.txt"
)

// See https://developers.google.com/android/binary_transparency/pixel_tech_details#log_implementation.
//
//go:embed log_pub_key.pixel.pem
var pixelLogPubKey []byte

// See https://developers.google.com/android/binary_transparency/google1p/log_details#log_implementation.
//
//go:embed log_pub_key.google_system_apk.pem
var googleSystemAppLogPubKey []byte

var (
	payloadPath = flag.String("payload_path", "", "Path to the payload describing the binary of interest.")
	logType     = flag.String("log_type", "", "Which log: 'pixel' or 'google_system_apk'.")
)

func main() {
	flag.Parse()

	if *payloadPath == "" {
		log.Fatal("must specify the payload_path for the image payload")
	}
	b, err := os.ReadFile(*payloadPath)
	if err != nil {
		log.Fatalf("unable to open file %q: %v", *payloadPath, err)
	}
	// Payload should not contain excessive leading or trailing whitespace.
	payloadBytes := bytes.TrimSpace(b)
	payloadBytes = append(payloadBytes, '\n')
	if string(b) != string(payloadBytes) {
		log.Printf("Reformatted payload content from %q to %q", b, payloadBytes)
	}

	var logPubKey []byte
	var logBaseURL string
	var keyNameForVerifier string
	var binaryInfoFilename string
	if *logType == "" {
		log.Fatal("must specify which log to verify against: 'pixel' or 'google_system_apk'")
	} else if *logType == "pixel" {
		logPubKey = pixelLogPubKey
		logBaseURL = LogBaseURLPixel
		keyNameForVerifier = KeyNameForVerifierPixel
		binaryInfoFilename = ImageInfoFilename
	} else if *logType == "google_system_apk" {
		logPubKey = googleSystemAppLogPubKey
		logBaseURL = LogBaseURLG1P
		keyNameForVerifier = KeyNameForVerifierG1P
		binaryInfoFilename = PackageInfoFilename
	} else {
		log.Fatal("unsupported log type")
	}

	v, err := checkpoint.NewVerifier(logPubKey, keyNameForVerifier)
	if err != nil {
		log.Fatalf("error creating verifier: %v", err)
	}
	root, err := checkpoint.FromURL(logBaseURL, v)
	if err != nil {
		log.Fatalf("error reading checkpoint for log(%s): %v", logBaseURL, err)
	}

	m, err := tiles.BinaryInfosIndex(logBaseURL, binaryInfoFilename)
	if err != nil {
		log.Fatalf("failed to load binary info map to find log index: %v", err)
	}
	binaryInfoIndex, ok := m[string(payloadBytes)]
	if !ok {
		log.Fatalf("failed to find payload %q in %s", string(payloadBytes), filepath.Join(logBaseURL, binaryInfoFilename))
	}

	var th tlog.Hash
	copy(th[:], root.Hash)

	logSize := int64(root.Size)
	r := tiles.HashReader{URL: logBaseURL}
	rp, err := tlog.ProveRecord(logSize, binaryInfoIndex, r)
	if err != nil {
		log.Fatalf("error in tlog.ProveRecord: %v", err)
	}

	leafHash, err := tiles.PayloadHash(payloadBytes)
	if err != nil {
		log.Fatalf("error hashing payload: %v", err)
	}

	if err := tlog.CheckRecord(rp, logSize, th, binaryInfoIndex, leafHash); err != nil {
		log.Fatalf("FAILURE: inclusion check error in tlog.CheckRecord: %v", err)
	} else {
		log.Print("OK. inclusion check success!")
	}
}

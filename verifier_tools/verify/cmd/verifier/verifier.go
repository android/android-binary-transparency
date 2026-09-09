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
	KeyNameForVerifierG1PAPK         = "gstatic.com/android/binary_transparency/google1p/apk/2026/0"
	KeyNameForVerifierMainlineModule = "gstatic.com/android/binary_transparency/mainline/modules/2026/0"
	LogBaseURLPixel                  = "https://developers.google.com/android/binary_transparency"
	LogBaseURLG1PJWT                 = "https://developers.google.com/android/binary_transparency/google1p"
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
	payloadPath = flag.String("payload_path", "", "Path to the payload describing the binary of interest.")
	logType     = flag.String("log_type", "", "Which log: 'pixel' or 'google_1p_code' or 'google_1p_apk' or 'mainline_module'.")
)

type logTarget struct {
	name                string
	baseURL             string
	checkpointPath      string
	verifier            note.Verifier
	tileHeight          int
	isTessera           bool
	binaryInfoFilenames []string
}

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

	var targets []logTarget
	switch *logType {
	case "":
		slog.Error("must specify which log to verify against using '--log_type' flag: {pixel, google_1p_code, google_1p_apk, mainline_module}")
		os.Exit(1)
	case "pixel":
		v, err := checkpoint.NewVerifier(pixelLogPubKey, KeyNameForVerifierPixel)
		if err != nil {
			slog.Error("error creating verifier", "log", "pixel", "error", err)
			os.Exit(1)
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
		v, err := checkpoint.NewVerifier(googleSystemAppLogPubKey, KeyNameForVerifierG1PJWT)
		if err != nil {
			slog.Error("error creating verifier", "log", "google_1p_code", "error", err)
			os.Exit(1)
		}
		targets = append(targets, logTarget{
			name:                "google_1p_code",
			baseURL:             LogBaseURLG1PJWT,
			checkpointPath:      "checkpoint.txt",
			verifier:            v,
			tileHeight:          1,
			isTessera:           false,
			binaryInfoFilenames: []string{PackageInfoFilename},
		})
	case "google_1p_apk":
		// Shard 2026/02: Tessera log
		v2, err := note.NewVerifier(NoteVerifierG1PAPK202602)
		if err != nil {
			slog.Error("error creating verifier for 2026/02 Tessera log", "error", err)
			os.Exit(1)
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
			slog.Error("error creating verifier for 2026/01 log", "error", err)
			os.Exit(1)
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
			slog.Error("error creating verifier for 2026/02 Tessera log", "error", err)
			os.Exit(1)
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
			slog.Error("error creating verifier for 2026/01 log", "error", err)
			os.Exit(1)
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
		slog.Error("unsupported log type")
		os.Exit(1)
	}

	var verified bool
	for _, target := range targets {
		slog.Info("Checking log", "log", target.name, "url", target.baseURL)
		root, err := checkpoint.FromURLWithPath(target.baseURL, target.checkpointPath, target.verifier)
		if err != nil {
			slog.Warn("Failed to read checkpoint", "log", target.name, "error", err)
			continue
		}

		logSize := int64(root.Size)
		var binaryInfoIndex int64
		var found bool

		if target.isTessera {
			idx, ok, err := tiles.TesseraFindPayloadIndex(target.baseURL, logSize, payloadBytes)
			if err != nil {
				slog.Warn("Failed to search Tessera entry tiles", "log", target.name, "error", err)
				continue
			}
			binaryInfoIndex = idx
			found = ok
		} else {
			for _, filename := range target.binaryInfoFilenames {
				m, err := tiles.BinaryInfosIndex(target.baseURL, filename, logSize)
				if err != nil {
					slog.Warn("Failed to load binary info map", "log", target.name, "file", filename, "error", err)
					continue
				}
				if idx, ok := m[string(payloadBytes)]; ok {
					binaryInfoIndex = idx
					found = true
					break
				}
			}
		}

		if !found {
			slog.Info("Payload not found in log", "log", target.name)
			continue
		}

		var th tlog.Hash
		copy(th[:], root.Hash)

		r := tiles.HashReader{
			URL:        target.baseURL,
			TileHeight: target.tileHeight,
			TreeSize:   logSize,
			IsTessera:  target.isTessera,
		}
		slog.Debug("tlog.ProveRecord", "log", target.name, "logSize", logSize, "binaryInfoIndex", binaryInfoIndex)
		rp, err := tlog.ProveRecord(logSize, binaryInfoIndex, r)
		if err != nil {
			slog.Error("error in tlog.ProveRecord", "log", target.name, "error", err)
			os.Exit(1)
		}

		leafHash, err := tiles.PayloadHash(payloadBytes)
		if err != nil {
			slog.Error("error hashing payload", "error", err)
			os.Exit(1)
		}

		if err := tlog.CheckRecord(rp, logSize, th, binaryInfoIndex, leafHash); err != nil {
			slog.Error("FAILURE: inclusion check error in tlog.CheckRecord", "log", target.name, "error", err)
			os.Exit(1)
		}

		slog.Info("OK. inclusion check success!", "log", target.name)
		verified = true
		break
	}

	if !verified {
		slog.Error("FAILURE: payload not verified in any log")
		os.Exit(1)
	}
}

package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/android/android-binary-transparency/verifier_tools/verify/internal/checkpoint"
)

func TestResolveTargetsGoogle1PCode(t *testing.T) {
	targets, err := resolveTargets("google_1p_code")
	if err != nil {
		t.Fatalf("resolveTargets(\"google_1p_code\") returned unexpected error: %v", err)
	}

	if len(targets) != 2 {
		t.Fatalf("got %d targets for google_1p_code, want 2", len(targets))
	}

	// Target 0: 2026/01 shard (primary, tileHeight 8)
	t0 := targets[0]
	if t0.name != "google_1p_code (2026/01)" {
		t.Errorf("targets[0].name = %q, want %q", t0.name, "google_1p_code (2026/01)")
	}
	if t0.baseURL != LogBaseURLG1PJWT202601 {
		t.Errorf("targets[0].baseURL = %q, want %q", t0.baseURL, LogBaseURLG1PJWT202601)
	}
	if t0.checkpointPath != "checkpoint.txt" {
		t.Errorf("targets[0].checkpointPath = %q, want %q", t0.checkpointPath, "checkpoint.txt")
	}
	if t0.verifier.Name() != KeyNameForVerifierG1PJWT202601 {
		t.Errorf("targets[0].verifier.Name() = %q, want %q", t0.verifier.Name(), KeyNameForVerifierG1PJWT202601)
	}
	if t0.tileHeight != 8 {
		t.Errorf("targets[0].tileHeight = %d, want 8", t0.tileHeight)
	}
	if t0.isTessera {
		t.Errorf("targets[0].isTessera = true, want false")
	}
	if len(t0.binaryInfoFilenames) != 1 || t0.binaryInfoFilenames[0] != PackageInfoFilename {
		t.Errorf("targets[0].binaryInfoFilenames = %v, want [%q]", t0.binaryInfoFilenames, PackageInfoFilename)
	}

	// Target 1: legacy developers.google.com shard (fallback, tileHeight 1)
	t1 := targets[1]
	if t1.name != "google_1p_code (legacy)" {
		t.Errorf("targets[1].name = %q, want %q", t1.name, "google_1p_code (legacy)")
	}
	if t1.baseURL != LogBaseURLG1PJWT {
		t.Errorf("targets[1].baseURL = %q, want %q", t1.baseURL, LogBaseURLG1PJWT)
	}
	if t1.checkpointPath != "checkpoint.txt" {
		t.Errorf("targets[1].checkpointPath = %q, want %q", t1.checkpointPath, "checkpoint.txt")
	}
	if t1.verifier.Name() != KeyNameForVerifierG1PJWT {
		t.Errorf("targets[1].verifier.Name() = %q, want %q", t1.verifier.Name(), KeyNameForVerifierG1PJWT)
	}
	if t1.tileHeight != 1 {
		t.Errorf("targets[1].tileHeight = %d, want 1", t1.tileHeight)
	}
	if t1.isTessera {
		t.Errorf("targets[1].isTessera = true, want false")
	}
	if len(t1.binaryInfoFilenames) != 1 || t1.binaryInfoFilenames[0] != PackageInfoFilename {
		t.Errorf("targets[1].binaryInfoFilenames = %v, want [%q]", t1.binaryInfoFilenames, PackageInfoFilename)
	}

	// Both targets use the same embedded public key so their 4-byte key hashes must match.
	if t0.verifier.KeyHash() != t1.verifier.KeyHash() {
		t.Errorf("expected identical key hash for both google_1p_code targets: got %x vs %x",
			t0.verifier.KeyHash(), t1.verifier.KeyHash())
	}
}

func TestGoogle1PCodeCheckpointSignatureVerification(t *testing.T) {
	// Real signed checkpoints from the 2026/01 shard and the legacy log.
	const signedCheckpoint202601 = "gstatic.com/android/binary_transparency/google1p/jwt/0\n" +
		"234\n" +
		"HpW7vHFFioFiMf0IglK1B3MLk80iaGOC6Ud6Etq038U=\n" +
		"\n" +
		"— gstatic.com/android/binary_transparency/google1p/jwt/0 qsuhszBFAiEAomG6In9+okg+Pj1Jw4JpWfignNeNXQweJxoYf9q59GMCIEyy/Ebu096WrCsT9L0Dv5D1EBHzqNQ26A1XcnNESPKX\n"

	const signedCheckpointLegacy = "developers.google.com/android/binary_transparency/google1p/0\n" +
		"134\n" +
		"WddUpZSJPJPm93SLwoCdKv+oJqPEqie52TZTIVNOhok=\n" +
		"\n" +
		"— developers.google.com/android/binary_transparency/google1p/0 qsuhszBEAiBA1NO/xnL4++iXFVwPhRsNU6AWDPEtOvDJQL3OuqCBOwIgbyMsA1l2yLvPUq8CoMNBf4E88l4XjlW4YanDLn5HRRI=\n"

	targets, err := resolveTargets("google_1p_code")
	if err != nil {
		t.Fatalf("resolveTargets(\"google_1p_code\") failed: %v", err)
	}

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/2026/01/checkpoint.txt":
			w.Write([]byte(signedCheckpoint202601))
		case "/legacy/checkpoint.txt":
			w.Write([]byte(signedCheckpointLegacy))
		default:
			http.NotFound(w, r)
		}
	}))
	defer s.Close()

	// Verify 2026/01 checkpoint with targets[0].verifier
	root202601, err := checkpoint.FromURLWithPath(s.URL+"/2026/01", "checkpoint.txt", targets[0].verifier)
	if err != nil {
		t.Fatalf("failed to verify 2026/01 checkpoint with targets[0].verifier: %v", err)
	}
	if root202601.Size != 234 {
		t.Errorf("root202601.Size = %d, want 234", root202601.Size)
	}

	// Verify legacy checkpoint with targets[1].verifier
	rootLegacy, err := checkpoint.FromURLWithPath(s.URL+"/legacy", "checkpoint.txt", targets[1].verifier)
	if err != nil {
		t.Fatalf("failed to verify legacy checkpoint with targets[1].verifier: %v", err)
	}
	if rootLegacy.Size != 134 {
		t.Errorf("rootLegacy.Size = %d, want 134", rootLegacy.Size)
	}

	// Cross-check: targets[0].verifier must reject legacy checkpoint and vice versa
	if _, err := checkpoint.FromURLWithPath(s.URL+"/legacy", "checkpoint.txt", targets[0].verifier); err == nil {
		t.Errorf("expected targets[0].verifier to reject legacy checkpoint, got nil")
	}
	if _, err := checkpoint.FromURLWithPath(s.URL+"/2026/01", "checkpoint.txt", targets[1].verifier); err == nil {
		t.Errorf("expected targets[1].verifier to reject 2026/01 checkpoint, got nil")
	}
}

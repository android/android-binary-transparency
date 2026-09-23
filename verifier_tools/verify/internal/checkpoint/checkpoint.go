// Package checkpoint implements methods to interact with checkpoints
// as described below.
//
// Root is the internal representation of the information needed to
// commit to the contents of the tree, and contains the root hash and size.
//
// When a commitment needs to be sent to other processes (such as a witness or
// other log clients), it is put in the form of a checkpoint, which also
// includes an "origin" string. The origin should is a unique identifier for
// the log identity which issues the checkpoint. This package deals only with
// the origin for the Pixel Binary Transparency Log.
//
// This checkpoint is signed in a note format (golang.org/x/mod/sumdb/note)
// before sending out. An unsigned checkpoint is not a valid commitment and
// must not be used.
//
// There is only a single signature.
// Support for multiple signing identities will be added as needed.
package checkpoint

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/android/android-binary-transparency/verifier_tools/verify/internal/httpclient"
	"golang.org/x/mod/sumdb/note"
)

const (
	// originIDPixel identifies a checkpoint for the Pixel Binary Transparency Log.
	originIDPixel = "developers.google.com/android/binary_transparency/0\n"
	// originIDG1P identifies a checkpoint for the Google System APK Transparency Log.
	originIDG1P = "developers.google.com/android/binary_transparency/google1p/0\n"
	// originIDG1PJWT202601 identifies a checkpoint for the Google System APK Transparency Log (2026/01 shard).
	originIDG1PJWT202601 = "gstatic.com/android/binary_transparency/google1p/jwt/0\n"
	// originIDG1PAPK identifies a checkpoint for the Google 1P APK Transparency Log.
	originIDG1PAPK = "gstatic.com/android/binary_transparency/google1p/apk/2026/0\n"
	// originIDG1PAPKTessera identifies a checkpoint for the Google 1P APK Transparency Log (Tessera shard).
	originIDG1PAPKTessera = "android.transparency.goog/google1p/apk/2026/1\n"
	// originIDMainlineModule identifies a checkpoint for the Android Mainline Module Transparency Log.
	originIDMainlineModule = "gstatic.com/android/binary_transparency/mainline/modules/2026/0\n"
	// originIDMainlineModuleTessera identifies a checkpoint for the Android Mainline Module Transparency Log (Tessera shard).
	originIDMainlineModuleTessera = "android.transparency.goog/mainline/modules/2026/1\n"
)

type verifier interface {
	Verify(msg []byte, sig []byte) bool
	Name() string
	KeyHash() uint32
}

// EcdsaVerifier verifies a message signature that was signed using ECDSA.
type EcdsaVerifier struct {
	PubKey *ecdsa.PublicKey
	name   string
	hash   uint32
}

// Verify returns whether the signature of the message is valid using its
// pubKey.
func (v EcdsaVerifier) Verify(msg, sig []byte) bool {
	h := sha256.Sum256(msg)
	if !ecdsa.VerifyASN1(v.PubKey, h[:], sig) {
		return false
	}
	return true
}

// KeyHash returns a 4 byte hash of the public key to be used as a hint to the
// verifier.
func (v EcdsaVerifier) KeyHash() uint32 {
	return v.hash
}

// Name returns the name of the key.
func (v EcdsaVerifier) Name() string {
	return v.name
}

// NewVerifier expects an ECDSA public key in PEM format in a file with the provided path and key name.
func NewVerifier(pemKey []byte, name string) (EcdsaVerifier, error) {
	b, _ := pem.Decode(pemKey)
	if b == nil || b.Type != "PUBLIC KEY" {
		return EcdsaVerifier{}, fmt.Errorf("Failed to decode public key, must contain an ECDSA public key in PEM format")
	}

	key := b.Bytes
	sum := sha256.Sum256(key)
	keyHash := binary.BigEndian.Uint32(sum[:])

	pub, err := x509.ParsePKIXPublicKey(key)
	if err != nil {
		return EcdsaVerifier{}, fmt.Errorf("Can't parse key: %v", err)
	}
	return EcdsaVerifier{
		PubKey: pub.(*ecdsa.PublicKey),
		hash:   keyHash,
		name:   name,
	}, nil
}

// Root contains the checkpoint data.
type Root struct {
	// Size is the number of entries in the log at this point.
	Size uint64
	// Hash commits to the contents of the entire log.
	Hash []byte
}

func parseCheckpoint(ckpt string) (Root, error) {
	var body string
	// Strip the origin ID and parse the rest of the checkpoint.
	switch {
	case strings.HasPrefix(ckpt, originIDPixel):
		body = ckpt[len(originIDPixel):]
	case strings.HasPrefix(ckpt, originIDG1P):
		body = ckpt[len(originIDG1P):]
	case strings.HasPrefix(ckpt, originIDG1PJWT202601):
		body = ckpt[len(originIDG1PJWT202601):]
	case strings.HasPrefix(ckpt, originIDG1PAPK):
		body = ckpt[len(originIDG1PAPK):]
	case strings.HasPrefix(ckpt, originIDG1PAPKTessera):
		body = ckpt[len(originIDG1PAPKTessera):]
	case strings.HasPrefix(ckpt, originIDMainlineModule):
		body = ckpt[len(originIDMainlineModule):]
	case strings.HasPrefix(ckpt, originIDMainlineModuleTessera):
		body = ckpt[len(originIDMainlineModuleTessera):]
	default:
		return Root{}, fmt.Errorf("invalid checkpoint - unknown origin, must be either %s, %s, %s, %s, %s, %s, or %s",
			strings.TrimSpace(originIDPixel),
			strings.TrimSpace(originIDG1P),
			strings.TrimSpace(originIDG1PJWT202601),
			strings.TrimSpace(originIDG1PAPK),
			strings.TrimSpace(originIDG1PAPKTessera),
			strings.TrimSpace(originIDMainlineModule),
			strings.TrimSpace(originIDMainlineModuleTessera))
	}

	if !strings.HasSuffix(ckpt, "\n") {
		return Root{}, fmt.Errorf("invalid checkpoint - bad format: must terminate with newline")
	}

	// body must contain at least 2 lines: size and root hash.
	lines := strings.Split(body, "\n")
	if len(lines) < 3 || lines[0] == "" || lines[1] == "" {
		return Root{}, fmt.Errorf("invalid checkpoint - bad format: must have origin id, size and root hash each followed by newline")
	}
	size, err := strconv.ParseUint(lines[0], 10, 64)
	if err != nil {
		return Root{}, fmt.Errorf("invalid checkpoint - cannot read size: %w", err)
	}
	rh, err := base64.StdEncoding.DecodeString(lines[1])
	if err != nil {
		return Root{}, fmt.Errorf("invalid checkpoint - invalid roothash: %w", err)
	}
	return Root{Size: size, Hash: rh}, nil
}

const (
	defaultHTTPTimeout = 30 * time.Second
)

var httpClient = httpclient.New(defaultHTTPTimeout)

func getSignedCheckpoint(logURL, checkpointPath string) ([]byte, error) {
	return getSignedCheckpointContext(context.Background(), logURL, checkpointPath)
}

func getSignedCheckpointContext(ctx context.Context, logURL, checkpointPath string) ([]byte, error) {
	// Sanity check the input url.
	u, err := url.Parse(logURL)
	if err != nil {
		return []byte{}, fmt.Errorf("invalid URL %s: %v", u, err)
	}

	u.Path = path.Join(u.Path, checkpointPath)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return []byte{}, fmt.Errorf("http.NewRequestWithContext(%s): %w", u, err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return []byte{}, fmt.Errorf("http.Get(%s): %w", u, err)
	}
	defer resp.Body.Close()
	if code := resp.StatusCode; code != 200 {
		return []byte{}, fmt.Errorf("http.Get(%s): %s", u, http.StatusText(code))
	}

	return io.ReadAll(resp.Body)
}

// FromURLWithPathContext verifies the signature and unpacks and returns a Root from the given checkpoint path using ctx.
func FromURLWithPathContext(ctx context.Context, logURL, checkpointPath string, v note.Verifier) (Root, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	b, err := getSignedCheckpointContext(ctx, logURL, checkpointPath)
	if err != nil {
		return Root{}, fmt.Errorf("failed to get signed checkpoint: %w", err)
	}

	n, err := note.Open(b, note.VerifierList(v))
	if err != nil {
		return Root{}, fmt.Errorf("failed to verify note signatures: %v", err)
	}
	return parseCheckpoint(n.Text)
}

// FromURLWithPath verifies the signature and unpacks and returns a Root from the given checkpoint path.
func FromURLWithPath(logURL, checkpointPath string, v note.Verifier) (Root, error) {
	return FromURLWithPathContext(context.Background(), logURL, checkpointPath, v)
}

// FromURL verifies the signature and unpacks and returns a Root.
//
// Validates signature before reading data, using a provided verifier.
// Data at `logURL` is the checkpoint and must be in the note format
// (golang.org/x/mod/sumdb/note).
//
// Returns error if the signature fails to verify or if the checkpoint
// does not conform to the following format:
//
//	[]byte("[origin]\n[size]\n[hash]").
func FromURL(logURL string, v note.Verifier) (Root, error) {
	return FromURLWithPath(logURL, "checkpoint.txt", v)
}

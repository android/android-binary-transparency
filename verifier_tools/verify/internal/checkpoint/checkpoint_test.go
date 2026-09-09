package checkpoint

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestInvalidCheckpointFormat(t *testing.T) {
	tests := []struct {
		desc string
		// m represents the checkpoint message text (n.Text). A valid signed checkpoint body
		// contains 3 newline-separated lines: <origin>\n<tree_size>\n<base64_root_hash>\n.
		m       string
		wantErr bool
	}{
		{
			desc:    "unknown origin",
			m:       "UNKNOWN\n1\nbananas\n",
			wantErr: true,
		},
		{
			desc:    "bad size",
			m:       "developers.google.com/android/binary_transparency/0\n-1\nbananas\n",
			wantErr: true,
		},
		{
			desc:    "not enough newlines",
			m:       "developers.google.com/android/binary_transparency/0\n1\n",
			wantErr: true,
		},
		{
			desc:    "non-numeric size",
			m:       "developers.google.com/android/binary_transparency/0\nbananas\ndGhlIHZpZXcgZnJvbSB0aGUgdHJlZSB0b3BzIGlzIGdyZWF0IQ==\n",
			wantErr: true,
		},
		{
			desc:    "too many newlines",
			m:       "developers.google.com/android/binary_transparency/0\n1\n\n\n\n",
			wantErr: true,
		},
		{
			desc:    "does not end with newline",
			m:       "developers.google.com/android/binary_transparency/0\n1\ngarbage",
			wantErr: true,
		},
		{
			desc:    "invalid - empty header",
			m:       "\n9944\ndGhlIHZpZXcgZnJvbSB0aGUgdHJlZSB0b3BzIGlzIGdyZWF0IQ==\n",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			if _, gotErr := parseCheckpoint(tt.m); gotErr == nil {
				t.Fatalf("fromText(%v): want error, got nil", tt.m)
			}
		})
	}
}

// testServer serves a test envelope `e` at path "test/file" and 404 otherwise.
// It is used to minimally test FromURL.
func testServer(t *testing.T, e string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.String() == "/test/file/checkpoint.txt" {
			w.Write([]byte(e))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

// TestGetSignedCheckpoint is a minimal test to check URL I/O.
// Content specific tests are done in the other tests.
func TestGetSignedCheckpoint(t *testing.T) {
	serverContent := "testContent"
	s := testServer(t, serverContent)
	u, err := url.Parse(s.URL)
	if err != nil {
		t.Fatalf("invalid URL for testServer %s: %v", s.URL, err)
	}
	defer s.Close()

	for _, tt := range []struct {
		desc    string
		path    string
		want    string
		wantErr bool
	}{
		{
			desc:    "good_file",
			path:    "test/file",
			want:    serverContent,
			wantErr: false,
		},
		{
			desc:    "bad_path",
			path:    "bad/path",
			wantErr: true,
		},
	} {
		t.Run(tt.desc, func(t *testing.T) {
			u.Path = path.Join(u.Path, tt.path)
			b, gotErr := getSignedCheckpoint(u.String(), "checkpoint.txt")
			got := string(b)
			if diff := cmp.Diff(got, tt.want); diff != "" {
				t.Errorf("bad response body: got %v, want %v", got, tt.want)
			}
			if gotErr != nil && !tt.wantErr {
				t.Errorf("unexpected error: got %t, want %t", gotErr, tt.wantErr)
			}
		})
	}
}

func TestValidCheckpointFormat(t *testing.T) {
	tests := []struct {
		desc string
		// m represents the checkpoint message text (n.Text). A valid signed checkpoint body
		// contains 3 newline-separated lines: <origin>\n<tree_size>\n<base64_root_hash>\n.
		m        string
		wantSize uint64
	}{
		{
			desc:     "pixel origin",
			m:        "developers.google.com/android/binary_transparency/0\n10\ndGhlIHZpZXcgZnJvbSB0aGUgdHJlZSB0b3BzIGlzIGdyZWF0IQ==\n",
			wantSize: 10,
		},
		{
			desc:     "google 1p apk origin",
			m:        "gstatic.com/android/binary_transparency/google1p/apk/2026/0\n1797152\nIkmuYB2xKKEOLiaQkIho1o9/uGjrKDbk8xa3xXaFeHY=\n",
			wantSize: 1797152,
		},
		{
			desc:     "google 1p apk tessera origin",
			m:        "android.transparency.goog/google1p/apk/2026/1\n42\ndGhlIHZpZXcgZnJvbSB0aGUgdHJlZSB0b3BzIGlzIGdyZWF0IQ==\n",
			wantSize: 42,
		},
		{
			desc:     "mainline module tessera origin",
			m:        "android.transparency.goog/mainline/modules/2026/1\n14\n1WyF4nQ0ONJUILx/rVTdxFoURKUdeGwHHLeIKCcIYHw=\n",
			wantSize: 14,
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			root, err := parseCheckpoint(tt.m)
			if err != nil {
				t.Fatalf("parseCheckpoint(%q) returned error: %v", tt.m, err)
			}
			if root.Size != tt.wantSize {
				t.Errorf("got size %d, want %d", root.Size, tt.wantSize)
			}
		})
	}
}

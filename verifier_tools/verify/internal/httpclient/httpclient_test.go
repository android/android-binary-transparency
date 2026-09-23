package httpclient

import (
	"net/http"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	const customTimeout = 45 * time.Second
	client := New(customTimeout)

	if client.Timeout != customTimeout {
		t.Errorf("client.Timeout = %v, want %v", client.Timeout, customTimeout)
	}

	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport == nil {
		t.Fatalf("expected client.Transport to be *http.Transport, got %T", client.Transport)
	}
	if !transport.ForceAttemptHTTP2 {
		t.Errorf("transport.ForceAttemptHTTP2 = false, want true (required when DialContext is non-nil)")
	}
	if transport.ResponseHeaderTimeout != DefaultResponseHeaderTimeout {
		t.Errorf("transport.ResponseHeaderTimeout = %v, want %v", transport.ResponseHeaderTimeout, DefaultResponseHeaderTimeout)
	}
	if transport.TLSHandshakeTimeout != DefaultTLSHandshakeTimeout {
		t.Errorf("transport.TLSHandshakeTimeout = %v, want %v", transport.TLSHandshakeTimeout, DefaultTLSHandshakeTimeout)
	}
	if transport.DialContext == nil {
		t.Errorf("expected transport.DialContext to be non-nil")
	}
	if transport.MaxIdleConns != 100 {
		t.Errorf("transport.MaxIdleConns = %d, want 100", transport.MaxIdleConns)
	}
	if transport.MaxIdleConnsPerHost != 32 {
		t.Errorf("transport.MaxIdleConnsPerHost = %d, want 32", transport.MaxIdleConnsPerHost)
	}
	if transport.IdleConnTimeout != 90*time.Second {
		t.Errorf("transport.IdleConnTimeout = %v, want 90s", transport.IdleConnTimeout)
	}
	if transport.ExpectContinueTimeout != 1*time.Second {
		t.Errorf("transport.ExpectContinueTimeout = %v, want 1s", transport.ExpectContinueTimeout)
	}
}

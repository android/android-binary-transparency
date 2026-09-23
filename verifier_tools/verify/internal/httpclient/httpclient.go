// Package httpclient provides a shared HTTP client constructor with tuned
// connection, TLS, and response header timeouts for transparency log requests.
package httpclient

import (
	"net"
	"net/http"
	"time"
)

const (
	// DefaultResponseHeaderTimeout bounds the time spent waiting for a server's
	// response headers after a request is written.
	DefaultResponseHeaderTimeout = 30 * time.Second
	// DefaultDialTimeout bounds TCP connection establishment.
	DefaultDialTimeout = 10 * time.Second
	// DefaultTLSHandshakeTimeout bounds the TLS handshake.
	DefaultTLSHandshakeTimeout = 10 * time.Second
)

// New returns an *http.Client configured with the given overall request timeout
// and a shared transport policy (10s dial/TLS timeouts, 30s response header
// timeout, and HTTP/2 enabled).
func New(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   DefaultDialTimeout,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   32,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   DefaultTLSHandshakeTimeout,
			ResponseHeaderTimeout: DefaultResponseHeaderTimeout,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
}

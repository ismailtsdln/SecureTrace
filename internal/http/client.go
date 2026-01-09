package http

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"time"

	"github.com/ismailtasdelen/securetrace/internal/logger"
	"github.com/ismailtasdelen/securetrace/pkg/types"
)

// Client is an instrumented HTTP client for tracing
type Client struct {
	config     *types.Config
	httpClient *http.Client
	log        *logger.Logger
}

// TimingInfo holds timing information collected during a request
type TimingInfo struct {
	DNSStart           time.Time
	DNSDone            time.Time
	ConnectStart       time.Time
	ConnectDone        time.Time
	TLSStart           time.Time
	TLSDone            time.Time
	GotFirstByte       time.Time
	RequestStart       time.Time
	RequestDone        time.Time
	TLSConnectionState *tls.ConnectionState
}

// NewClient creates a new instrumented HTTP client
func NewClient(config *types.Config) *Client {
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   config.Timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: config.Timeout,
		ExpectContinueTimeout: 1 * time.Second,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
	}

	// Configure TLS
	transport.TLSClientConfig = &tls.Config{
		InsecureSkipVerify: !config.VerifyTLS,
		MinVersion:         tls.VersionTLS10,
	}

	// Configure proxy if specified
	if config.Proxy != "" {
		proxyURL, err := url.Parse(config.Proxy)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   config.Timeout,
	}

	// Don't follow redirects automatically - we track them manually
	if !config.FollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	return &Client{
		config:     config,
		httpClient: client,
		log:        logger.New().WithPrefix("http"),
	}
}

// Do performs an HTTP request with timing instrumentation
func (c *Client) Do(ctx context.Context, req *http.Request) (*http.Response, *TimingInfo, error) {
	timing := &TimingInfo{}

	trace := &httptrace.ClientTrace{
		DNSStart: func(info httptrace.DNSStartInfo) {
			timing.DNSStart = time.Now()
		},
		DNSDone: func(info httptrace.DNSDoneInfo) {
			timing.DNSDone = time.Now()
		},
		ConnectStart: func(network, addr string) {
			timing.ConnectStart = time.Now()
		},
		ConnectDone: func(network, addr string, err error) {
			timing.ConnectDone = time.Now()
		},
		TLSHandshakeStart: func() {
			timing.TLSStart = time.Now()
		},
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			timing.TLSDone = time.Now()
			if err == nil {
				timing.TLSConnectionState = &state
			}
		},
		GotFirstResponseByte: func() {
			timing.GotFirstByte = time.Now()
		},
	}

	req = req.WithContext(httptrace.WithClientTrace(ctx, trace))
	timing.RequestStart = time.Now()

	// Set user agent
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", c.config.UserAgent)
	}

	resp, err := c.httpClient.Do(req)
	timing.RequestDone = time.Now()

	if err != nil {
		return nil, timing, fmt.Errorf("request failed: %w", err)
	}

	return resp, timing, nil
}

// DoWithRetry performs an HTTP request with retry logic
func (c *Client) DoWithRetry(ctx context.Context, req *http.Request) (*http.Response, *TimingInfo, error) {
	var lastErr error
	var resp *http.Response
	var timing *TimingInfo

	for attempt := 0; attempt <= c.config.Retries; attempt++ {
		if attempt > 0 {
			// Exponential backoff
			backoff := time.Duration(1<<uint(attempt-1)) * 100 * time.Millisecond
			if backoff > 5*time.Second {
				backoff = 5 * time.Second
			}
			c.log.Debug("Retrying request (attempt %d/%d) after %v", attempt+1, c.config.Retries+1, backoff)

			select {
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			case <-time.After(backoff):
			}

			// Clone the request for retry
			var err error
			req, err = cloneRequest(req)
			if err != nil {
				return nil, nil, err
			}
		}

		resp, timing, lastErr = c.Do(ctx, req)
		if lastErr == nil {
			return resp, timing, nil
		}

		c.log.Warn("Request failed: %v", lastErr)
	}

	return nil, timing, fmt.Errorf("all %d retries failed: %w", c.config.Retries+1, lastErr)
}

// cloneRequest creates a copy of an HTTP request
func cloneRequest(req *http.Request) (*http.Request, error) {
	clone := req.Clone(req.Context())
	if req.Body != nil {
		return nil, fmt.Errorf("cannot retry request with body")
	}
	return clone, nil
}

// Close closes the HTTP client's idle connections
func (c *Client) Close() {
	c.httpClient.CloseIdleConnections()
}

// CalculateTimeline converts TimingInfo to a Timeline struct
func CalculateTimeline(timing *TimingInfo) types.Timeline {
	var timeline types.Timeline

	// DNS Lookup
	if !timing.DNSStart.IsZero() && !timing.DNSDone.IsZero() {
		timeline.DNSLookup = types.Duration{Duration: timing.DNSDone.Sub(timing.DNSStart)}
	}

	// TCP Connection
	if !timing.ConnectStart.IsZero() && !timing.ConnectDone.IsZero() {
		timeline.TCPConnection = types.Duration{Duration: timing.ConnectDone.Sub(timing.ConnectStart)}
	}

	// TLS Handshake
	if !timing.TLSStart.IsZero() && !timing.TLSDone.IsZero() {
		timeline.TLSHandshake = types.Duration{Duration: timing.TLSDone.Sub(timing.TLSStart)}
	}

	// Server Processing (from TLS done or connect done to first byte)
	connectEnd := timing.ConnectDone
	if !timing.TLSDone.IsZero() {
		connectEnd = timing.TLSDone
	}
	if !connectEnd.IsZero() && !timing.GotFirstByte.IsZero() {
		timeline.ServerProcessing = types.Duration{Duration: timing.GotFirstByte.Sub(connectEnd)}
	}

	// Content Transfer (from first byte to done)
	if !timing.GotFirstByte.IsZero() && !timing.RequestDone.IsZero() {
		timeline.ContentTransfer = types.Duration{Duration: timing.RequestDone.Sub(timing.GotFirstByte)}
	}

	// Total
	if !timing.RequestStart.IsZero() && !timing.RequestDone.IsZero() {
		timeline.Total = types.Duration{Duration: timing.RequestDone.Sub(timing.RequestStart)}
	}

	return timeline
}

// ReadBodyPreview reads a limited preview of the response body
func ReadBodyPreview(resp *http.Response, maxSize int64) ([]byte, error) {
	if resp.Body == nil {
		return nil, nil
	}

	limited := io.LimitReader(resp.Body, maxSize)
	return io.ReadAll(limited)
}

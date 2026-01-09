package tracer

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	httpclient "github.com/ismailtasdelen/securetrace/internal/http"
	"github.com/ismailtasdelen/securetrace/internal/logger"
	"github.com/ismailtasdelen/securetrace/internal/tls"
	"github.com/ismailtasdelen/securetrace/pkg/types"
)

// Tracer performs HTTP/HTTPS request tracing with detailed analysis
type Tracer struct {
	config          *types.Config
	client          *httpclient.Client
	tlsAnalyzer     *tls.Analyzer
	headersAnalyzer *httpclient.SecurityHeadersAnalyzer
	bodyInspector   *httpclient.BodyInspector
	log             *logger.Logger
}

// New creates a new Tracer instance
func New(config *types.Config) *Tracer {
	return &Tracer{
		config:          config,
		client:          httpclient.NewClient(config),
		tlsAnalyzer:     tls.NewAnalyzer(),
		headersAnalyzer: httpclient.NewSecurityHeadersAnalyzer(),
		bodyInspector:   httpclient.NewBodyInspector(1024 * 1024), // 1MB max body
		log:             logger.New().WithPrefix("tracer"),
	}
}

// Trace performs a complete trace of the given URL
func (t *Tracer) Trace(ctx context.Context, targetURL string) (*types.TraceResult, error) {
	result := &types.TraceResult{
		URL:       targetURL,
		Method:    "GET",
		Timestamp: time.Now(),
		Redirects: make([]types.RedirectHop, 0),
	}

	// Parse and validate URL
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		result.Error = fmt.Sprintf("Invalid URL: %v", err)
		return result, err
	}

	// Add scheme if missing
	if parsedURL.Scheme == "" {
		parsedURL.Scheme = "https"
		targetURL = parsedURL.String()
		result.URL = targetURL
	}

	t.log.Debug("Starting trace for %s", targetURL)

	// Perform the trace with redirect tracking
	currentURL := targetURL
	var lastTiming *httpclient.TimingInfo
	var lastResp *http.Response

	for hop := 0; hop <= t.config.MaxRedirects; hop++ {
		req, err := http.NewRequestWithContext(ctx, "GET", currentURL, nil)
		if err != nil {
			result.Error = fmt.Sprintf("Failed to create request: %v", err)
			return result, err
		}

		// Set headers
		req.Header.Set("User-Agent", t.config.UserAgent)
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		req.Header.Set("Accept-Language", "en-US,en;q=0.5")

		// Perform request
		resp, timing, err := t.client.DoWithRetry(ctx, req)
		if err != nil {
			result.Error = fmt.Sprintf("Request failed: %v", err)
			return result, err
		}

		lastTiming = timing
		lastResp = resp

		// Check if this is a redirect
		if isRedirect(resp.StatusCode) && t.config.FollowRedirects {
			location := resp.Header.Get("Location")
			if location == "" {
				break
			}

			// Resolve relative URLs
			redirectURL, err := url.Parse(location)
			if err != nil {
				break
			}
			if !redirectURL.IsAbs() {
				base, _ := url.Parse(currentURL)
				redirectURL = base.ResolveReference(redirectURL)
			}

			// Record redirect hop
			hop := types.RedirectHop{
				URL:        currentURL,
				StatusCode: resp.StatusCode,
				Headers:    resp.Header,
				Duration:   types.Duration{Duration: httpclient.CalculateTimeline(timing).Total.Duration},
			}
			result.Redirects = append(result.Redirects, hop)

			t.log.Debug("Following redirect: %s -> %s", currentURL, redirectURL.String())
			currentURL = redirectURL.String()
			resp.Body.Close()
			continue
		}

		break
	}

	if lastResp == nil {
		result.Error = "No response received"
		return result, fmt.Errorf("no response received")
	}
	defer lastResp.Body.Close()

	// Populate result
	result.FinalURL = currentURL
	result.StatusCode = lastResp.StatusCode
	result.Headers = lastResp.Header

	// Calculate timeline
	if lastTiming != nil {
		result.Timeline = httpclient.CalculateTimeline(lastTiming)

		// Analyze TLS if available
		if lastTiming.TLSConnectionState != nil {
			result.TLSInfo = t.tlsAnalyzer.Analyze(lastTiming.TLSConnectionState)
		}
	}

	// Analyze security headers
	result.SecurityInfo = t.headersAnalyzer.Analyze(lastResp.Header)

	// Inspect body
	bodyInfo, _, err := t.bodyInspector.Inspect(lastResp)
	if err == nil && bodyInfo != nil {
		result.Body = bodyInfo
	}

	t.log.Debug("Trace complete: %s -> %d", targetURL, result.StatusCode)
	return result, nil
}

// TraceMultiple traces multiple URLs concurrently
func (t *Tracer) TraceMultiple(ctx context.Context, urls []string, concurrency int) *types.ScanResult {
	if concurrency <= 0 {
		concurrency = 5
	}

	result := &types.ScanResult{
		Targets:   urls,
		Results:   make([]types.TraceResult, 0, len(urls)),
		StartTime: time.Now(),
	}

	// Create a semaphore channel for concurrency control
	sem := make(chan struct{}, concurrency)
	resultsChan := make(chan types.TraceResult, len(urls))

	for _, targetURL := range urls {
		sem <- struct{}{} // Acquire semaphore
		go func(u string) {
			defer func() { <-sem }() // Release semaphore

			traceResult, err := t.Trace(ctx, u)
			if traceResult == nil {
				traceResult = &types.TraceResult{
					URL:       u,
					Timestamp: time.Now(),
					Error:     err.Error(),
				}
			}
			resultsChan <- *traceResult
		}(targetURL)
	}

	// Collect results
	for i := 0; i < len(urls); i++ {
		traceResult := <-resultsChan
		result.Results = append(result.Results, traceResult)
	}

	result.EndTime = time.Now()
	result.Duration = types.Duration{Duration: result.EndTime.Sub(result.StartTime)}

	// Calculate summary
	result.Summary = t.calculateSummary(result.Results)

	return result
}

// calculateSummary generates a summary of scan results
func (t *Tracer) calculateSummary(results []types.TraceResult) types.ScanSummary {
	summary := types.ScanSummary{
		TotalTargets: len(results),
	}

	for _, r := range results {
		if r.Error == "" && r.StatusCode > 0 {
			summary.Successful++
		} else {
			summary.Failed++
		}

		if r.TLSInfo != nil {
			summary.TLSEnabled++
		}

		if len(r.SecurityInfo.Issues) > 0 {
			summary.SecurityIssues++
		}
	}

	return summary
}

// Close cleans up tracer resources
func (t *Tracer) Close() {
	t.client.Close()
}

// isRedirect checks if a status code indicates a redirect
func isRedirect(statusCode int) bool {
	return statusCode >= 300 && statusCode < 400
}

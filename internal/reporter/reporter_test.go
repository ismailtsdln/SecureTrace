package reporter

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ismailtasdelen/securetrace/pkg/types"
)

func createTestResult() *types.TraceResult {
	return &types.TraceResult{
		URL:        "https://example.com",
		FinalURL:   "https://example.com/",
		StatusCode: 200,
		Method:     "GET",
		Headers:    http.Header{"Content-Type": []string{"text/html"}},
		Timeline: types.Timeline{
			DNSLookup:        types.Duration{Duration: 10 * time.Millisecond},
			TCPConnection:    types.Duration{Duration: 20 * time.Millisecond},
			TLSHandshake:     types.Duration{Duration: 50 * time.Millisecond},
			ServerProcessing: types.Duration{Duration: 100 * time.Millisecond},
			ContentTransfer:  types.Duration{Duration: 30 * time.Millisecond},
			Total:            types.Duration{Duration: 210 * time.Millisecond},
		},
		TLSInfo: &types.TLSInfo{
			Version:     "TLS 1.3",
			CipherSuite: "TLS_AES_256_GCM_SHA384",
			Grade:       "A+",
		},
		SecurityInfo: types.SecurityInfo{
			Score: 85,
			Grade: "A",
		},
		Timestamp: time.Now(),
	}
}

func TestJSONReporter_Format(t *testing.T) {
	reporter := NewJSONReporter(true)
	result := createTestResult()

	data, err := reporter.Format(result)
	if err != nil {
		t.Fatalf("Failed to format: %v", err)
	}

	// Verify it's valid JSON
	var decoded types.TraceResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Invalid JSON output: %v", err)
	}

	if decoded.URL != result.URL {
		t.Errorf("URL mismatch: expected %s, got %s", result.URL, decoded.URL)
	}
	if decoded.StatusCode != result.StatusCode {
		t.Errorf("Status code mismatch: expected %d, got %d", result.StatusCode, decoded.StatusCode)
	}
}

func TestJSONReporter_ContentType(t *testing.T) {
	reporter := NewJSONReporter(false)
	if reporter.ContentType() != "application/json" {
		t.Errorf("Expected application/json, got %s", reporter.ContentType())
	}
}

func TestHTMLReporter_Format(t *testing.T) {
	reporter := NewHTMLReporter()
	result := createTestResult()

	data, err := reporter.Format(result)
	if err != nil {
		t.Fatalf("Failed to format: %v", err)
	}

	html := string(data)

	// Check for essential HTML elements
	if !strings.Contains(html, "<!DOCTYPE html>") {
		t.Error("Missing DOCTYPE")
	}
	if !strings.Contains(html, "SecureTrace") {
		t.Error("Missing SecureTrace branding")
	}
	if !strings.Contains(html, result.FinalURL) {
		t.Error("Missing final URL")
	}
}

func TestHTMLReporter_ContentType(t *testing.T) {
	reporter := NewHTMLReporter()
	if reporter.ContentType() != "text/html" {
		t.Errorf("Expected text/html, got %s", reporter.ContentType())
	}
}

func TestCSVReporter_Format(t *testing.T) {
	reporter := NewCSVReporter()
	result := createTestResult()

	data, err := reporter.Format(result)
	if err != nil {
		t.Fatalf("Failed to format: %v", err)
	}

	csv := string(data)
	lines := strings.Split(strings.TrimSpace(csv), "\n")

	if len(lines) != 2 {
		t.Errorf("Expected 2 lines (header + data), got %d", len(lines))
	}

	// Check header
	if !strings.Contains(lines[0], "URL") {
		t.Error("Missing URL header")
	}

	// Check data row
	if !strings.Contains(lines[1], "https://example.com") {
		t.Error("Missing URL in data")
	}
}

func TestCSVReporter_FormatScan(t *testing.T) {
	reporter := NewCSVReporter()

	scanResult := &types.ScanResult{
		Results: []types.TraceResult{
			*createTestResult(),
			{
				URL:        "https://example2.com",
				FinalURL:   "https://example2.com/",
				StatusCode: 301,
			},
		},
	}

	data, err := reporter.FormatScan(scanResult)
	if err != nil {
		t.Fatalf("Failed to format: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 3 {
		t.Errorf("Expected 3 lines (header + 2 data rows), got %d", len(lines))
	}
}

func TestTextReporter_Format(t *testing.T) {
	reporter := NewTextReporter(false)
	result := createTestResult()

	data, err := reporter.Format(result)
	if err != nil {
		t.Fatalf("Failed to format: %v", err)
	}

	text := string(data)

	// Check for essential elements
	if !strings.Contains(text, result.FinalURL) {
		t.Error("Missing final URL")
	}
	if !strings.Contains(text, "200") {
		t.Error("Missing status code")
	}
	if !strings.Contains(text, "TLS") {
		t.Error("Missing TLS section")
	}
}

func TestParseFormat(t *testing.T) {
	tests := []struct {
		input    string
		expected Format
	}{
		{"json", FormatJSON},
		{"html", FormatHTML},
		{"csv", FormatCSV},
		{"text", FormatText},
		{"unknown", FormatText},
	}

	for _, tt := range tests {
		result := ParseFormat(tt.input)
		if result != tt.expected {
			t.Errorf("ParseFormat(%s): expected %v, got %v", tt.input, tt.expected, result)
		}
	}
}

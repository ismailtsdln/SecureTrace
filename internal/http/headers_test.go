package http

import (
	"net/http"
	"testing"
)

func TestSecurityHeadersAnalyzer_Analyze(t *testing.T) {
	analyzer := NewSecurityHeadersAnalyzer()

	tests := []struct {
		name          string
		headers       http.Header
		expectedScore int
		expectedGrade string
		issueContains string
	}{
		{
			name:          "Empty headers",
			headers:       http.Header{},
			expectedScore: 0,
			expectedGrade: "F",
		},
		{
			name: "Full security headers",
			headers: http.Header{
				"Strict-Transport-Security": []string{"max-age=31536000; includeSubDomains; preload"},
				"Content-Security-Policy":   []string{"default-src 'self'"},
				"X-Frame-Options":           []string{"DENY"},
				"X-Content-Type-Options":    []string{"nosniff"},
				"Referrer-Policy":           []string{"strict-origin-when-cross-origin"},
				"Permissions-Policy":        []string{"geolocation=()"},
			},
			expectedScore: 100,
			expectedGrade: "A+",
		},
		{
			name: "Partial security headers",
			headers: http.Header{
				"Strict-Transport-Security": []string{"max-age=31536000"},
				"X-Frame-Options":           []string{"SAMEORIGIN"},
			},
			expectedScore: 50,
			expectedGrade: "D",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := analyzer.Analyze(tt.headers)

			if info.Score != tt.expectedScore {
				t.Errorf("Score: expected %d, got %d", tt.expectedScore, info.Score)
			}
			if info.Grade != tt.expectedGrade {
				t.Errorf("Grade: expected %s, got %s", tt.expectedGrade, info.Grade)
			}
		})
	}
}

func TestParseHSTS(t *testing.T) {
	tests := []struct {
		value              string
		expectedMaxAge     int
		expectedSubdomains bool
		expectedPreload    bool
	}{
		{
			value:              "max-age=31536000",
			expectedMaxAge:     31536000,
			expectedSubdomains: false,
			expectedPreload:    false,
		},
		{
			value:              "max-age=31536000; includeSubDomains",
			expectedMaxAge:     31536000,
			expectedSubdomains: true,
			expectedPreload:    false,
		},
		{
			value:              "max-age=31536000; includeSubDomains; preload",
			expectedMaxAge:     31536000,
			expectedSubdomains: true,
			expectedPreload:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			hsts := parseHSTS(tt.value)

			if hsts.MaxAge != tt.expectedMaxAge {
				t.Errorf("MaxAge: expected %d, got %d", tt.expectedMaxAge, hsts.MaxAge)
			}
			if hsts.IncludeSubdomains != tt.expectedSubdomains {
				t.Errorf("IncludeSubdomains: expected %v, got %v", tt.expectedSubdomains, hsts.IncludeSubdomains)
			}
			if hsts.Preload != tt.expectedPreload {
				t.Errorf("Preload: expected %v, got %v", tt.expectedPreload, hsts.Preload)
			}
		})
	}
}

func TestIsSecurityHeader(t *testing.T) {
	securityHeaders := []string{
		"Strict-Transport-Security",
		"Content-Security-Policy",
		"X-Frame-Options",
		"X-Content-Type-Options",
	}

	nonSecurityHeaders := []string{
		"Content-Type",
		"Cache-Control",
		"Accept",
		"User-Agent",
	}

	for _, h := range securityHeaders {
		if !IsSecurityHeader(h) {
			t.Errorf("Expected %s to be a security header", h)
		}
	}

	for _, h := range nonSecurityHeaders {
		if IsSecurityHeader(h) {
			t.Errorf("Expected %s not to be a security header", h)
		}
	}
}

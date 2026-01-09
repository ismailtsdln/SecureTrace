package tls

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func TestAnalyzer_GetVersionName(t *testing.T) {
	analyzer := NewAnalyzer()

	tests := []struct {
		version  uint16
		expected string
	}{
		{tls.VersionTLS13, "TLS 1.3"},
		{tls.VersionTLS12, "TLS 1.2"},
		{tls.VersionTLS11, "TLS 1.1"},
		{tls.VersionTLS10, "TLS 1.0"},
	}

	for _, tt := range tests {
		result := analyzer.getVersionName(tt.version)
		if result != tt.expected {
			t.Errorf("Version 0x%04x: expected %s, got %s", tt.version, tt.expected, result)
		}
	}
}

func TestAnalyzer_IsSecure(t *testing.T) {
	analyzer := NewAnalyzer()

	// Create a mock certificate
	now := time.Now()
	cert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		NotBefore:    now.Add(-24 * time.Hour),
		NotAfter:     now.Add(365 * 24 * time.Hour),
		SerialNumber: big.NewInt(12345),
	}

	tests := []struct {
		name     string
		state    *tls.ConnectionState
		expected bool
	}{
		{
			name:     "nil state",
			state:    nil,
			expected: false,
		},
		{
			name: "TLS 1.3 secure cipher",
			state: &tls.ConnectionState{
				Version:          tls.VersionTLS13,
				CipherSuite:      tls.TLS_AES_256_GCM_SHA384,
				PeerCertificates: []*x509.Certificate{cert},
			},
			expected: true,
		},
		{
			name: "TLS 1.2 secure cipher",
			state: &tls.ConnectionState{
				Version:          tls.VersionTLS12,
				CipherSuite:      tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				PeerCertificates: []*x509.Certificate{cert},
			},
			expected: true,
		},
		{
			name: "TLS 1.0 insecure",
			state: &tls.ConnectionState{
				Version:          tls.VersionTLS10,
				CipherSuite:      tls.TLS_RSA_WITH_AES_128_CBC_SHA,
				PeerCertificates: []*x509.Certificate{cert},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.IsSecure(tt.state)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestAnalyzer_GetSecurityIssues(t *testing.T) {
	analyzer := NewAnalyzer()

	// Create expired certificate
	now := time.Now()
	expiredCert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "expired.example.com",
		},
		NotBefore:    now.Add(-365 * 24 * time.Hour),
		NotAfter:     now.Add(-1 * 24 * time.Hour),
		SerialNumber: big.NewInt(12345),
	}

	tests := []struct {
		name          string
		state         *tls.ConnectionState
		expectIssues  bool
		issueContains string
	}{
		{
			name:          "nil state",
			state:         nil,
			expectIssues:  true,
			issueContains: "No TLS connection",
		},
		{
			name: "TLS 1.0",
			state: &tls.ConnectionState{
				Version:     tls.VersionTLS10,
				CipherSuite: tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			},
			expectIssues:  true,
			issueContains: "TLS 1.0",
		},
		{
			name: "expired certificate",
			state: &tls.ConnectionState{
				Version:          tls.VersionTLS12,
				CipherSuite:      tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				PeerCertificates: []*x509.Certificate{expiredCert},
			},
			expectIssues:  true,
			issueContains: "expired",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues := analyzer.GetSecurityIssues(tt.state)

			if tt.expectIssues && len(issues) == 0 {
				t.Error("Expected issues but got none")
			}

			if tt.issueContains != "" {
				found := false
				for _, issue := range issues {
					if contains(issue, tt.issueContains) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected issue containing '%s', got: %v", tt.issueContains, issues)
				}
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

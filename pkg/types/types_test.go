package types

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Timeout != 30*time.Second {
		t.Errorf("Expected timeout 30s, got %v", cfg.Timeout)
	}
	if cfg.MaxRedirects != 10 {
		t.Errorf("Expected max redirects 10, got %d", cfg.MaxRedirects)
	}
	if !cfg.FollowRedirects {
		t.Error("Expected follow redirects to be true")
	}
	if !cfg.VerifyTLS {
		t.Error("Expected verify TLS to be true")
	}
	if cfg.Retries != 3 {
		t.Errorf("Expected retries 3, got %d", cfg.Retries)
	}
}

func TestDurationMarshalJSON(t *testing.T) {
	d := Duration{Duration: 5 * time.Second}

	data, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("Failed to marshal duration: %v", err)
	}

	expected := `"5s"`
	if string(data) != expected {
		t.Errorf("Expected %s, got %s", expected, string(data))
	}
}

func TestNewCertificateInfo(t *testing.T) {
	now := time.Now()
	cert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		Issuer: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore:          now.Add(-24 * time.Hour),
		NotAfter:           now.Add(365 * 24 * time.Hour),
		SerialNumber:       big.NewInt(12345),
		SignatureAlgorithm: x509.SHA256WithRSA,
		DNSNames:           []string{"test.example.com", "*.example.com"},
		IsCA:               false,
	}

	info := NewCertificateInfo(cert)

	if info.IsExpired {
		t.Error("Expected certificate not to be expired")
	}
	if info.DaysUntilExpiry < 364 || info.DaysUntilExpiry > 366 {
		t.Errorf("Expected ~365 days until expiry, got %d", info.DaysUntilExpiry)
	}
	if len(info.DNSNames) != 2 {
		t.Errorf("Expected 2 DNS names, got %d", len(info.DNSNames))
	}
	if info.IsCA {
		t.Error("Expected IsCA to be false")
	}
}

func TestNewCertificateInfo_Expired(t *testing.T) {
	now := time.Now()
	cert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "expired.example.com",
		},
		Issuer: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore:          now.Add(-365 * 24 * time.Hour),
		NotAfter:           now.Add(-1 * 24 * time.Hour),
		SerialNumber:       big.NewInt(12345),
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	info := NewCertificateInfo(cert)

	if !info.IsExpired {
		t.Error("Expected certificate to be expired")
	}
	if info.DaysUntilExpiry >= 0 {
		t.Errorf("Expected negative days until expiry for expired cert, got %d", info.DaysUntilExpiry)
	}
}

func TestTraceResult_JSON(t *testing.T) {
	result := TraceResult{
		URL:        "https://example.com",
		FinalURL:   "https://example.com/",
		StatusCode: 200,
		Method:     "GET",
		Timeline: Timeline{
			Total: Duration{Duration: 500 * time.Millisecond},
		},
		Timestamp: time.Now(),
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Failed to marshal trace result: %v", err)
	}

	var decoded TraceResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal trace result: %v", err)
	}

	if decoded.URL != result.URL {
		t.Errorf("URL mismatch: expected %s, got %s", result.URL, decoded.URL)
	}
	if decoded.StatusCode != result.StatusCode {
		t.Errorf("Status code mismatch: expected %d, got %d", result.StatusCode, decoded.StatusCode)
	}
}

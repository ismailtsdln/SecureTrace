package types

import (
	"crypto/x509"
	"net/http"
	"time"
)

// Version information
const (
	Version = "1.0.0"
	AppName = "SecureTrace"
)

// TraceResult holds the complete result of an HTTP trace
type TraceResult struct {
	URL           string           `json:"url"`
	FinalURL      string           `json:"final_url"`
	StatusCode    int              `json:"status_code"`
	Method        string           `json:"method"`
	Redirects     []RedirectHop    `json:"redirects,omitempty"`
	Timeline      Timeline         `json:"timeline"`
	TLSInfo       *TLSInfo         `json:"tls_info,omitempty"`
	Headers       http.Header      `json:"headers"`
	SecurityInfo  SecurityInfo     `json:"security_info"`
	Body          *BodyInfo        `json:"body,omitempty"`
	Error         string           `json:"error,omitempty"`
	Timestamp     time.Time        `json:"timestamp"`
}

// RedirectHop represents a single redirect in the chain
type RedirectHop struct {
	URL        string      `json:"url"`
	StatusCode int         `json:"status_code"`
	Headers    http.Header `json:"headers"`
	Duration   Duration    `json:"duration"`
}

// Timeline holds timing information for the request
type Timeline struct {
	DNSLookup        Duration `json:"dns_lookup"`
	TCPConnection    Duration `json:"tcp_connection"`
	TLSHandshake     Duration `json:"tls_handshake"`
	ServerProcessing Duration `json:"server_processing"`
	ContentTransfer  Duration `json:"content_transfer"`
	Total            Duration `json:"total"`
}

// Duration is a wrapper for time.Duration with custom JSON marshaling
type Duration struct {
	time.Duration
}

// MarshalJSON implements json.Marshaler
func (d Duration) MarshalJSON() ([]byte, error) {
	return []byte(`"` + d.Duration.String() + `"`), nil
}

// TLSInfo holds TLS/SSL connection information
type TLSInfo struct {
	Version            string            `json:"version"`
	CipherSuite        string            `json:"cipher_suite"`
	ServerName         string            `json:"server_name"`
	NegotiatedProtocol string            `json:"negotiated_protocol"`
	Certificates       []CertificateInfo `json:"certificates"`
	Grade              string            `json:"grade"`
}

// CertificateInfo holds parsed certificate information
type CertificateInfo struct {
	Subject            string    `json:"subject"`
	Issuer             string    `json:"issuer"`
	NotBefore          time.Time `json:"not_before"`
	NotAfter           time.Time `json:"not_after"`
	SerialNumber       string    `json:"serial_number"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
	DNSNames           []string  `json:"dns_names,omitempty"`
	IsCA               bool      `json:"is_ca"`
	IsExpired          bool      `json:"is_expired"`
	DaysUntilExpiry    int       `json:"days_until_expiry"`
}

// NewCertificateInfo creates CertificateInfo from x509.Certificate
func NewCertificateInfo(cert *x509.Certificate) CertificateInfo {
	now := time.Now()
	daysUntilExpiry := int(cert.NotAfter.Sub(now).Hours() / 24)
	
	return CertificateInfo{
		Subject:            cert.Subject.String(),
		Issuer:             cert.Issuer.String(),
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		SerialNumber:       cert.SerialNumber.String(),
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		DNSNames:           cert.DNSNames,
		IsCA:               cert.IsCA,
		IsExpired:          now.After(cert.NotAfter),
		DaysUntilExpiry:    daysUntilExpiry,
	}
}

// SecurityInfo holds security header analysis results
type SecurityInfo struct {
	HSTS               *HSTSInfo     `json:"hsts,omitempty"`
	ContentSecurityPolicy string     `json:"content_security_policy,omitempty"`
	XFrameOptions      string        `json:"x_frame_options,omitempty"`
	XContentTypeOptions string       `json:"x_content_type_options,omitempty"`
	XXSSProtection     string        `json:"x_xss_protection,omitempty"`
	ReferrerPolicy     string        `json:"referrer_policy,omitempty"`
	PermissionsPolicy  string        `json:"permissions_policy,omitempty"`
	Score              int           `json:"score"`
	Grade              string        `json:"grade"`
	Issues             []string      `json:"issues,omitempty"`
}

// HSTSInfo holds HSTS header information
type HSTSInfo struct {
	Enabled           bool `json:"enabled"`
	MaxAge            int  `json:"max_age"`
	IncludeSubdomains bool `json:"include_subdomains"`
	Preload           bool `json:"preload"`
}

// BodyInfo holds response body information
type BodyInfo struct {
	Size        int64  `json:"size"`
	ContentType string `json:"content_type"`
	Encoding    string `json:"encoding,omitempty"`
	Preview     string `json:"preview,omitempty"`
	Hash        string `json:"hash,omitempty"`
}

// Config represents application configuration
type Config struct {
	Timeout         time.Duration `json:"timeout"`
	MaxRedirects    int           `json:"max_redirects"`
	UserAgent       string        `json:"user_agent"`
	Proxy           string        `json:"proxy,omitempty"`
	FollowRedirects bool          `json:"follow_redirects"`
	VerifyTLS       bool          `json:"verify_tls"`
	Verbose         bool          `json:"verbose"`
	OutputFormat    string        `json:"output_format"`
	RateLimit       int           `json:"rate_limit"`
	Retries         int           `json:"retries"`
	CacheTTL        time.Duration `json:"cache_ttl"`
}

// DefaultConfig returns a Config with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		Timeout:         30 * time.Second,
		MaxRedirects:    10,
		UserAgent:       AppName + "/" + Version,
		FollowRedirects: true,
		VerifyTLS:       true,
		Verbose:         false,
		OutputFormat:    "text",
		RateLimit:       0,
		Retries:         3,
		CacheTTL:        5 * time.Minute,
	}
}

// ScanResult holds results from multiple URL scans
type ScanResult struct {
	Targets   []string      `json:"targets"`
	Results   []TraceResult `json:"results"`
	Summary   ScanSummary   `json:"summary"`
	StartTime time.Time     `json:"start_time"`
	EndTime   time.Time     `json:"end_time"`
	Duration  Duration      `json:"duration"`
}

// ScanSummary provides an overview of scan results
type ScanSummary struct {
	TotalTargets   int `json:"total_targets"`
	Successful     int `json:"successful"`
	Failed         int `json:"failed"`
	TLSEnabled     int `json:"tls_enabled"`
	SecurityIssues int `json:"security_issues"`
}

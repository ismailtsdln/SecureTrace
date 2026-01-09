package tls

import (
	"crypto/tls"
	"fmt"
	"strings"

	"github.com/ismailtasdelen/securetrace/pkg/types"
)

// TLS version names
var tlsVersionNames = map[uint16]string{
	tls.VersionSSL30: "SSL 3.0",
	tls.VersionTLS10: "TLS 1.0",
	tls.VersionTLS11: "TLS 1.1",
	tls.VersionTLS12: "TLS 1.2",
	tls.VersionTLS13: "TLS 1.3",
}

// Cipher suite security ratings
var cipherSuiteSecure = map[uint16]bool{
	// TLS 1.3 cipher suites (all secure)
	tls.TLS_AES_128_GCM_SHA256:       true,
	tls.TLS_AES_256_GCM_SHA384:       true,
	tls.TLS_CHACHA20_POLY1305_SHA256: true,
	// TLS 1.2 secure cipher suites
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:   true,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:   true,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: true,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: true,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305:    true,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305:  true,
}

// Analyzer provides TLS/SSL connection analysis
type Analyzer struct{}

// NewAnalyzer creates a new TLS analyzer
func NewAnalyzer() *Analyzer {
	return &Analyzer{}
}

// Analyze examines a TLS connection state and returns detailed information
func (a *Analyzer) Analyze(state *tls.ConnectionState) *types.TLSInfo {
	if state == nil {
		return nil
	}

	info := &types.TLSInfo{
		Version:            a.getVersionName(state.Version),
		CipherSuite:        tls.CipherSuiteName(state.CipherSuite),
		ServerName:         state.ServerName,
		NegotiatedProtocol: state.NegotiatedProtocol,
		Certificates:       make([]types.CertificateInfo, 0, len(state.PeerCertificates)),
	}

	// Analyze certificates
	for _, cert := range state.PeerCertificates {
		info.Certificates = append(info.Certificates, types.NewCertificateInfo(cert))
	}

	// Calculate security grade
	info.Grade = a.calculateGrade(state)

	return info
}

// getVersionName returns a human-readable TLS version name
func (a *Analyzer) getVersionName(version uint16) string {
	if name, ok := tlsVersionNames[version]; ok {
		return name
	}
	return fmt.Sprintf("Unknown (0x%04x)", version)
}

// calculateGrade calculates a security grade based on TLS configuration
func (a *Analyzer) calculateGrade(state *tls.ConnectionState) string {
	score := 100

	// Version scoring
	switch state.Version {
	case tls.VersionTLS13:
		// Best, no penalty
	case tls.VersionTLS12:
		score -= 5
	case tls.VersionTLS11:
		score -= 30
	case tls.VersionTLS10:
		score -= 50
	default:
		score -= 70
	}

	// Cipher suite scoring
	if _, secure := cipherSuiteSecure[state.CipherSuite]; !secure {
		score -= 20
	}

	// Certificate scoring
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		certInfo := types.NewCertificateInfo(cert)

		if certInfo.IsExpired {
			score -= 50
		} else if certInfo.DaysUntilExpiry < 30 {
			score -= 10
		}
	} else {
		score -= 30
	}

	// Convert score to grade
	switch {
	case score >= 95:
		return "A+"
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	default:
		return "F"
	}
}

// IsSecure checks if a TLS connection is considered secure
func (a *Analyzer) IsSecure(state *tls.ConnectionState) bool {
	if state == nil {
		return false
	}

	// Require TLS 1.2 or higher
	if state.Version < tls.VersionTLS12 {
		return false
	}

	// Check cipher suite security
	if _, secure := cipherSuiteSecure[state.CipherSuite]; !secure {
		return false
	}

	// Check certificate validity
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		certInfo := types.NewCertificateInfo(cert)
		if certInfo.IsExpired {
			return false
		}
	}

	return true
}

// GetSecurityIssues returns a list of security issues with the TLS connection
func (a *Analyzer) GetSecurityIssues(state *tls.ConnectionState) []string {
	issues := make([]string, 0)

	if state == nil {
		return []string{"No TLS connection"}
	}

	// Version issues
	switch state.Version {
	case tls.VersionTLS10:
		issues = append(issues, "TLS 1.0 is deprecated and insecure")
	case tls.VersionTLS11:
		issues = append(issues, "TLS 1.1 is deprecated")
	case tls.VersionSSL30:
		issues = append(issues, "SSL 3.0 is insecure and should not be used")
	}

	// Cipher suite issues
	cipherName := tls.CipherSuiteName(state.CipherSuite)
	if strings.Contains(cipherName, "CBC") {
		issues = append(issues, "CBC mode cipher suites are vulnerable to padding oracle attacks")
	}
	if strings.Contains(cipherName, "RC4") {
		issues = append(issues, "RC4 is insecure and should not be used")
	}
	if strings.Contains(cipherName, "3DES") {
		issues = append(issues, "3DES is weak and should be avoided")
	}
	if !strings.Contains(cipherName, "ECDHE") && !strings.Contains(cipherName, "DHE") {
		issues = append(issues, "Forward secrecy (ECDHE/DHE) is not enabled")
	}

	// Certificate issues
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		certInfo := types.NewCertificateInfo(cert)

		if certInfo.IsExpired {
			issues = append(issues, "Certificate has expired")
		} else if certInfo.DaysUntilExpiry < 30 {
			issues = append(issues, fmt.Sprintf("Certificate expires in %d days", certInfo.DaysUntilExpiry))
		}

		if cert.PublicKeyAlgorithm.String() == "RSA" {
			// Check key size for RSA
			if cert.PublicKey != nil {
				// RSA keys less than 2048 bits are weak
			}
		}
	} else {
		issues = append(issues, "No peer certificates present")
	}

	return issues
}

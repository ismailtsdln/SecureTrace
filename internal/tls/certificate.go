package tls

import (
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"github.com/ismailtasdelen/securetrace/pkg/types"
)

// CertificateAnalyzer provides detailed certificate analysis
type CertificateAnalyzer struct{}

// NewCertificateAnalyzer creates a new certificate analyzer
func NewCertificateAnalyzer() *CertificateAnalyzer {
	return &CertificateAnalyzer{}
}

// AnalyzeChain analyzes a certificate chain
func (a *CertificateAnalyzer) AnalyzeChain(certs []*x509.Certificate) []types.CertificateInfo {
	result := make([]types.CertificateInfo, 0, len(certs))
	for _, cert := range certs {
		result = append(result, types.NewCertificateInfo(cert))
	}
	return result
}

// ValidateChain validates a certificate chain
func (a *CertificateAnalyzer) ValidateChain(certs []*x509.Certificate, hostname string) []string {
	issues := make([]string, 0)

	if len(certs) == 0 {
		return []string{"No certificates in chain"}
	}

	// Get the leaf certificate
	leaf := certs[0]

	// Check hostname
	if err := leaf.VerifyHostname(hostname); err != nil {
		issues = append(issues, fmt.Sprintf("Hostname verification failed: %v", err))
	}

	// Check expiration
	now := time.Now()
	if now.Before(leaf.NotBefore) {
		issues = append(issues, "Certificate is not yet valid")
	}
	if now.After(leaf.NotAfter) {
		issues = append(issues, "Certificate has expired")
	}

	// Check key usage
	if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		issues = append(issues, "Certificate missing DigitalSignature key usage")
	}

	// Check extended key usage for server auth
	hasServerAuth := false
	for _, usage := range leaf.ExtKeyUsage {
		if usage == x509.ExtKeyUsageServerAuth {
			hasServerAuth = true
			break
		}
	}
	if !hasServerAuth && len(leaf.ExtKeyUsage) > 0 {
		issues = append(issues, "Certificate missing ServerAuth extended key usage")
	}

	// Check signature algorithm
	weakAlgorithms := []x509.SignatureAlgorithm{
		x509.MD2WithRSA,
		x509.MD5WithRSA,
		x509.SHA1WithRSA,
		x509.DSAWithSHA1,
		x509.ECDSAWithSHA1,
	}
	for _, weak := range weakAlgorithms {
		if leaf.SignatureAlgorithm == weak {
			issues = append(issues, fmt.Sprintf("Weak signature algorithm: %s", leaf.SignatureAlgorithm.String()))
			break
		}
	}

	return issues
}

// GetCertificateDetails returns detailed information about a certificate
func (a *CertificateAnalyzer) GetCertificateDetails(cert *x509.Certificate) map[string]interface{} {
	details := make(map[string]interface{})

	details["subject"] = cert.Subject.String()
	details["issuer"] = cert.Issuer.String()
	details["serial_number"] = cert.SerialNumber.String()
	details["not_before"] = cert.NotBefore
	details["not_after"] = cert.NotAfter
	details["signature_algorithm"] = cert.SignatureAlgorithm.String()
	details["public_key_algorithm"] = cert.PublicKeyAlgorithm.String()
	details["version"] = cert.Version
	details["is_ca"] = cert.IsCA

	if len(cert.DNSNames) > 0 {
		details["dns_names"] = cert.DNSNames
	}
	if len(cert.EmailAddresses) > 0 {
		details["email_addresses"] = cert.EmailAddresses
	}
	if len(cert.IPAddresses) > 0 {
		ips := make([]string, len(cert.IPAddresses))
		for i, ip := range cert.IPAddresses {
			ips[i] = ip.String()
		}
		details["ip_addresses"] = ips
	}
	if len(cert.URIs) > 0 {
		uris := make([]string, len(cert.URIs))
		for i, uri := range cert.URIs {
			uris[i] = uri.String()
		}
		details["uris"] = uris
	}

	// Key usage
	keyUsages := make([]string, 0)
	if cert.KeyUsage&x509.KeyUsageDigitalSignature != 0 {
		keyUsages = append(keyUsages, "DigitalSignature")
	}
	if cert.KeyUsage&x509.KeyUsageKeyEncipherment != 0 {
		keyUsages = append(keyUsages, "KeyEncipherment")
	}
	if cert.KeyUsage&x509.KeyUsageCertSign != 0 {
		keyUsages = append(keyUsages, "CertSign")
	}
	if len(keyUsages) > 0 {
		details["key_usage"] = keyUsages
	}

	// Extended key usage
	extKeyUsages := make([]string, 0)
	for _, usage := range cert.ExtKeyUsage {
		switch usage {
		case x509.ExtKeyUsageServerAuth:
			extKeyUsages = append(extKeyUsages, "ServerAuth")
		case x509.ExtKeyUsageClientAuth:
			extKeyUsages = append(extKeyUsages, "ClientAuth")
		case x509.ExtKeyUsageCodeSigning:
			extKeyUsages = append(extKeyUsages, "CodeSigning")
		case x509.ExtKeyUsageEmailProtection:
			extKeyUsages = append(extKeyUsages, "EmailProtection")
		case x509.ExtKeyUsageOCSPSigning:
			extKeyUsages = append(extKeyUsages, "OCSPSigning")
		}
	}
	if len(extKeyUsages) > 0 {
		details["extended_key_usage"] = extKeyUsages
	}

	// OCSP and CRL
	if len(cert.OCSPServer) > 0 {
		details["ocsp_servers"] = cert.OCSPServer
	}
	if len(cert.CRLDistributionPoints) > 0 {
		details["crl_distribution_points"] = cert.CRLDistributionPoints
	}

	return details
}

// FormatCertificateSummary returns a human-readable summary of a certificate
func (a *CertificateAnalyzer) FormatCertificateSummary(cert *x509.Certificate) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Subject: %s\n", cert.Subject.CommonName))
	sb.WriteString(fmt.Sprintf("Issuer: %s\n", cert.Issuer.CommonName))
	sb.WriteString(fmt.Sprintf("Valid: %s - %s\n",
		cert.NotBefore.Format("2006-01-02"),
		cert.NotAfter.Format("2006-01-02")))

	if len(cert.DNSNames) > 0 {
		sb.WriteString(fmt.Sprintf("SANs: %s\n", strings.Join(cert.DNSNames, ", ")))
	}

	// Days until expiry
	daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)
	if daysLeft < 0 {
		sb.WriteString(fmt.Sprintf("Status: EXPIRED (%d days ago)\n", -daysLeft))
	} else if daysLeft < 30 {
		sb.WriteString(fmt.Sprintf("Status: WARNING (expires in %d days)\n", daysLeft))
	} else {
		sb.WriteString(fmt.Sprintf("Status: Valid (%d days remaining)\n", daysLeft))
	}

	return sb.String()
}

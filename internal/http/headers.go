package http

import (
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/ismailtasdelen/securetrace/pkg/types"
)

// SecurityHeadersAnalyzer analyzes security-related HTTP headers
type SecurityHeadersAnalyzer struct{}

// NewSecurityHeadersAnalyzer creates a new analyzer
func NewSecurityHeadersAnalyzer() *SecurityHeadersAnalyzer {
	return &SecurityHeadersAnalyzer{}
}

// Analyze examines response headers and returns security information
func (a *SecurityHeadersAnalyzer) Analyze(headers http.Header) types.SecurityInfo {
	info := types.SecurityInfo{
		Issues: make([]string, 0),
	}

	// Analyze HSTS
	if hsts := headers.Get("Strict-Transport-Security"); hsts != "" {
		info.HSTS = parseHSTS(hsts)
	} else {
		info.Issues = append(info.Issues, "Missing Strict-Transport-Security header")
	}

	// Content Security Policy
	if csp := headers.Get("Content-Security-Policy"); csp != "" {
		info.ContentSecurityPolicy = csp
	} else {
		info.Issues = append(info.Issues, "Missing Content-Security-Policy header")
	}

	// X-Frame-Options
	if xfo := headers.Get("X-Frame-Options"); xfo != "" {
		info.XFrameOptions = xfo
	} else {
		info.Issues = append(info.Issues, "Missing X-Frame-Options header")
	}

	// X-Content-Type-Options
	if xcto := headers.Get("X-Content-Type-Options"); xcto != "" {
		info.XContentTypeOptions = xcto
		if xcto != "nosniff" {
			info.Issues = append(info.Issues, "X-Content-Type-Options should be 'nosniff'")
		}
	} else {
		info.Issues = append(info.Issues, "Missing X-Content-Type-Options header")
	}

	// X-XSS-Protection (legacy but still relevant)
	if xxss := headers.Get("X-XSS-Protection"); xxss != "" {
		info.XXSSProtection = xxss
	}

	// Referrer-Policy
	if rp := headers.Get("Referrer-Policy"); rp != "" {
		info.ReferrerPolicy = rp
	} else {
		info.Issues = append(info.Issues, "Missing Referrer-Policy header")
	}

	// Permissions-Policy
	if pp := headers.Get("Permissions-Policy"); pp != "" {
		info.PermissionsPolicy = pp
	}

	// Calculate score and grade
	info.Score = a.calculateScore(info)
	info.Grade = a.calculateGrade(info.Score)

	return info
}

// parseHSTS parses the Strict-Transport-Security header
func parseHSTS(value string) *types.HSTSInfo {
	hsts := &types.HSTSInfo{Enabled: true}

	// Parse max-age
	maxAgeRegex := regexp.MustCompile(`max-age=(\d+)`)
	if matches := maxAgeRegex.FindStringSubmatch(value); len(matches) > 1 {
		if age, err := strconv.Atoi(matches[1]); err == nil {
			hsts.MaxAge = age
		}
	}

	// Check for includeSubDomains
	hsts.IncludeSubdomains = strings.Contains(strings.ToLower(value), "includesubdomains")

	// Check for preload
	hsts.Preload = strings.Contains(strings.ToLower(value), "preload")

	return hsts
}

// calculateScore calculates a security score (0-100)
func (a *SecurityHeadersAnalyzer) calculateScore(info types.SecurityInfo) int {
	score := 0
	maxScore := 100

	// HSTS (25 points)
	if info.HSTS != nil && info.HSTS.Enabled {
		score += 15
		if info.HSTS.MaxAge >= 31536000 { // 1 year
			score += 5
		}
		if info.HSTS.IncludeSubdomains {
			score += 3
		}
		if info.HSTS.Preload {
			score += 2
		}
	}

	// CSP (25 points)
	if info.ContentSecurityPolicy != "" {
		score += 25
	}

	// X-Frame-Options (15 points)
	if info.XFrameOptions != "" {
		score += 15
	}

	// X-Content-Type-Options (15 points)
	if info.XContentTypeOptions == "nosniff" {
		score += 15
	}

	// Referrer-Policy (10 points)
	if info.ReferrerPolicy != "" {
		score += 10
	}

	// Permissions-Policy (10 points)
	if info.PermissionsPolicy != "" {
		score += 10
	}

	if score > maxScore {
		score = maxScore
	}

	return score
}

// calculateGrade converts a score to a letter grade
func (a *SecurityHeadersAnalyzer) calculateGrade(score int) string {
	switch {
	case score >= 90:
		return "A+"
	case score >= 80:
		return "A"
	case score >= 70:
		return "B"
	case score >= 60:
		return "C"
	case score >= 50:
		return "D"
	default:
		return "F"
	}
}

// SecurityHeaders contains common security header names
var SecurityHeaders = []string{
	"Strict-Transport-Security",
	"Content-Security-Policy",
	"Content-Security-Policy-Report-Only",
	"X-Frame-Options",
	"X-Content-Type-Options",
	"X-XSS-Protection",
	"Referrer-Policy",
	"Permissions-Policy",
	"Cross-Origin-Embedder-Policy",
	"Cross-Origin-Opener-Policy",
	"Cross-Origin-Resource-Policy",
}

// IsSecurityHeader checks if a header is security-related
func IsSecurityHeader(name string) bool {
	lowerName := strings.ToLower(name)
	for _, h := range SecurityHeaders {
		if strings.ToLower(h) == lowerName {
			return true
		}
	}
	return false
}

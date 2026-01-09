package http

import (
	"crypto/md5"
	"encoding/hex"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/ismailtasdelen/securetrace/pkg/types"
)

// BodyInspector handles response body inspection
type BodyInspector struct {
	maxSize int64
}

// NewBodyInspector creates a new body inspector
func NewBodyInspector(maxSize int64) *BodyInspector {
	if maxSize <= 0 {
		maxSize = 1024 * 1024 // 1MB default
	}
	return &BodyInspector{maxSize: maxSize}
}

// Inspect reads and analyzes the response body
func (b *BodyInspector) Inspect(resp *http.Response) (*types.BodyInfo, []byte, error) {
	if resp.Body == nil {
		return nil, nil, nil
	}

	// Read body with size limit
	limited := io.LimitReader(resp.Body, b.maxSize)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, nil, err
	}

	info := &types.BodyInfo{
		Size:        int64(len(body)),
		ContentType: resp.Header.Get("Content-Type"),
		Encoding:    resp.Header.Get("Content-Encoding"),
	}

	// Parse content type
	if info.ContentType != "" {
		mediaType, _, _ := mime.ParseMediaType(info.ContentType)
		info.ContentType = mediaType
	}

	// Calculate hash
	hash := md5.Sum(body)
	info.Hash = hex.EncodeToString(hash[:])

	// Generate preview for text content
	if isTextContent(info.ContentType) && len(body) > 0 {
		preview := string(body)
		if len(preview) > 500 {
			preview = preview[:500] + "..."
		}
		// Clean up the preview
		preview = strings.ReplaceAll(preview, "\r\n", "\n")
		preview = strings.TrimSpace(preview)
		info.Preview = preview
	}

	return info, body, nil
}

// isTextContent checks if the content type is text-based
func isTextContent(contentType string) bool {
	textTypes := []string{
		"text/",
		"application/json",
		"application/xml",
		"application/javascript",
		"application/x-javascript",
	}

	ct := strings.ToLower(contentType)
	for _, t := range textTypes {
		if strings.HasPrefix(ct, t) {
			return true
		}
	}
	return false
}

// DetectContentType attempts to detect the content type from body
func DetectContentType(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	return http.DetectContentType(body)
}

package plugin

import (
	"context"

	"github.com/ismailtasdelen/securetrace/pkg/types"
)

// Plugin defines the interface that all plugins must implement
type Plugin interface {
	// Name returns the plugin's unique name
	Name() string

	// Version returns the plugin's version
	Version() string

	// Description returns a brief description of what the plugin does
	Description() string

	// Init initializes the plugin with configuration
	Init(config map[string]interface{}) error

	// Close cleans up plugin resources
	Close() error
}

// PreRequestPlugin is called before an HTTP request is made
type PreRequestPlugin interface {
	Plugin
	PreRequest(ctx context.Context, target string, config *types.Config) error
}

// PostResponsePlugin is called after receiving an HTTP response
type PostResponsePlugin interface {
	Plugin
	PostResponse(ctx context.Context, result *types.TraceResult) (*PluginResult, error)
}

// AnalyzerPlugin provides additional analysis capabilities
type AnalyzerPlugin interface {
	Plugin
	Analyze(ctx context.Context, result *types.TraceResult) (*PluginResult, error)
}

// PluginResult represents the output from a plugin
type PluginResult struct {
	PluginName string                 `json:"plugin_name"`
	Success    bool                   `json:"success"`
	Message    string                 `json:"message,omitempty"`
	Data       map[string]interface{} `json:"data,omitempty"`
	Findings   []Finding              `json:"findings,omitempty"`
}

// Finding represents a security finding or observation
type Finding struct {
	Type        string   `json:"type"` // info, warning, vulnerability
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"` // low, medium, high, critical
	Reference   string   `json:"reference,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

// PluginInfo contains metadata about a plugin
type PluginInfo struct {
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	Description  string   `json:"description"`
	Author       string   `json:"author,omitempty"`
	Capabilities []string `json:"capabilities"`
}

// NewPluginResult creates a new plugin result
func NewPluginResult(pluginName string) *PluginResult {
	return &PluginResult{
		PluginName: pluginName,
		Success:    true,
		Data:       make(map[string]interface{}),
		Findings:   make([]Finding, 0),
	}
}

// AddFinding adds a finding to the result
func (r *PluginResult) AddFinding(finding Finding) {
	r.Findings = append(r.Findings, finding)
}

// SetError marks the result as failed with an error message
func (r *PluginResult) SetError(message string) {
	r.Success = false
	r.Message = message
}

// FindingSeverity constants
const (
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

// FindingType constants
const (
	FindingTypeInfo          = "info"
	FindingTypeWarning       = "warning"
	FindingTypeVulnerability = "vulnerability"
)

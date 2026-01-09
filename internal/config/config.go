package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ismailtasdelen/securetrace/pkg/types"
)

// UserAgentProfiles contains predefined user agent strings
var UserAgentProfiles = map[string]string{
	"default": types.AppName + "/" + types.Version,
	"chrome":  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"firefox": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
	"safari":  "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
	"curl":    "curl/8.4.0",
	"wget":    "Wget/1.21.4",
	"bot":     "SecureTraceBot/1.0 (+https://github.com/ismailtasdelen/securetrace)",
}

// Manager handles configuration loading and management
type Manager struct {
	config     *types.Config
	configPath string
}

// NewManager creates a new configuration manager
func NewManager() *Manager {
	return &Manager{
		config: types.DefaultConfig(),
	}
}

// Load loads configuration from file
func (m *Manager) Load(path string) error {
	m.configPath = path

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // Use defaults if file doesn't exist
		}
		return fmt.Errorf("failed to read config file: %w", err)
	}

	var fileConfig struct {
		Timeout         string `json:"timeout"`
		MaxRedirects    int    `json:"max_redirects"`
		UserAgent       string `json:"user_agent"`
		Proxy           string `json:"proxy"`
		FollowRedirects *bool  `json:"follow_redirects"`
		VerifyTLS       *bool  `json:"verify_tls"`
		Verbose         bool   `json:"verbose"`
		OutputFormat    string `json:"output_format"`
		RateLimit       int    `json:"rate_limit"`
		Retries         int    `json:"retries"`
		CacheTTL        string `json:"cache_ttl"`
	}

	if err := json.Unmarshal(data, &fileConfig); err != nil {
		return fmt.Errorf("failed to parse config file: %w", err)
	}

	// Apply file configuration
	if fileConfig.Timeout != "" {
		d, err := time.ParseDuration(fileConfig.Timeout)
		if err == nil {
			m.config.Timeout = d
		}
	}
	if fileConfig.MaxRedirects > 0 {
		m.config.MaxRedirects = fileConfig.MaxRedirects
	}
	if fileConfig.UserAgent != "" {
		m.config.UserAgent = m.ResolveUserAgent(fileConfig.UserAgent)
	}
	if fileConfig.Proxy != "" {
		m.config.Proxy = fileConfig.Proxy
	}
	if fileConfig.FollowRedirects != nil {
		m.config.FollowRedirects = *fileConfig.FollowRedirects
	}
	if fileConfig.VerifyTLS != nil {
		m.config.VerifyTLS = *fileConfig.VerifyTLS
	}
	m.config.Verbose = fileConfig.Verbose
	if fileConfig.OutputFormat != "" {
		m.config.OutputFormat = fileConfig.OutputFormat
	}
	if fileConfig.RateLimit > 0 {
		m.config.RateLimit = fileConfig.RateLimit
	}
	if fileConfig.Retries > 0 {
		m.config.Retries = fileConfig.Retries
	}
	if fileConfig.CacheTTL != "" {
		d, err := time.ParseDuration(fileConfig.CacheTTL)
		if err == nil {
			m.config.CacheTTL = d
		}
	}

	return nil
}

// Save saves current configuration to file
func (m *Manager) Save(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	data, err := json.MarshalIndent(m.config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// Get returns the current configuration
func (m *Manager) Get() *types.Config {
	return m.config
}

// Set updates the configuration
func (m *Manager) Set(config *types.Config) {
	m.config = config
}

// ResolveUserAgent resolves a user agent profile name to its string
func (m *Manager) ResolveUserAgent(name string) string {
	if ua, ok := UserAgentProfiles[name]; ok {
		return ua
	}
	return name // Assume it's a custom user agent string
}

// DefaultConfigPath returns the default configuration file path
func DefaultConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".securetrace.json"
	}
	return filepath.Join(home, ".config", "securetrace", "config.json")
}

// Merge merges command-line flags into the configuration
func (m *Manager) Merge(overrides map[string]interface{}) {
	for key, value := range overrides {
		switch key {
		case "timeout":
			if v, ok := value.(time.Duration); ok {
				m.config.Timeout = v
			}
		case "max_redirects":
			if v, ok := value.(int); ok {
				m.config.MaxRedirects = v
			}
		case "user_agent":
			if v, ok := value.(string); ok && v != "" {
				m.config.UserAgent = m.ResolveUserAgent(v)
			}
		case "proxy":
			if v, ok := value.(string); ok {
				m.config.Proxy = v
			}
		case "follow_redirects":
			if v, ok := value.(bool); ok {
				m.config.FollowRedirects = v
			}
		case "verify_tls":
			if v, ok := value.(bool); ok {
				m.config.VerifyTLS = v
			}
		case "verbose":
			if v, ok := value.(bool); ok {
				m.config.Verbose = v
			}
		case "output_format":
			if v, ok := value.(string); ok && v != "" {
				m.config.OutputFormat = v
			}
		case "rate_limit":
			if v, ok := value.(int); ok {
				m.config.RateLimit = v
			}
		case "retries":
			if v, ok := value.(int); ok {
				m.config.Retries = v
			}
		}
	}
}

package plugin

import (
	"context"
	"fmt"
	"sync"

	"github.com/ismailtasdelen/securetrace/internal/logger"
	"github.com/ismailtasdelen/securetrace/pkg/types"
)

// Manager handles plugin lifecycle and execution
type Manager struct {
	plugins      map[string]Plugin
	preRequest   []PreRequestPlugin
	postResponse []PostResponsePlugin
	analyzers    []AnalyzerPlugin
	log          *logger.Logger
	mu           sync.RWMutex
}

// NewManager creates a new plugin manager
func NewManager() *Manager {
	return &Manager{
		plugins:      make(map[string]Plugin),
		preRequest:   make([]PreRequestPlugin, 0),
		postResponse: make([]PostResponsePlugin, 0),
		analyzers:    make([]AnalyzerPlugin, 0),
		log:          logger.New().WithPrefix("plugin"),
	}
}

// Register adds a plugin to the manager
func (m *Manager) Register(p Plugin) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	name := p.Name()
	if _, exists := m.plugins[name]; exists {
		return fmt.Errorf("plugin %s already registered", name)
	}

	m.plugins[name] = p

	// Categorize by capability
	if pre, ok := p.(PreRequestPlugin); ok {
		m.preRequest = append(m.preRequest, pre)
	}
	if post, ok := p.(PostResponsePlugin); ok {
		m.postResponse = append(m.postResponse, post)
	}
	if analyzer, ok := p.(AnalyzerPlugin); ok {
		m.analyzers = append(m.analyzers, analyzer)
	}

	m.log.Info("Registered plugin: %s v%s", name, p.Version())
	return nil
}

// Unregister removes a plugin from the manager
func (m *Manager) Unregister(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	p, exists := m.plugins[name]
	if !exists {
		return fmt.Errorf("plugin %s not found", name)
	}

	// Clean up
	if err := p.Close(); err != nil {
		m.log.Warn("Error closing plugin %s: %v", name, err)
	}

	delete(m.plugins, name)

	// Remove from capability slices
	m.preRequest = filterPreRequest(m.preRequest, name)
	m.postResponse = filterPostResponse(m.postResponse, name)
	m.analyzers = filterAnalyzers(m.analyzers, name)

	m.log.Info("Unregistered plugin: %s", name)
	return nil
}

// ListPlugins returns information about all registered plugins
func (m *Manager) ListPlugins() []PluginInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	infos := make([]PluginInfo, 0, len(m.plugins))
	for _, p := range m.plugins {
		info := PluginInfo{
			Name:         p.Name(),
			Version:      p.Version(),
			Description:  p.Description(),
			Capabilities: make([]string, 0),
		}

		if _, ok := p.(PreRequestPlugin); ok {
			info.Capabilities = append(info.Capabilities, "pre_request")
		}
		if _, ok := p.(PostResponsePlugin); ok {
			info.Capabilities = append(info.Capabilities, "post_response")
		}
		if _, ok := p.(AnalyzerPlugin); ok {
			info.Capabilities = append(info.Capabilities, "analyzer")
		}

		infos = append(infos, info)
	}

	return infos
}

// RunPreRequest executes all pre-request plugins
func (m *Manager) RunPreRequest(ctx context.Context, target string, config *types.Config) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, p := range m.preRequest {
		if err := p.PreRequest(ctx, target, config); err != nil {
			m.log.Error("PreRequest plugin %s failed: %v", p.Name(), err)
			// Continue with other plugins
		}
	}

	return nil
}

// RunPostResponse executes all post-response plugins
func (m *Manager) RunPostResponse(ctx context.Context, result *types.TraceResult) []*PluginResult {
	m.mu.RLock()
	defer m.mu.RUnlock()

	results := make([]*PluginResult, 0)

	for _, p := range m.postResponse {
		r, err := p.PostResponse(ctx, result)
		if err != nil {
			m.log.Error("PostResponse plugin %s failed: %v", p.Name(), err)
			r = NewPluginResult(p.Name())
			r.SetError(err.Error())
		}
		if r != nil {
			results = append(results, r)
		}
	}

	return results
}

// RunAnalyzers executes all analyzer plugins
func (m *Manager) RunAnalyzers(ctx context.Context, result *types.TraceResult) []*PluginResult {
	m.mu.RLock()
	defer m.mu.RUnlock()

	results := make([]*PluginResult, 0)

	for _, p := range m.analyzers {
		r, err := p.Analyze(ctx, result)
		if err != nil {
			m.log.Error("Analyzer plugin %s failed: %v", p.Name(), err)
			r = NewPluginResult(p.Name())
			r.SetError(err.Error())
		}
		if r != nil {
			results = append(results, r)
		}
	}

	return results
}

// Close shuts down all plugins
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var lastErr error
	for name, p := range m.plugins {
		if err := p.Close(); err != nil {
			m.log.Error("Error closing plugin %s: %v", name, err)
			lastErr = err
		}
	}

	m.plugins = make(map[string]Plugin)
	m.preRequest = nil
	m.postResponse = nil
	m.analyzers = nil

	return lastErr
}

// Helper functions to filter plugin slices
func filterPreRequest(plugins []PreRequestPlugin, name string) []PreRequestPlugin {
	result := make([]PreRequestPlugin, 0, len(plugins))
	for _, p := range plugins {
		if p.Name() != name {
			result = append(result, p)
		}
	}
	return result
}

func filterPostResponse(plugins []PostResponsePlugin, name string) []PostResponsePlugin {
	result := make([]PostResponsePlugin, 0, len(plugins))
	for _, p := range plugins {
		if p.Name() != name {
			result = append(result, p)
		}
	}
	return result
}

func filterAnalyzers(plugins []AnalyzerPlugin, name string) []AnalyzerPlugin {
	result := make([]AnalyzerPlugin, 0, len(plugins))
	for _, p := range plugins {
		if p.Name() != name {
			result = append(result, p)
		}
	}
	return result
}

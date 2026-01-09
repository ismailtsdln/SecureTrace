# Plugin Development Guide

SecureTrace provides an extensible plugin system that allows you to add custom analysis capabilities. This guide explains how to develop and integrate your own plugins.

## Plugin Architecture

Plugins in SecureTrace can hook into three phases of the tracing process:

1. **PreRequest** - Before an HTTP request is made
2. **PostResponse** - After receiving a response
3. **Analyzer** - For additional analysis of trace results

## Plugin Interface

All plugins must implement the base `Plugin` interface:

```go
type Plugin interface {
    Name() string
    Version() string
    Description() string
    Init(config map[string]interface{}) error
    Close() error
}
```

### Optional Interfaces

Depending on when you want your plugin to execute, implement one or more of:

```go
// Called before making a request
type PreRequestPlugin interface {
    Plugin
    PreRequest(ctx context.Context, target string, config *types.Config) error
}

// Called after receiving a response
type PostResponsePlugin interface {
    Plugin
    PostResponse(ctx context.Context, result *types.TraceResult) (*PluginResult, error)
}

// For custom analysis logic
type AnalyzerPlugin interface {
    Plugin
    Analyze(ctx context.Context, result *types.TraceResult) (*PluginResult, error)
}
```

## Creating a Plugin

### Step 1: Create Plugin Structure

```go
package myplugin

import (
    "context"
    "github.com/ismailtasdelen/securetrace/internal/plugin"
    "github.com/ismailtasdelen/securetrace/pkg/types"
)

type MyAnalyzerPlugin struct {
    config map[string]interface{}
}

func New() *MyAnalyzerPlugin {
    return &MyAnalyzerPlugin{}
}
```

### Step 2: Implement Base Interface

```go
func (p *MyAnalyzerPlugin) Name() string {
    return "my-analyzer"
}

func (p *MyAnalyzerPlugin) Version() string {
    return "1.0.0"
}

func (p *MyAnalyzerPlugin) Description() string {
    return "Custom security analyzer for specific checks"
}

func (p *MyAnalyzerPlugin) Init(config map[string]interface{}) error {
    p.config = config
    // Validate configuration
    return nil
}

func (p *MyAnalyzerPlugin) Close() error {
    // Cleanup resources
    return nil
}
```

### Step 3: Implement Analysis Logic

```go
func (p *MyAnalyzerPlugin) Analyze(ctx context.Context, result *types.TraceResult) (*plugin.PluginResult, error) {
    r := plugin.NewPluginResult(p.Name())

    // Example: Check for specific security headers
    if result.Headers.Get("X-Custom-Security") == "" {
        r.AddFinding(plugin.Finding{
            Type:        plugin.FindingTypeWarning,
            Title:       "Missing X-Custom-Security Header",
            Description: "The response is missing the X-Custom-Security header",
            Severity:    plugin.SeverityMedium,
            Remediation: "Add X-Custom-Security header to responses",
        })
    }

    // Add custom data to the result
    r.Data["custom_check"] = "passed"

    return r, nil
}
```

## Plugin Results

Plugins return `PluginResult` which can contain:

### Findings

Security findings with severity levels:

```go
r.AddFinding(plugin.Finding{
    Type:        plugin.FindingTypeVulnerability,
    Title:       "SQL Injection Possible",
    Description: "Input validation appears to be missing",
    Severity:    plugin.SeverityCritical,
    Reference:   "https://owasp.org/www-community/attacks/SQL_Injection",
    Remediation: "Use parameterized queries",
    Tags:        []string{"owasp", "injection"},
})
```

### Severity Levels

- `SeverityLow` - Informational or minor issues
- `SeverityMedium` - Should be addressed
- `SeverityHigh` - Important security issue
- `SeverityCritical` - Critical vulnerability

### Finding Types

- `FindingTypeInfo` - Informational observations
- `FindingTypeWarning` - Potential issues
- `FindingTypeVulnerability` - Security vulnerabilities

## Registering Plugins

Register your plugin with the plugin manager:

```go
import (
    "github.com/ismailtasdelen/securetrace/internal/plugin"
    myplugin "path/to/my/plugin"
)

func main() {
    manager := plugin.NewManager()
    
    // Register plugin
    myPlugin := myplugin.New()
    if err := manager.Register(myPlugin); err != nil {
        log.Fatal(err)
    }
    
    // Later, unregister if needed
    manager.Unregister(myPlugin.Name())
}
```

## Best Practices

1. **Keep plugins focused** - Each plugin should do one thing well
2. **Handle errors gracefully** - Don't panic, return errors
3. **Use context for cancellation** - Respect context cancellation
4. **Clean up resources** - Implement `Close()` properly
5. **Document your plugin** - Provide clear description and usage

## Example Plugins

### SSL Labs Integration

```go
func (p *SSLLabsPlugin) Analyze(ctx context.Context, result *types.TraceResult) (*plugin.PluginResult, error) {
    r := plugin.NewPluginResult(p.Name())

    if result.TLSInfo == nil {
        r.SetError("No TLS connection")
        return r, nil
    }

    // Call SSL Labs API
    grade, err := p.checkSSLLabs(ctx, result.FinalURL)
    if err != nil {
        return nil, err
    }

    r.Data["ssllabs_grade"] = grade
    
    if grade[0] < 'B' {
        r.AddFinding(plugin.Finding{
            Type:     plugin.FindingTypeInfo,
            Title:    "SSL Labs Grade: " + grade,
            Severity: plugin.SeverityLow,
        })
    }

    return r, nil
}
```

### Cookie Security Check

```go
func (p *CookiePlugin) PostResponse(ctx context.Context, result *types.TraceResult) (*plugin.PluginResult, error) {
    r := plugin.NewPluginResult(p.Name())

    cookies := result.Headers.Values("Set-Cookie")
    for _, cookie := range cookies {
        if !strings.Contains(cookie, "Secure") {
            r.AddFinding(plugin.Finding{
                Type:        plugin.FindingTypeWarning,
                Title:       "Cookie without Secure flag",
                Description: "Cookie is missing the Secure attribute",
                Severity:    plugin.SeverityMedium,
            })
        }
        if !strings.Contains(cookie, "HttpOnly") {
            r.AddFinding(plugin.Finding{
                Type:        plugin.FindingTypeWarning,
                Title:       "Cookie without HttpOnly flag",
                Description: "Cookie is accessible via JavaScript",
                Severity:    plugin.SeverityMedium,
            })
        }
    }

    return r, nil
}
```

## Testing Plugins

```go
func TestMyPlugin(t *testing.T) {
    p := myplugin.New()
    
    // Initialize
    err := p.Init(nil)
    if err != nil {
        t.Fatalf("Init failed: %v", err)
    }
    defer p.Close()

    // Create test result
    result := &types.TraceResult{
        URL:        "https://example.com",
        StatusCode: 200,
        Headers:    http.Header{},
    }

    // Run analysis
    ctx := context.Background()
    pluginResult, err := p.Analyze(ctx, result)
    
    if err != nil {
        t.Fatalf("Analyze failed: %v", err)
    }

    // Assert findings
    if len(pluginResult.Findings) == 0 {
        t.Error("Expected findings")
    }
}
```

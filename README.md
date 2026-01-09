# SecureTrace

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go" alt="Go Version">
  <img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License">
  <img src="https://img.shields.io/github/actions/workflow/status/ismailtasdelen/securetrace/ci.yml?branch=main" alt="Build Status">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey" alt="Platform">
</p>

**SecureTrace** is a modern, high-performance HTTP/HTTPS security analysis and profiling tool written in Go. It provides comprehensive request tracing, SSL/TLS handshake analysis, security header inspection, and detailed timing breakdowns.

## ✨ Features

- 🔍 **HTTP/HTTPS Request Tracing** - Detailed timing for DNS, TCP, TLS, and content transfer
- 🔒 **TLS/SSL Analysis** - Certificate inspection, cipher suite evaluation, security grading
- 🛡️ **Security Headers Audit** - HSTS, CSP, X-Frame-Options analysis with scoring
- 📊 **Multiple Output Formats** - JSON, HTML, CSV, and colored terminal output
- 🔄 **Redirect Chain Tracking** - Follow and analyze redirect chains
- ⚡ **Concurrent Scanning** - Scan multiple URLs in parallel
- 🔌 **Plugin System** - Extensible architecture for custom analyzers
- 🎨 **Beautiful Reports** - Professional HTML reports with dark theme

## 🚀 Installation

### Binary Download

Download the latest release for your platform from the [Releases](https://github.com/ismailtasdelen/securetrace/releases) page.

### Build from Source

```bash
# Clone the repository
git clone https://github.com/ismailtasdelen/securetrace.git
cd securetrace

# Build
go build -o securetrace ./cmd/securetrace

# Or install directly
go install github.com/ismailtasdelen/securetrace/cmd/securetrace@latest
```

### Docker

```bash
# Build image
docker build -t securetrace .

# Run
docker run --rm securetrace https://example.com
```

## 📖 Usage

### Basic Trace

```bash
# Trace a single URL
securetrace https://example.com

# With verbose output
securetrace -v https://example.com
```

### Output Formats

```bash
# JSON output
securetrace -o json https://example.com

# Save to file
securetrace -o json -f report.json https://example.com

# HTML report
securetrace -o html -f report.html https://example.com

# CSV for spreadsheets
securetrace -o csv -f results.csv https://example.com
```

### Multiple URLs

```bash
# Scan multiple URLs concurrently
securetrace https://site1.com https://site2.com https://site3.com

# With increased concurrency
securetrace -c 10 https://site1.com https://site2.com https://site3.com
```

### Advanced Options

```bash
# Use custom user agent (or preset: chrome, firefox, safari, curl)
securetrace -A chrome https://example.com

# Use proxy
securetrace -x http://proxy:8080 https://example.com

# Skip TLS verification (for self-signed certs)
securetrace -k https://self-signed.example.com

# Don't follow redirects
securetrace --no-redirect https://example.com

# Custom timeout
securetrace -t 60s https://slow-server.com
```

## 🔧 CLI Options

| Option | Description |
|--------|-------------|
| `-o, --output` | Output format: text, json, html, csv (default: text) |
| `-f, --file` | Write output to file |
| `-A, --user-agent` | User agent string or profile |
| `-t, --timeout` | Request timeout (default: 30s) |
| `-x, --proxy` | Proxy URL (http, https, or socks5) |
| `-c, --concurrency` | Concurrent requests (default: 5) |
| `-r, --retries` | Retry attempts on failure (default: 3) |
| `-k, --insecure` | Skip TLS certificate verification |
| `--no-redirect` | Don't follow redirects |
| `--no-color` | Disable colored output |
| `-v, --verbose` | Enable verbose logging |
| `--config` | Configuration file path |

## 📊 Example Output

### Terminal Output

```
  https://example.com/
  Status: 200

  Timeline:
  DNS Lookup:        ████                                    2.34ms
  TCP Connect:       ██████                                  3.12ms
  TLS Handshake:     ██████████████████                      45.67ms
  Server Wait:       ████████████                            28.91ms
  Content Transfer:  ██                                      1.23ms

  Total:             81.27ms

  TLS Security
  Grade:         A+
  Version:       TLS 1.3
  Cipher:        TLS_AES_256_GCM_SHA384

  Security Headers
  Grade:         A
  Score:         85/100
  Issues:
    • Missing Permissions-Policy header
```

### HTML Report

Generate beautiful, shareable HTML reports with:
- Interactive timeline visualization
- Security score breakdown
- Certificate details
- Full header analysis

```bash
securetrace -o html -f report.html https://example.com
```

## 🔌 Plugin Development

SecureTrace supports custom plugins for extended analysis. Plugins implement the `Plugin` interface:

```go
package main

import (
    "context"
    "github.com/ismailtasdelen/securetrace/internal/plugin"
    "github.com/ismailtasdelen/securetrace/pkg/types"
)

type MyPlugin struct{}

func (p *MyPlugin) Name() string { return "my-plugin" }
func (p *MyPlugin) Version() string { return "1.0.0" }
func (p *MyPlugin) Description() string { return "Custom analyzer" }
func (p *MyPlugin) Init(config map[string]interface{}) error { return nil }
func (p *MyPlugin) Close() error { return nil }

func (p *MyPlugin) Analyze(ctx context.Context, result *types.TraceResult) (*plugin.PluginResult, error) {
    r := plugin.NewPluginResult(p.Name())
    // Your analysis logic here
    return r, nil
}
```

See the [Plugin Development Guide](docs/plugins.md) for more details.

## 🏗️ Project Structure

```
securetrace/
├── cmd/securetrace/    # CLI entry point
├── internal/
│   ├── config/         # Configuration management
│   ├── http/           # HTTP client and header analysis
│   ├── logger/         # Structured logging
│   ├── plugin/         # Plugin system
│   ├── reporter/       # Output formatters (JSON, HTML, CSV)
│   ├── tls/            # TLS/SSL analysis
│   └── tracer/         # Core tracing engine
├── pkg/types/          # Public types and interfaces
├── docs/               # Documentation
└── .github/workflows/  # CI/CD pipelines
```

## 🧪 Testing

```bash
# Run all tests
go test ./...

# With coverage
go test -cover ./...

# Verbose output
go test -v ./...
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Inspired by various HTTP analysis tools
- Built with ❤️ using Go

---

<p align="center">
  Made with ☕ by <a href="https://github.com/ismailtasdelen">Ismail Tasdelen</a>
</p>

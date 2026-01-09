package reporter

import (
	"bytes"
	"fmt"
	"html/template"
	"io"
	"time"

	"github.com/ismailtasdelen/securetrace/pkg/types"
)

// HTMLReporter outputs results as HTML reports
type HTMLReporter struct{}

// NewHTMLReporter creates a new HTML reporter
func NewHTMLReporter() *HTMLReporter {
	return &HTMLReporter{}
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecureTrace Report - {{.URL}}</title>
    <style>
        :root {
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #21262d;
            --text-primary: #c9d1d9;
            --text-secondary: #8b949e;
            --accent-green: #3fb950;
            --accent-red: #f85149;
            --accent-yellow: #d29922;
            --accent-blue: #58a6ff;
            --accent-purple: #a371f7;
            --border-color: #30363d;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Noto Sans', Helvetica, Arial, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 2rem;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        .header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 2rem;
            padding-bottom: 1rem;
            border-bottom: 1px solid var(--border-color);
        }
        .header h1 { font-size: 1.5rem; font-weight: 600; }
        .header .logo { color: var(--accent-blue); font-weight: 700; }
        .timestamp { color: var(--text-secondary); font-size: 0.875rem; }
        .card {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            margin-bottom: 1rem;
            overflow: hidden;
        }
        .card-header {
            background: var(--bg-tertiary);
            padding: 0.75rem 1rem;
            font-weight: 600;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        .card-body { padding: 1rem; }
        .status-badge {
            display: inline-flex;
            align-items: center;
            padding: 0.25rem 0.75rem;
            border-radius: 999px;
            font-weight: 600;
            font-size: 0.875rem;
        }
        .status-2xx { background: rgba(63, 185, 80, 0.2); color: var(--accent-green); }
        .status-3xx { background: rgba(210, 153, 34, 0.2); color: var(--accent-yellow); }
        .status-4xx { background: rgba(248, 81, 73, 0.2); color: var(--accent-red); }
        .status-5xx { background: rgba(163, 113, 247, 0.2); color: var(--accent-purple); }
        .grade {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 2.5rem;
            height: 2.5rem;
            border-radius: 50%;
            font-weight: 700;
            font-size: 1.25rem;
        }
        .grade-a { background: var(--accent-green); color: var(--bg-primary); }
        .grade-b { background: #8cc265; color: var(--bg-primary); }
        .grade-c { background: var(--accent-yellow); color: var(--bg-primary); }
        .grade-d { background: #f0883e; color: var(--bg-primary); }
        .grade-f { background: var(--accent-red); color: var(--bg-primary); }
        .timeline-bar {
            height: 0.5rem;
            border-radius: 4px;
            margin: 0.25rem 0;
        }
        .timeline-item { display: flex; align-items: center; gap: 1rem; margin: 0.5rem 0; }
        .timeline-label { width: 140px; color: var(--text-secondary); font-size: 0.875rem; }
        .timeline-value { font-family: monospace; font-size: 0.875rem; }
        .dns { background: #58a6ff; }
        .tcp { background: #d29922; }
        .tls { background: #a371f7; }
        .wait { background: #3fb950; }
        .transfer { background: #f85149; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 0.5rem; text-align: left; border-bottom: 1px solid var(--border-color); }
        th { color: var(--text-secondary); font-weight: 500; font-size: 0.75rem; text-transform: uppercase; }
        td { font-family: monospace; font-size: 0.875rem; word-break: break-all; }
        .issue { padding: 0.5rem 0.75rem; background: rgba(248, 81, 73, 0.1); border-left: 3px solid var(--accent-red); margin: 0.5rem 0; border-radius: 0 4px 4px 0; }
        .url-display { font-family: monospace; background: var(--bg-tertiary); padding: 0.75rem 1rem; border-radius: 4px; margin: 0.5rem 0; word-break: break-all; }
        .redirect-chain { margin: 0.5rem 0; }
        .redirect-hop { display: flex; align-items: center; gap: 0.5rem; padding: 0.25rem 0; color: var(--text-secondary); font-size: 0.875rem; }
        .redirect-hop .status { font-weight: 600; }
        .section-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1rem; }
        .cert-info { margin-bottom: 1rem; padding-bottom: 1rem; border-bottom: 1px solid var(--border-color); }
        .cert-info:last-child { border-bottom: none; margin-bottom: 0; padding-bottom: 0; }
        .meta-row { display: flex; justify-content: space-between; padding: 0.25rem 0; }
        .meta-label { color: var(--text-secondary); }
        @media (max-width: 768px) {
            body { padding: 1rem; }
            .section-grid { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <h1><span class="logo">SecureTrace</span> Report</h1>
            <span class="timestamp">{{.Timestamp.Format "2006-01-02 15:04:05 MST"}}</span>
        </header>

        <div class="card">
            <div class="card-header">
                <span>Overview</span>
                <span class="status-badge status-{{statusClass .StatusCode}}">{{.StatusCode}}</span>
            </div>
            <div class="card-body">
                <div class="url-display">{{.FinalURL}}</div>
                {{if .Redirects}}
                <div class="redirect-chain">
                    <small style="color: var(--text-secondary);">Redirect chain ({{len .Redirects}} hops):</small>
                    {{range .Redirects}}
                    <div class="redirect-hop">
                        <span class="status">{{.StatusCode}}</span>
                        <span>→</span>
                        <span>{{.URL}}</span>
                    </div>
                    {{end}}
                </div>
                {{end}}
            </div>
        </div>

        <div class="section-grid">
            <div class="card">
                <div class="card-header">⏱ Timeline</div>
                <div class="card-body">
                    {{with .Timeline}}
                    <div class="timeline-item">
                        <span class="timeline-label">DNS Lookup</span>
                        <div class="timeline-bar dns" style="width: {{timelineWidth .DNSLookup.Duration $.Timeline.Total.Duration}}%;"></div>
                        <span class="timeline-value">{{formatDuration .DNSLookup.Duration}}</span>
                    </div>
                    <div class="timeline-item">
                        <span class="timeline-label">TCP Connect</span>
                        <div class="timeline-bar tcp" style="width: {{timelineWidth .TCPConnection.Duration $.Timeline.Total.Duration}}%;"></div>
                        <span class="timeline-value">{{formatDuration .TCPConnection.Duration}}</span>
                    </div>
                    <div class="timeline-item">
                        <span class="timeline-label">TLS Handshake</span>
                        <div class="timeline-bar tls" style="width: {{timelineWidth .TLSHandshake.Duration $.Timeline.Total.Duration}}%;"></div>
                        <span class="timeline-value">{{formatDuration .TLSHandshake.Duration}}</span>
                    </div>
                    <div class="timeline-item">
                        <span class="timeline-label">Server Wait</span>
                        <div class="timeline-bar wait" style="width: {{timelineWidth .ServerProcessing.Duration $.Timeline.Total.Duration}}%;"></div>
                        <span class="timeline-value">{{formatDuration .ServerProcessing.Duration}}</span>
                    </div>
                    <div class="timeline-item">
                        <span class="timeline-label">Content Transfer</span>
                        <div class="timeline-bar transfer" style="width: {{timelineWidth .ContentTransfer.Duration $.Timeline.Total.Duration}}%;"></div>
                        <span class="timeline-value">{{formatDuration .ContentTransfer.Duration}}</span>
                    </div>
                    <hr style="border-color: var(--border-color); margin: 0.5rem 0;">
                    <div class="timeline-item">
                        <span class="timeline-label" style="font-weight: 600;">Total</span>
                        <span class="timeline-value" style="font-weight: 600;">{{formatDuration .Total.Duration}}</span>
                    </div>
                    {{end}}
                </div>
            </div>

            {{if .TLSInfo}}
            <div class="card">
                <div class="card-header">
                    🔒 TLS Security
                    <span class="grade grade-{{gradeClass .TLSInfo.Grade}}">{{.TLSInfo.Grade}}</span>
                </div>
                <div class="card-body">
                    <div class="meta-row"><span class="meta-label">Version</span><span>{{.TLSInfo.Version}}</span></div>
                    <div class="meta-row"><span class="meta-label">Cipher Suite</span><span style="font-size: 0.75rem;">{{.TLSInfo.CipherSuite}}</span></div>
                    {{if .TLSInfo.NegotiatedProtocol}}
                    <div class="meta-row"><span class="meta-label">Protocol</span><span>{{.TLSInfo.NegotiatedProtocol}}</span></div>
                    {{end}}
                    {{if .TLSInfo.Certificates}}
                    <hr style="border-color: var(--border-color); margin: 0.75rem 0;">
                    {{range $i, $cert := .TLSInfo.Certificates}}
                    {{if eq $i 0}}
                    <div class="cert-info">
                        <div class="meta-row"><span class="meta-label">Subject</span><span>{{$cert.Subject}}</span></div>
                        <div class="meta-row"><span class="meta-label">Issuer</span><span>{{$cert.Issuer}}</span></div>
                        <div class="meta-row"><span class="meta-label">Expires</span><span>{{$cert.NotAfter.Format "2006-01-02"}} ({{$cert.DaysUntilExpiry}} days)</span></div>
                    </div>
                    {{end}}
                    {{end}}
                    {{end}}
                </div>
            </div>
            {{end}}
        </div>

        <div class="card">
            <div class="card-header">
                🛡 Security Headers
                <span class="grade grade-{{gradeClass .SecurityInfo.Grade}}">{{.SecurityInfo.Grade}}</span>
                <span style="margin-left: auto; color: var(--text-secondary); font-weight: normal;">Score: {{.SecurityInfo.Score}}/100</span>
            </div>
            <div class="card-body">
                <table>
                    <tr><th>Header</th><th>Value</th></tr>
                    {{if .SecurityInfo.HSTS}}<tr><td>Strict-Transport-Security</td><td>✓ Enabled (max-age={{.SecurityInfo.HSTS.MaxAge}})</td></tr>{{end}}
                    {{if .SecurityInfo.ContentSecurityPolicy}}<tr><td>Content-Security-Policy</td><td style="max-width: 400px; overflow: hidden; text-overflow: ellipsis;">{{truncate .SecurityInfo.ContentSecurityPolicy 80}}</td></tr>{{end}}
                    {{if .SecurityInfo.XFrameOptions}}<tr><td>X-Frame-Options</td><td>{{.SecurityInfo.XFrameOptions}}</td></tr>{{end}}
                    {{if .SecurityInfo.XContentTypeOptions}}<tr><td>X-Content-Type-Options</td><td>{{.SecurityInfo.XContentTypeOptions}}</td></tr>{{end}}
                    {{if .SecurityInfo.ReferrerPolicy}}<tr><td>Referrer-Policy</td><td>{{.SecurityInfo.ReferrerPolicy}}</td></tr>{{end}}
                </table>
                {{if .SecurityInfo.Issues}}
                <div style="margin-top: 1rem;">
                    <small style="color: var(--text-secondary); display: block; margin-bottom: 0.5rem;">Issues Found:</small>
                    {{range .SecurityInfo.Issues}}
                    <div class="issue">{{.}}</div>
                    {{end}}
                </div>
                {{end}}
            </div>
        </div>

        <div class="card">
            <div class="card-header">📋 Response Headers</div>
            <div class="card-body">
                <table>
                    <tr><th>Header</th><th>Value</th></tr>
                    {{range $name, $values := .Headers}}
                    <tr><td>{{$name}}</td><td>{{index $values 0}}</td></tr>
                    {{end}}
                </table>
            </div>
        </div>

        <footer style="text-align: center; color: var(--text-secondary); margin-top: 2rem; padding-top: 1rem; border-top: 1px solid var(--border-color);">
            Generated by SecureTrace v{{version}}
        </footer>
    </div>
</body>
</html>`

// Format formats a trace result to HTML
func (r *HTMLReporter) Format(result *types.TraceResult) ([]byte, error) {
	funcs := template.FuncMap{
		"statusClass": func(status int) string {
			switch {
			case status >= 200 && status < 300:
				return "2xx"
			case status >= 300 && status < 400:
				return "3xx"
			case status >= 400 && status < 500:
				return "4xx"
			default:
				return "5xx"
			}
		},
		"gradeClass": func(grade string) string {
			switch grade {
			case "A+", "A":
				return "a"
			case "B":
				return "b"
			case "C":
				return "c"
			case "D":
				return "d"
			default:
				return "f"
			}
		},
		"formatDuration": func(d time.Duration) string {
			if d < time.Millisecond {
				return fmt.Sprintf("%.2fµs", float64(d.Microseconds()))
			}
			if d < time.Second {
				return fmt.Sprintf("%.2fms", float64(d.Microseconds())/1000)
			}
			return fmt.Sprintf("%.2fs", d.Seconds())
		},
		"timelineWidth": func(d, total time.Duration) float64 {
			if total == 0 {
				return 0
			}
			w := float64(d) / float64(total) * 100
			if w < 2 && d > 0 {
				w = 2
			}
			return w
		},
		"truncate": func(s string, maxLen int) string {
			if len(s) <= maxLen {
				return s
			}
			return s[:maxLen] + "..."
		},
		"version": func() string {
			return types.Version
		},
	}

	tmpl, err := template.New("report").Funcs(funcs).Parse(htmlTemplate)
	if err != nil {
		return nil, fmt.Errorf("failed to parse template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, result); err != nil {
		return nil, fmt.Errorf("failed to execute template: %w", err)
	}

	return buf.Bytes(), nil
}

// FormatScan formats a scan result to HTML
func (r *HTMLReporter) FormatScan(result *types.ScanResult) ([]byte, error) {
	// For scan results, generate a summary page
	// This could be expanded with a more detailed template
	var buf bytes.Buffer
	buf.WriteString("<!DOCTYPE html><html><head><title>SecureTrace Scan Report</title></head><body>")
	buf.WriteString("<h1>Scan Results</h1>")
	buf.WriteString(fmt.Sprintf("<p>Scanned %d targets in %s</p>", result.Summary.TotalTargets, result.Duration.Duration))
	buf.WriteString(fmt.Sprintf("<p>Successful: %d, Failed: %d</p>", result.Summary.Successful, result.Summary.Failed))
	buf.WriteString("</body></html>")
	return buf.Bytes(), nil
}

// Write writes HTML output to a writer
func (r *HTMLReporter) Write(w io.Writer, result *types.TraceResult) error {
	data, err := r.Format(result)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// WriteScan writes HTML scan output to a writer
func (r *HTMLReporter) WriteScan(w io.Writer, result *types.ScanResult) error {
	data, err := r.FormatScan(result)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// ContentType returns the HTML MIME type
func (r *HTMLReporter) ContentType() string {
	return "text/html"
}

// Extension returns the HTML file extension
func (r *HTMLReporter) Extension() string {
	return ".html"
}

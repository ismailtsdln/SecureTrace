package reporter

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/ismailtasdelen/securetrace/internal/tracer"
	"github.com/ismailtasdelen/securetrace/pkg/types"
)

// TextReporter outputs results in human-readable text format
type TextReporter struct {
	colored   bool
	formatter *tracer.TimelineFormatter
}

// NewTextReporter creates a new text reporter
func NewTextReporter(colored bool) *TextReporter {
	return &TextReporter{
		colored:   colored,
		formatter: tracer.NewTimelineFormatter(colored),
	}
}

// ANSI color codes
const (
	colorReset  = "\033[0m"
	colorBold   = "\033[1m"
	colorDim    = "\033[90m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorCyan   = "\033[36m"
)

// Format formats a trace result to text
func (r *TextReporter) Format(result *types.TraceResult) ([]byte, error) {
	var buf bytes.Buffer
	r.writeResult(&buf, result)
	return buf.Bytes(), nil
}

// FormatScan formats a scan result to text
func (r *TextReporter) FormatScan(result *types.ScanResult) ([]byte, error) {
	var buf bytes.Buffer

	// Header
	r.writeLine(&buf, "")
	r.writeBanner(&buf, "SecureTrace Scan Report")
	r.writeLine(&buf, "")

	// Summary
	r.writeSection(&buf, "Summary")
	r.writeField(&buf, "Targets", fmt.Sprintf("%d", result.Summary.TotalTargets))
	r.writeField(&buf, "Successful", fmt.Sprintf("%d", result.Summary.Successful))
	r.writeField(&buf, "Failed", fmt.Sprintf("%d", result.Summary.Failed))
	r.writeField(&buf, "TLS Enabled", fmt.Sprintf("%d", result.Summary.TLSEnabled))
	r.writeField(&buf, "With Issues", fmt.Sprintf("%d", result.Summary.SecurityIssues))
	r.writeField(&buf, "Duration", result.Duration.Duration.String())
	r.writeLine(&buf, "")

	// Individual results
	for i, res := range result.Results {
		r.writeLine(&buf, fmt.Sprintf("─── Target %d/%d ───", i+1, len(result.Results)))
		r.writeResult(&buf, &res)
		r.writeLine(&buf, "")
	}

	return buf.Bytes(), nil
}

// writeResult writes a single trace result
func (r *TextReporter) writeResult(w *bytes.Buffer, result *types.TraceResult) {
	// URL and status
	r.writeLine(w, "")
	statusColor := r.getStatusColor(result.StatusCode)
	if r.colored {
		r.writeLine(w, fmt.Sprintf("  %s%s%s", colorBold, result.FinalURL, colorReset))
		r.writeLine(w, fmt.Sprintf("  Status: %s%d%s", statusColor, result.StatusCode, colorReset))
	} else {
		r.writeLine(w, fmt.Sprintf("  %s", result.FinalURL))
		r.writeLine(w, fmt.Sprintf("  Status: %d", result.StatusCode))
	}

	// Error if present
	if result.Error != "" {
		if r.colored {
			r.writeLine(w, fmt.Sprintf("  %sError: %s%s", colorRed, result.Error, colorReset))
		} else {
			r.writeLine(w, fmt.Sprintf("  Error: %s", result.Error))
		}
		return
	}

	// Redirects
	if len(result.Redirects) > 0 {
		w.WriteString(r.formatter.FormatRedirectChain(result.Redirects))
	}

	// Timeline
	w.WriteString(r.formatter.FormatTimeline(result.Timeline))

	// TLS Info
	if result.TLSInfo != nil {
		r.writeLine(w, "")
		r.writeSection(w, "TLS Security")
		r.writeGradedField(w, "Grade", result.TLSInfo.Grade)
		r.writeField(w, "Version", result.TLSInfo.Version)
		r.writeField(w, "Cipher", result.TLSInfo.CipherSuite)
		if len(result.TLSInfo.Certificates) > 0 {
			cert := result.TLSInfo.Certificates[0]
			r.writeField(w, "Certificate", cert.Subject)
			r.writeField(w, "Expires", fmt.Sprintf("%s (%d days)",
				cert.NotAfter.Format("2006-01-02"), cert.DaysUntilExpiry))
		}
	}

	// Security Headers
	r.writeLine(w, "")
	r.writeSection(w, "Security Headers")
	r.writeGradedField(w, "Grade", result.SecurityInfo.Grade)
	r.writeField(w, "Score", fmt.Sprintf("%d/100", result.SecurityInfo.Score))

	if len(result.SecurityInfo.Issues) > 0 {
		r.writeLine(w, "  Issues:")
		for _, issue := range result.SecurityInfo.Issues {
			if r.colored {
				r.writeLine(w, fmt.Sprintf("    %s• %s%s", colorYellow, issue, colorReset))
			} else {
				r.writeLine(w, fmt.Sprintf("    • %s", issue))
			}
		}
	}

	// Body info
	if result.Body != nil {
		r.writeLine(w, "")
		r.writeSection(w, "Response Body")
		r.writeField(w, "Size", formatBytes(result.Body.Size))
		r.writeField(w, "Content-Type", result.Body.ContentType)
		if result.Body.Encoding != "" {
			r.writeField(w, "Encoding", result.Body.Encoding)
		}
	}
}

func (r *TextReporter) writeLine(w *bytes.Buffer, line string) {
	w.WriteString(line)
	w.WriteString("\n")
}

func (r *TextReporter) writeBanner(w *bytes.Buffer, text string) {
	line := strings.Repeat("═", len(text)+4)
	if r.colored {
		w.WriteString(fmt.Sprintf("%s╔%s╗%s\n", colorCyan, line, colorReset))
		w.WriteString(fmt.Sprintf("%s║%s  %s  %s║%s\n", colorCyan, colorReset, text, colorCyan, colorReset))
		w.WriteString(fmt.Sprintf("%s╚%s╝%s\n", colorCyan, line, colorReset))
	} else {
		w.WriteString(fmt.Sprintf("╔%s╗\n", line))
		w.WriteString(fmt.Sprintf("║  %s  ║\n", text))
		w.WriteString(fmt.Sprintf("╚%s╝\n", line))
	}
}

func (r *TextReporter) writeSection(w *bytes.Buffer, title string) {
	if r.colored {
		r.writeLine(w, fmt.Sprintf("  %s%s%s", colorBold+colorBlue, title, colorReset))
	} else {
		r.writeLine(w, fmt.Sprintf("  [%s]", title))
	}
}

func (r *TextReporter) writeField(w *bytes.Buffer, name, value string) {
	if r.colored {
		r.writeLine(w, fmt.Sprintf("  %s%-14s%s %s", colorDim, name+":", colorReset, value))
	} else {
		r.writeLine(w, fmt.Sprintf("  %-14s %s", name+":", value))
	}
}

func (r *TextReporter) writeGradedField(w *bytes.Buffer, name, grade string) {
	gradeColor := r.getGradeColor(grade)
	if r.colored {
		r.writeLine(w, fmt.Sprintf("  %s%-14s%s %s%s%s", colorDim, name+":", colorReset, gradeColor, grade, colorReset))
	} else {
		r.writeLine(w, fmt.Sprintf("  %-14s %s", name+":", grade))
	}
}

func (r *TextReporter) getStatusColor(status int) string {
	if !r.colored {
		return ""
	}
	switch {
	case status >= 200 && status < 300:
		return colorGreen
	case status >= 300 && status < 400:
		return colorYellow
	case status >= 400:
		return colorRed
	default:
		return colorReset
	}
}

func (r *TextReporter) getGradeColor(grade string) string {
	if !r.colored {
		return ""
	}
	switch grade {
	case "A+", "A":
		return colorGreen
	case "B":
		return colorCyan
	case "C":
		return colorYellow
	default:
		return colorRed
	}
}

// Write writes text output to a writer
func (r *TextReporter) Write(w io.Writer, result *types.TraceResult) error {
	data, err := r.Format(result)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// WriteScan writes text scan output to a writer
func (r *TextReporter) WriteScan(w io.Writer, result *types.ScanResult) error {
	data, err := r.FormatScan(result)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// ContentType returns the text MIME type
func (r *TextReporter) ContentType() string {
	return "text/plain"
}

// Extension returns the text file extension
func (r *TextReporter) Extension() string {
	return ".txt"
}

// formatBytes formats bytes in human-readable form
func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// formatDurationText formats duration for text output
func formatDurationText(d time.Duration) string {
	if d < time.Millisecond {
		return fmt.Sprintf("%.2fµs", float64(d.Microseconds()))
	}
	if d < time.Second {
		return fmt.Sprintf("%.2fms", float64(d.Microseconds())/1000)
	}
	return fmt.Sprintf("%.2fs", d.Seconds())
}

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
	colorReset   = "\033[0m"
	colorBold    = "\033[1m"
	colorDim     = "\033[2m"
	colorItalic  = "\033[3m"
	colorRed     = "\033[31m"
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorBlue    = "\033[34m"
	colorMagenta = "\033[35m"
	colorCyan    = "\033[36m"
	colorWhite   = "\033[37m"
	colorBgGreen = "\033[42m"
	colorBgRed   = "\033[41m"
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
	r.writeScanBanner(&buf)
	r.writeLine(&buf, "")

	// Summary Card
	r.writeSummaryCard(&buf, result)
	r.writeLine(&buf, "")

	// Individual results
	for i, res := range result.Results {
		r.writeDivider(&buf, fmt.Sprintf("Target %d/%d", i+1, len(result.Results)))
		r.writeResult(&buf, &res)
		r.writeLine(&buf, "")
	}

	return buf.Bytes(), nil
}

func (r *TextReporter) writeScanBanner(w *bytes.Buffer) {
	if r.colored {
		w.WriteString(fmt.Sprintf(`
  %s╔══════════════════════════════════════════════════╗%s
  %s║%s   %s🔍 SecureTrace Scan Report%s                      %s║%s
  %s╚══════════════════════════════════════════════════╝%s
`, colorCyan, colorReset, colorCyan, colorReset, colorBold, colorReset, colorCyan, colorReset, colorCyan, colorReset))
	} else {
		w.WriteString(`
  ╔══════════════════════════════════════════════════╗
  ║   SecureTrace Scan Report                        ║
  ╚══════════════════════════════════════════════════╝
`)
	}
}

func (r *TextReporter) writeSummaryCard(w *bytes.Buffer, result *types.ScanResult) {
	s := result.Summary

	if r.colored {
		w.WriteString(fmt.Sprintf("  %s📊 Summary%s\n", colorBold+colorBlue, colorReset))
		w.WriteString(fmt.Sprintf("  %s┌────────────────────────────────────────────────┐%s\n", colorDim, colorReset))
		w.WriteString(fmt.Sprintf("  %s│%s  🎯 Total Targets:    %s%-25d%s %s│%s\n", colorDim, colorReset, colorBold, s.TotalTargets, colorReset, colorDim, colorReset))
		w.WriteString(fmt.Sprintf("  %s│%s  %s✓%s  Successful:       %s%-25d%s %s│%s\n", colorDim, colorReset, colorGreen, colorReset, colorGreen, s.Successful, colorReset, colorDim, colorReset))
		w.WriteString(fmt.Sprintf("  %s│%s  %s✗%s  Failed:           %s%-25d%s %s│%s\n", colorDim, colorReset, colorRed, colorReset, colorRed, s.Failed, colorReset, colorDim, colorReset))
		w.WriteString(fmt.Sprintf("  %s│%s  🔒 TLS Enabled:      %-25d %s│%s\n", colorDim, colorReset, s.TLSEnabled, colorDim, colorReset))
		w.WriteString(fmt.Sprintf("  %s│%s  %s⚠%s  Security Issues:  %s%-25d%s %s│%s\n", colorDim, colorReset, colorYellow, colorReset, colorYellow, s.SecurityIssues, colorReset, colorDim, colorReset))
		w.WriteString(fmt.Sprintf("  %s│%s  ⏱️  Duration:         %-25s %s│%s\n", colorDim, colorReset, result.Duration.Duration.String(), colorDim, colorReset))
		w.WriteString(fmt.Sprintf("  %s└────────────────────────────────────────────────┘%s\n", colorDim, colorReset))
	} else {
		w.WriteString("  Summary\n")
		w.WriteString("  ┌────────────────────────────────────────────────┐\n")
		w.WriteString(fmt.Sprintf("  │  Total Targets:    %-25d │\n", s.TotalTargets))
		w.WriteString(fmt.Sprintf("  │  Successful:       %-25d │\n", s.Successful))
		w.WriteString(fmt.Sprintf("  │  Failed:           %-25d │\n", s.Failed))
		w.WriteString(fmt.Sprintf("  │  TLS Enabled:      %-25d │\n", s.TLSEnabled))
		w.WriteString(fmt.Sprintf("  │  Security Issues:  %-25d │\n", s.SecurityIssues))
		w.WriteString(fmt.Sprintf("  │  Duration:         %-25s │\n", result.Duration.Duration.String()))
		w.WriteString("  └────────────────────────────────────────────────┘\n")
	}
}

func (r *TextReporter) writeDivider(w *bytes.Buffer, title string) {
	if r.colored {
		padding := 50 - len(title) - 6
		if padding < 0 {
			padding = 0
		}
		w.WriteString(fmt.Sprintf("\n  %s───── %s%s%s %s%s%s\n",
			colorDim, colorReset, colorBold+colorCyan, title, colorReset, colorDim, strings.Repeat("─", padding)+colorReset))
	} else {
		padding := 50 - len(title) - 6
		if padding < 0 {
			padding = 0
		}
		w.WriteString(fmt.Sprintf("\n  ───── %s %s\n", title, strings.Repeat("─", padding)))
	}
}

// writeResult writes a single trace result
func (r *TextReporter) writeResult(w *bytes.Buffer, result *types.TraceResult) {
	r.writeLine(w, "")

	// URL Card Header
	statusIcon := r.getStatusIcon(result.StatusCode)
	statusColor := r.getStatusColor(result.StatusCode)

	if r.colored {
		w.WriteString(fmt.Sprintf("  %s┌───────────────────────────────────────────────────────────────┐%s\n", colorDim, colorReset))
		w.WriteString(fmt.Sprintf("  %s│%s %s %s%-58s%s %s│%s\n", colorDim, colorReset, statusIcon, colorBold, truncateStr(result.FinalURL, 58), colorReset, colorDim, colorReset))
		w.WriteString(fmt.Sprintf("  %s│%s  Status: %s%d%s %s%s%s %s│%s\n", colorDim, colorReset, statusColor+colorBold, result.StatusCode, colorReset, colorDim, strings.Repeat(" ", 47), colorReset, colorDim, colorReset))
		w.WriteString(fmt.Sprintf("  %s└───────────────────────────────────────────────────────────────┘%s\n", colorDim, colorReset))
	} else {
		w.WriteString("  ┌───────────────────────────────────────────────────────────────┐\n")
		w.WriteString(fmt.Sprintf("  │ %s%-60s │\n", statusIcon+" ", truncateStr(result.FinalURL, 58)))
		w.WriteString(fmt.Sprintf("  │ Status: %-55d │\n", result.StatusCode))
		w.WriteString("  └───────────────────────────────────────────────────────────────┘\n")
	}

	// Error if present
	if result.Error != "" {
		if r.colored {
			w.WriteString(fmt.Sprintf("\n  %s❌ Error:%s %s%s%s\n", colorRed+colorBold, colorReset, colorRed, result.Error, colorReset))
		} else {
			w.WriteString(fmt.Sprintf("\n  Error: %s\n", result.Error))
		}
		return
	}

	// Redirects
	if len(result.Redirects) > 0 {
		r.writeRedirectChain(w, result.Redirects)
	}

	// Timeline
	r.writeTimeline(w, result.Timeline)

	// TLS Info
	if result.TLSInfo != nil {
		r.writeTLSCard(w, result.TLSInfo)
	}

	// Security Headers
	r.writeSecurityCard(w, result.SecurityInfo)

	// Body info
	if result.Body != nil {
		r.writeBodyInfo(w, result.Body)
	}
}

func (r *TextReporter) writeRedirectChain(w *bytes.Buffer, redirects []types.RedirectHop) {
	r.writeLine(w, "")
	if r.colored {
		r.writeLine(w, fmt.Sprintf("  %s🔄 Redirect Chain%s (%d hops)", colorBold+colorYellow, colorReset, len(redirects)))
	} else {
		r.writeLine(w, fmt.Sprintf("  Redirect Chain (%d hops)", len(redirects)))
	}

	for i, hop := range redirects {
		arrow := "├─"
		if i == len(redirects)-1 {
			arrow = "└─"
		}

		if r.colored {
			statusColor := r.getStatusColor(hop.StatusCode)
			r.writeLine(w, fmt.Sprintf("  %s%s%s %s%d%s → %s", colorDim, arrow, colorReset, statusColor, hop.StatusCode, colorReset, truncateStr(hop.URL, 50)))
		} else {
			r.writeLine(w, fmt.Sprintf("  %s %d → %s", arrow, hop.StatusCode, truncateStr(hop.URL, 50)))
		}
	}
}

func (r *TextReporter) writeTimeline(w *bytes.Buffer, timeline types.Timeline) {
	r.writeLine(w, "")
	if r.colored {
		r.writeLine(w, fmt.Sprintf("  %s⏱️  Timeline%s", colorBold+colorCyan, colorReset))
	} else {
		r.writeLine(w, "  Timeline")
	}

	phases := []struct {
		name     string
		duration time.Duration
		icon     string
		color    string
	}{
		{"DNS Lookup", timeline.DNSLookup.Duration, "🔍", colorBlue},
		{"TCP Connect", timeline.TCPConnection.Duration, "🔌", colorYellow},
		{"TLS Handshake", timeline.TLSHandshake.Duration, "🔒", colorMagenta},
		{"Server Wait", timeline.ServerProcessing.Duration, "⏳", colorCyan},
		{"Transfer", timeline.ContentTransfer.Duration, "📥", colorGreen},
	}

	total := timeline.Total.Duration
	if total == 0 {
		for _, p := range phases {
			total += p.duration
		}
	}

	for _, phase := range phases {
		if phase.duration == 0 {
			continue
		}

		ratio := float64(phase.duration) / float64(total)
		barWidth := int(ratio * 30)
		if barWidth < 1 && phase.duration > 0 {
			barWidth = 1
		}

		bar := strings.Repeat("█", barWidth)
		padding := strings.Repeat(" ", 30-barWidth)

		if r.colored {
			r.writeLine(w, fmt.Sprintf("  %s %-14s %s%s%s%s %s",
				phase.icon, phase.name+":", phase.color, bar, colorReset, padding, formatDurationText(phase.duration)))
		} else {
			r.writeLine(w, fmt.Sprintf("  %s %-14s %s%s %s",
				phase.icon, phase.name+":", bar, padding, formatDurationText(phase.duration)))
		}
	}

	// Total
	if r.colored {
		r.writeLine(w, fmt.Sprintf("  %s──────────────────────────────────────────────────%s", colorDim, colorReset))
		r.writeLine(w, fmt.Sprintf("  %s⚡ Total:%s          %s%s%s", colorBold, colorReset, colorBold+colorGreen, formatDurationText(total), colorReset))
	} else {
		r.writeLine(w, "  ──────────────────────────────────────────────────")
		r.writeLine(w, fmt.Sprintf("  Total:           %s", formatDurationText(total)))
	}
}

func (r *TextReporter) writeTLSCard(w *bytes.Buffer, tls *types.TLSInfo) {
	r.writeLine(w, "")
	gradeColor := r.getGradeColor(tls.Grade)
	gradeBg := r.getGradeBg(tls.Grade)

	if r.colored {
		r.writeLine(w, fmt.Sprintf("  %s🔒 TLS Security%s", colorBold+colorMagenta, colorReset))
		r.writeLine(w, fmt.Sprintf("  ┌─────────────────────────────────────────────────┐"))
		r.writeLine(w, fmt.Sprintf("  │ Grade: %s %s %s                                     │", gradeBg+colorBold, tls.Grade, colorReset))
		r.writeLine(w, fmt.Sprintf("  │ %sVersion:%s    %s%-38s%s│", colorDim, colorReset, gradeColor, tls.Version, colorReset))
		r.writeLine(w, fmt.Sprintf("  │ %sCipher:%s     %-38s │", colorDim, colorReset, truncateStr(tls.CipherSuite, 38)))

		if len(tls.Certificates) > 0 {
			cert := tls.Certificates[0]
			expiryColor := colorGreen
			if cert.DaysUntilExpiry < 30 {
				expiryColor = colorRed
			} else if cert.DaysUntilExpiry < 90 {
				expiryColor = colorYellow
			}
			r.writeLine(w, fmt.Sprintf("  │ %sSubject:%s    %-38s │", colorDim, colorReset, truncateStr(cert.Subject, 38)))
			r.writeLine(w, fmt.Sprintf("  │ %sExpires:%s    %s%s (%d days)%s%s │", colorDim, colorReset, expiryColor, cert.NotAfter.Format("2006-01-02"), cert.DaysUntilExpiry, colorReset, strings.Repeat(" ", 20)))
		}
		r.writeLine(w, "  └─────────────────────────────────────────────────┘")
	} else {
		r.writeLine(w, "  TLS Security")
		r.writeLine(w, fmt.Sprintf("  Grade:     %s", tls.Grade))
		r.writeLine(w, fmt.Sprintf("  Version:   %s", tls.Version))
		r.writeLine(w, fmt.Sprintf("  Cipher:    %s", tls.CipherSuite))
	}
}

func (r *TextReporter) writeSecurityCard(w *bytes.Buffer, sec types.SecurityInfo) {
	r.writeLine(w, "")
	gradeColor := r.getGradeColor(sec.Grade)
	gradeBg := r.getGradeBg(sec.Grade)

	if r.colored {
		r.writeLine(w, fmt.Sprintf("  %s🛡️  Security Headers%s", colorBold+colorBlue, colorReset))
		r.writeLine(w, fmt.Sprintf("  ┌─────────────────────────────────────────────────┐"))
		r.writeLine(w, fmt.Sprintf("  │ Grade: %s %s %s    Score: %s%d/100%s                    │", gradeBg+colorBold, sec.Grade, colorReset, gradeColor, sec.Score, colorReset))
		r.writeLine(w, "  └─────────────────────────────────────────────────┘")

		if len(sec.Issues) > 0 {
			r.writeLine(w, fmt.Sprintf("  %s⚠️  Issues Found:%s", colorYellow, colorReset))
			for _, issue := range sec.Issues {
				r.writeLine(w, fmt.Sprintf("  %s  • %s%s", colorDim, colorReset+colorYellow, issue+colorReset))
			}
		} else {
			r.writeLine(w, fmt.Sprintf("  %s✓ No security issues found%s", colorGreen, colorReset))
		}
	} else {
		r.writeLine(w, "  Security Headers")
		r.writeLine(w, fmt.Sprintf("  Grade: %s    Score: %d/100", sec.Grade, sec.Score))
		if len(sec.Issues) > 0 {
			r.writeLine(w, "  Issues:")
			for _, issue := range sec.Issues {
				r.writeLine(w, fmt.Sprintf("    • %s", issue))
			}
		}
	}
}

func (r *TextReporter) writeBodyInfo(w *bytes.Buffer, body *types.BodyInfo) {
	r.writeLine(w, "")
	if r.colored {
		r.writeLine(w, fmt.Sprintf("  %s📄 Response Body%s", colorBold+colorCyan, colorReset))
		r.writeLine(w, fmt.Sprintf("  %sSize:%s        %s", colorDim, colorReset, formatBytes(body.Size)))
		r.writeLine(w, fmt.Sprintf("  %sContent-Type:%s %s", colorDim, colorReset, body.ContentType))
	} else {
		r.writeLine(w, "  Response Body")
		r.writeLine(w, fmt.Sprintf("  Size:         %s", formatBytes(body.Size)))
		r.writeLine(w, fmt.Sprintf("  Content-Type: %s", body.ContentType))
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

func (r *TextReporter) getStatusIcon(status int) string {
	switch {
	case status >= 200 && status < 300:
		return "✓"
	case status >= 300 && status < 400:
		return "→"
	case status >= 400 && status < 500:
		return "✗"
	case status >= 500:
		return "⚠"
	default:
		return "?"
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

func (r *TextReporter) getGradeBg(grade string) string {
	if !r.colored {
		return ""
	}
	switch grade {
	case "A+", "A":
		return colorBgGreen + colorWhite
	default:
		return colorBgRed + colorWhite
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

// truncateStr truncates a string to maxLen
func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

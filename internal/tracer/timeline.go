package tracer

import (
	"fmt"
	"strings"
	"time"

	"github.com/ismailtasdelen/securetrace/pkg/types"
)

// TimelineFormatter generates visual timeline representations
type TimelineFormatter struct {
	colored bool
}

// NewTimelineFormatter creates a new timeline formatter
func NewTimelineFormatter(colored bool) *TimelineFormatter {
	return &TimelineFormatter{colored: colored}
}

// FormatTimeline generates a visual timeline string
func (f *TimelineFormatter) FormatTimeline(timeline types.Timeline) string {
	var sb strings.Builder

	phases := []struct {
		name     string
		duration time.Duration
		color    string
	}{
		{"DNS Lookup", timeline.DNSLookup.Duration, "\033[36m"},               // Cyan
		{"TCP Connect", timeline.TCPConnection.Duration, "\033[33m"},          // Yellow
		{"TLS Handshake", timeline.TLSHandshake.Duration, "\033[35m"},         // Magenta
		{"Server Processing", timeline.ServerProcessing.Duration, "\033[34m"}, // Blue
		{"Content Transfer", timeline.ContentTransfer.Duration, "\033[32m"},   // Green
	}

	total := timeline.Total.Duration
	if total == 0 {
		for _, p := range phases {
			total += p.duration
		}
	}

	sb.WriteString("\n")
	sb.WriteString("  Timeline:\n")

	// Calculate bar widths (max 50 chars)
	maxBarWidth := 50
	for _, phase := range phases {
		if phase.duration == 0 {
			continue
		}

		ratio := float64(phase.duration) / float64(total)
		barWidth := int(ratio * float64(maxBarWidth))
		if barWidth < 1 && phase.duration > 0 {
			barWidth = 1
		}

		bar := strings.Repeat("█", barWidth)
		padding := strings.Repeat(" ", maxBarWidth-barWidth)

		if f.colored {
			sb.WriteString(fmt.Sprintf("  %s%-18s%s %s%s%s %s\n",
				"\033[90m", phase.name+":", "\033[0m",
				phase.color, bar, "\033[0m"+padding,
				formatDuration(phase.duration)))
		} else {
			sb.WriteString(fmt.Sprintf("  %-18s %s%s %s\n",
				phase.name+":", bar, padding, formatDuration(phase.duration)))
		}
	}

	sb.WriteString(fmt.Sprintf("\n  %-18s %s\n", "Total:", formatDuration(total)))

	return sb.String()
}

// FormatRedirectChain generates a visual redirect chain
func (f *TimelineFormatter) FormatRedirectChain(redirects []types.RedirectHop) string {
	if len(redirects) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("\n  Redirect Chain:\n")

	for i, hop := range redirects {
		arrow := "├─"
		if i == len(redirects)-1 {
			arrow = "└─"
		}

		statusColor := f.getStatusColor(hop.StatusCode)
		if f.colored {
			sb.WriteString(fmt.Sprintf("  %s %s%d%s %s (%s)\n",
				arrow, statusColor, hop.StatusCode, "\033[0m",
				truncateURL(hop.URL, 60),
				formatDuration(hop.Duration.Duration)))
		} else {
			sb.WriteString(fmt.Sprintf("  %s %d %s (%s)\n",
				arrow, hop.StatusCode,
				truncateURL(hop.URL, 60),
				formatDuration(hop.Duration.Duration)))
		}
	}

	return sb.String()
}

// getStatusColor returns ANSI color code for status codes
func (f *TimelineFormatter) getStatusColor(status int) string {
	switch {
	case status >= 200 && status < 300:
		return "\033[32m" // Green
	case status >= 300 && status < 400:
		return "\033[33m" // Yellow
	case status >= 400 && status < 500:
		return "\033[31m" // Red
	case status >= 500:
		return "\033[35m" // Magenta
	default:
		return "\033[0m" // Reset
	}
}

// formatDuration formats a duration in a human-readable way
func formatDuration(d time.Duration) string {
	if d < time.Microsecond {
		return fmt.Sprintf("%dns", d.Nanoseconds())
	}
	if d < time.Millisecond {
		return fmt.Sprintf("%.2fµs", float64(d.Microseconds()))
	}
	if d < time.Second {
		return fmt.Sprintf("%.2fms", float64(d.Microseconds())/1000)
	}
	return fmt.Sprintf("%.2fs", d.Seconds())
}

// truncateURL truncates a URL to max length
func truncateURL(u string, maxLen int) string {
	if len(u) <= maxLen {
		return u
	}
	return u[:maxLen-3] + "..."
}

// FormatCompactTimeline returns a single-line timeline summary
func (f *TimelineFormatter) FormatCompactTimeline(timeline types.Timeline) string {
	parts := make([]string, 0)

	if timeline.DNSLookup.Duration > 0 {
		parts = append(parts, fmt.Sprintf("DNS: %s", formatDuration(timeline.DNSLookup.Duration)))
	}
	if timeline.TCPConnection.Duration > 0 {
		parts = append(parts, fmt.Sprintf("TCP: %s", formatDuration(timeline.TCPConnection.Duration)))
	}
	if timeline.TLSHandshake.Duration > 0 {
		parts = append(parts, fmt.Sprintf("TLS: %s", formatDuration(timeline.TLSHandshake.Duration)))
	}
	if timeline.ServerProcessing.Duration > 0 {
		parts = append(parts, fmt.Sprintf("Wait: %s", formatDuration(timeline.ServerProcessing.Duration)))
	}
	if timeline.ContentTransfer.Duration > 0 {
		parts = append(parts, fmt.Sprintf("Transfer: %s", formatDuration(timeline.ContentTransfer.Duration)))
	}

	return strings.Join(parts, " | ")
}

package reporter

import (
	"io"

	"github.com/ismailtasdelen/securetrace/pkg/types"
)

// Reporter defines the interface for output formatters
type Reporter interface {
	// Format formats a single trace result
	Format(result *types.TraceResult) ([]byte, error)

	// FormatScan formats a complete scan result
	FormatScan(result *types.ScanResult) ([]byte, error)

	// Write writes formatted output to a writer
	Write(w io.Writer, result *types.TraceResult) error

	// WriteScan writes formatted scan output to a writer
	WriteScan(w io.Writer, result *types.ScanResult) error

	// ContentType returns the MIME type of the output
	ContentType() string

	// Extension returns the file extension for the output
	Extension() string
}

// Format represents output format types
type Format string

const (
	FormatJSON Format = "json"
	FormatHTML Format = "html"
	FormatCSV  Format = "csv"
	FormatText Format = "text"
)

// GetReporter returns a reporter for the specified format
func GetReporter(format Format, colored bool) Reporter {
	switch format {
	case FormatJSON:
		return NewJSONReporter(false)
	case FormatHTML:
		return NewHTMLReporter()
	case FormatCSV:
		return NewCSVReporter()
	case FormatText:
		fallthrough
	default:
		return NewTextReporter(colored)
	}
}

// ParseFormat parses a format string to Format type
func ParseFormat(s string) Format {
	switch s {
	case "json":
		return FormatJSON
	case "html":
		return FormatHTML
	case "csv":
		return FormatCSV
	case "text":
		return FormatText
	default:
		return FormatText
	}
}

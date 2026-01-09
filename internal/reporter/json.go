package reporter

import (
	"encoding/json"
	"io"

	"github.com/ismailtasdelen/securetrace/pkg/types"
)

// JSONReporter outputs results in JSON format
type JSONReporter struct {
	pretty bool
}

// NewJSONReporter creates a new JSON reporter
func NewJSONReporter(pretty bool) *JSONReporter {
	return &JSONReporter{pretty: pretty}
}

// Format formats a single trace result to JSON
func (r *JSONReporter) Format(result *types.TraceResult) ([]byte, error) {
	if r.pretty {
		return json.MarshalIndent(result, "", "  ")
	}
	return json.Marshal(result)
}

// FormatScan formats a scan result to JSON
func (r *JSONReporter) FormatScan(result *types.ScanResult) ([]byte, error) {
	if r.pretty {
		return json.MarshalIndent(result, "", "  ")
	}
	return json.Marshal(result)
}

// Write writes JSON output to a writer
func (r *JSONReporter) Write(w io.Writer, result *types.TraceResult) error {
	enc := json.NewEncoder(w)
	if r.pretty {
		enc.SetIndent("", "  ")
	}
	return enc.Encode(result)
}

// WriteScan writes JSON scan output to a writer
func (r *JSONReporter) WriteScan(w io.Writer, result *types.ScanResult) error {
	enc := json.NewEncoder(w)
	if r.pretty {
		enc.SetIndent("", "  ")
	}
	return enc.Encode(result)
}

// ContentType returns the JSON MIME type
func (r *JSONReporter) ContentType() string {
	return "application/json"
}

// Extension returns the JSON file extension
func (r *JSONReporter) Extension() string {
	return ".json"
}

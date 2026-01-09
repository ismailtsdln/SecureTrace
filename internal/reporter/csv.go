package reporter

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"io"
	"strings"

	"github.com/ismailtasdelen/securetrace/pkg/types"
)

// CSVReporter outputs results in CSV format
type CSVReporter struct{}

// NewCSVReporter creates a new CSV reporter
func NewCSVReporter() *CSVReporter {
	return &CSVReporter{}
}

// csvHeaders defines the column headers
var csvHeaders = []string{
	"URL",
	"Final URL",
	"Status Code",
	"Total Time (ms)",
	"DNS Time (ms)",
	"TCP Time (ms)",
	"TLS Time (ms)",
	"TLS Version",
	"TLS Grade",
	"Security Score",
	"Security Grade",
	"Redirect Count",
	"Error",
}

// Format formats a trace result to CSV
func (r *CSVReporter) Format(result *types.TraceResult) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)

	// Write header
	if err := w.Write(csvHeaders); err != nil {
		return nil, err
	}

	// Write data
	if err := w.Write(r.resultToRow(result)); err != nil {
		return nil, err
	}

	w.Flush()
	return buf.Bytes(), w.Error()
}

// FormatScan formats a scan result to CSV
func (r *CSVReporter) FormatScan(result *types.ScanResult) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)

	// Write header
	if err := w.Write(csvHeaders); err != nil {
		return nil, err
	}

	// Write each result
	for _, res := range result.Results {
		if err := w.Write(r.resultToRow(&res)); err != nil {
			return nil, err
		}
	}

	w.Flush()
	return buf.Bytes(), w.Error()
}

// resultToRow converts a TraceResult to a CSV row
func (r *CSVReporter) resultToRow(result *types.TraceResult) []string {
	tlsVersion := ""
	tlsGrade := ""
	if result.TLSInfo != nil {
		tlsVersion = result.TLSInfo.Version
		tlsGrade = result.TLSInfo.Grade
	}

	return []string{
		result.URL,
		result.FinalURL,
		fmt.Sprintf("%d", result.StatusCode),
		fmt.Sprintf("%.2f", float64(result.Timeline.Total.Duration.Milliseconds())),
		fmt.Sprintf("%.2f", float64(result.Timeline.DNSLookup.Duration.Milliseconds())),
		fmt.Sprintf("%.2f", float64(result.Timeline.TCPConnection.Duration.Milliseconds())),
		fmt.Sprintf("%.2f", float64(result.Timeline.TLSHandshake.Duration.Milliseconds())),
		tlsVersion,
		tlsGrade,
		fmt.Sprintf("%d", result.SecurityInfo.Score),
		result.SecurityInfo.Grade,
		fmt.Sprintf("%d", len(result.Redirects)),
		result.Error,
	}
}

// Write writes CSV output to a writer
func (r *CSVReporter) Write(w io.Writer, result *types.TraceResult) error {
	data, err := r.Format(result)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// WriteScan writes CSV scan output to a writer
func (r *CSVReporter) WriteScan(w io.Writer, result *types.ScanResult) error {
	data, err := r.FormatScan(result)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// ContentType returns the CSV MIME type
func (r *CSVReporter) ContentType() string {
	return "text/csv"
}

// Extension returns the CSV file extension
func (r *CSVReporter) Extension() string {
	return ".csv"
}

// ParseCSV parses CSV data back into trace results (for testing/importing)
func ParseCSV(data []byte) ([]types.TraceResult, error) {
	reader := csv.NewReader(strings.NewReader(string(data)))
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}

	if len(records) < 2 {
		return nil, fmt.Errorf("no data in CSV")
	}

	results := make([]types.TraceResult, 0, len(records)-1)
	// Skip header row
	for _, record := range records[1:] {
		if len(record) < len(csvHeaders) {
			continue
		}
		result := types.TraceResult{
			URL:      record[0],
			FinalURL: record[1],
			Error:    record[12],
		}
		// Parse status code
		fmt.Sscanf(record[2], "%d", &result.StatusCode)
		results = append(results, result)
	}

	return results, nil
}

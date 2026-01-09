package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ismailtasdelen/securetrace/internal/config"
	"github.com/ismailtasdelen/securetrace/internal/logger"
	"github.com/ismailtasdelen/securetrace/internal/reporter"
	"github.com/ismailtasdelen/securetrace/internal/tracer"
	"github.com/ismailtasdelen/securetrace/pkg/types"
)

// CLI flags
var (
	cfgFile     string
	outputFmt   string
	outputFile  string
	userAgent   string
	timeout     time.Duration
	proxy       string
	followRedir bool
	verifyTLS   bool
	verbose     bool
	noColor     bool
	concurrency int
	retries     int
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// Parse arguments
	args := os.Args[1:]

	// Handle help and version
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		printUsage()
		return nil
	}

	if args[0] == "version" || args[0] == "-v" || args[0] == "--version" {
		printVersion()
		return nil
	}

	// Parse flags and extract URLs
	urls := make([]string, 0)
	i := 0
	for i < len(args) {
		arg := args[i]

		switch {
		case arg == "-o" || arg == "--output":
			if i+1 < len(args) {
				outputFmt = args[i+1]
				i += 2
				continue
			}
		case arg == "-f" || arg == "--file":
			if i+1 < len(args) {
				outputFile = args[i+1]
				i += 2
				continue
			}
		case arg == "-A" || arg == "--user-agent":
			if i+1 < len(args) {
				userAgent = args[i+1]
				i += 2
				continue
			}
		case arg == "-t" || arg == "--timeout":
			if i+1 < len(args) {
				d, err := time.ParseDuration(args[i+1])
				if err == nil {
					timeout = d
				}
				i += 2
				continue
			}
		case arg == "-x" || arg == "--proxy":
			if i+1 < len(args) {
				proxy = args[i+1]
				i += 2
				continue
			}
		case arg == "-c" || arg == "--concurrency":
			if i+1 < len(args) {
				fmt.Sscanf(args[i+1], "%d", &concurrency)
				i += 2
				continue
			}
		case arg == "-r" || arg == "--retries":
			if i+1 < len(args) {
				fmt.Sscanf(args[i+1], "%d", &retries)
				i += 2
				continue
			}
		case arg == "--no-redirect":
			followRedir = false
			i++
			continue
		case arg == "-k" || arg == "--insecure":
			verifyTLS = false
			i++
			continue
		case arg == "-v" || arg == "--verbose":
			verbose = true
			i++
			continue
		case arg == "--no-color":
			noColor = true
			i++
			continue
		case arg == "--config":
			if i+1 < len(args) {
				cfgFile = args[i+1]
				i += 2
				continue
			}
		case strings.HasPrefix(arg, "-"):
			// Unknown flag, skip
			i++
			continue
		default:
			// This is a URL
			urls = append(urls, arg)
		}
		i++
	}

	// Set defaults
	if outputFmt == "" {
		outputFmt = "text"
	}
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	if concurrency == 0 {
		concurrency = 5
	}
	if retries == 0 {
		retries = 3
	}
	followRedir = true // Default to following redirects unless --no-redirect

	// Setup logger
	if verbose {
		logger.SetLevel(logger.DEBUG)
	}
	if noColor {
		logger.SetColored(false)
	}

	// Load config
	cfgManager := config.NewManager()
	if cfgFile != "" {
		if err := cfgManager.Load(cfgFile); err != nil {
			logger.Warn("Failed to load config file: %v", err)
		}
	}

	// Apply CLI overrides
	cfg := cfgManager.Get()
	cfg.Timeout = timeout
	cfg.Verbose = verbose
	cfg.OutputFormat = outputFmt
	cfg.Retries = retries
	cfg.FollowRedirects = followRedir
	cfg.VerifyTLS = verifyTLS

	if userAgent != "" {
		cfg.UserAgent = cfgManager.ResolveUserAgent(userAgent)
	}
	if proxy != "" {
		cfg.Proxy = proxy
	}

	// Validate URLs
	if len(urls) == 0 {
		return fmt.Errorf("no URLs provided. Usage: securetrace [options] <url> [url...]")
	}

	// Setup context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\nInterrupted, cleaning up...")
		cancel()
	}()

	// Create tracer
	t := tracer.New(cfg)
	defer t.Close()

	// Get reporter
	colored := !noColor && isTerminal()
	rep := reporter.GetReporter(reporter.ParseFormat(outputFmt), colored)

	// Perform trace(s)
	var output []byte
	var err error

	if len(urls) == 1 {
		// Single URL trace
		result, traceErr := t.Trace(ctx, urls[0])
		if traceErr != nil && result == nil {
			return traceErr
		}
		output, err = rep.Format(result)
	} else {
		// Multiple URLs - concurrent scan
		result := t.TraceMultiple(ctx, urls, concurrency)
		output, err = rep.FormatScan(result)
	}

	if err != nil {
		return fmt.Errorf("failed to format output: %w", err)
	}

	// Write output
	if outputFile != "" {
		if err := os.WriteFile(outputFile, output, 0644); err != nil {
			return fmt.Errorf("failed to write output file: %w", err)
		}
		fmt.Printf("Report saved to: %s\n", outputFile)
	} else {
		fmt.Print(string(output))
	}

	return nil
}

func printVersion() {
	fmt.Printf("%s v%s\n", types.AppName, types.Version)
	fmt.Printf("HTTP/HTTPS Security Analysis Tool\n")
	fmt.Printf("https://github.com/ismailtasdelen/securetrace\n")
}

func printUsage() {
	fmt.Printf(`%s v%s - HTTP/HTTPS Security Analysis Tool

USAGE:
    securetrace [OPTIONS] <URL> [URL...]

COMMANDS:
    version     Print version information

OPTIONS:
    -o, --output <FORMAT>     Output format: text, json, html, csv (default: text)
    -f, --file <PATH>         Write output to file instead of stdout
    -A, --user-agent <UA>     User agent string or profile (chrome, firefox, safari, curl, wget)
    -t, --timeout <DURATION>  Request timeout (default: 30s)
    -x, --proxy <URL>         Proxy URL (http, https, or socks5)
    -c, --concurrency <N>     Number of concurrent requests (default: 5)
    -r, --retries <N>         Number of retries on failure (default: 3)
    -k, --insecure            Skip TLS certificate verification
        --no-redirect         Don't follow redirects
        --no-color            Disable colored output
    -v, --verbose             Enable verbose output
        --config <PATH>       Configuration file path
    -h, --help                Show this help message

EXAMPLES:
    # Basic trace
    securetrace https://example.com

    # JSON output to file
    securetrace -o json -f report.json https://example.com

    # HTML report
    securetrace -o html -f report.html https://example.com

    # Multiple URLs with concurrency
    securetrace -c 10 https://site1.com https://site2.com https://site3.com

    # Use Chrome user agent with proxy
    securetrace -A chrome -x http://proxy:8080 https://example.com

    # Skip certificate verification
    securetrace -k https://self-signed.example.com

For more information: https://github.com/ismailtasdelen/securetrace
`, types.AppName, types.Version)
}

func isTerminal() bool {
	fileInfo, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fileInfo.Mode() & os.ModeCharDevice) != 0
}

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ismailtasdelen/securetrace/internal/config"
	"github.com/ismailtasdelen/securetrace/internal/logger"
	"github.com/ismailtasdelen/securetrace/internal/reporter"
	"github.com/ismailtasdelen/securetrace/internal/tracer"
	"github.com/ismailtasdelen/securetrace/pkg/types"
)

// ANSI color codes
const (
	colorReset   = "\033[0m"
	colorBold    = "\033[1m"
	colorDim     = "\033[2m"
	colorRed     = "\033[31m"
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorBlue    = "\033[34m"
	colorMagenta = "\033[35m"
	colorCyan    = "\033[36m"
	colorWhite   = "\033[37m"
	colorBgBlue  = "\033[44m"
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
	useColors   bool
)

func main() {
	if err := run(); err != nil {
		if useColors {
			fmt.Fprintf(os.Stderr, "%s✗ Error:%s %v\n", colorRed, colorReset, err)
		} else {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		}
		os.Exit(1)
	}
}

func run() error {
	// Parse arguments
	args := os.Args[1:]
	useColors = isTerminal()

	// Handle help and version
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		printUsage()
		return nil
	}

	if args[0] == "version" || args[0] == "-V" || args[0] == "--version" {
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
			useColors = false
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
	verifyTLS = true   // Default to verify TLS

	// Setup logger
	if verbose {
		logger.SetLevel(logger.DEBUG)
	}
	if noColor {
		logger.SetColored(false)
		useColors = false
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

	// Print banner for text output
	if outputFmt == "text" && isTerminal() {
		printBanner()
	}

	// Setup context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		if useColors {
			fmt.Printf("\n%s⚠ Interrupted, cleaning up...%s\n", colorYellow, colorReset)
		} else {
			fmt.Println("\nInterrupted, cleaning up...")
		}
		cancel()
	}()

	// Create tracer
	t := tracer.New(cfg)
	defer t.Close()

	// Get reporter
	colored := useColors && !noColor
	rep := reporter.GetReporter(reporter.ParseFormat(outputFmt), colored)

	// Show progress for text output
	var spinner *Spinner
	if outputFmt == "text" && isTerminal() {
		spinner = NewSpinner("Analyzing")
		spinner.Start()
	}

	// Perform trace(s)
	var output []byte
	var err error

	if len(urls) == 1 {
		// Single URL trace
		if spinner != nil {
			spinner.SetMessage(fmt.Sprintf("Tracing %s", truncateURL(urls[0], 50)))
		}
		result, traceErr := t.Trace(ctx, urls[0])
		if spinner != nil {
			spinner.Stop()
		}
		if traceErr != nil && result == nil {
			return traceErr
		}
		output, err = rep.Format(result)
	} else {
		// Multiple URLs - concurrent scan
		if spinner != nil {
			spinner.SetMessage(fmt.Sprintf("Scanning %d targets", len(urls)))
		}
		result := t.TraceMultiple(ctx, urls, concurrency)
		if spinner != nil {
			spinner.Stop()
		}
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
		if useColors {
			fmt.Printf("%s✓ Report saved to:%s %s\n", colorGreen, colorReset, outputFile)
		} else {
			fmt.Printf("Report saved to: %s\n", outputFile)
		}
	} else {
		fmt.Print(string(output))
	}

	return nil
}

func printBanner() {
	if useColors {
		fmt.Printf(`
%s╔═══════════════════════════════════════════════════════════════╗%s
%s║%s  %s███████╗███████╗ ██████╗██╗   ██╗██████╗ ███████╗%s            %s║%s
%s║%s  %s██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝%s            %s║%s
%s║%s  %s███████╗█████╗  ██║     ██║   ██║██████╔╝█████╗%s              %s║%s
%s║%s  %s╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝%s              %s║%s
%s║%s  %s███████║███████╗╚██████╗╚██████╔╝██║  ██║███████╗%s            %s║%s
%s║%s  %s╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝%s            %s║%s
%s║%s                                                               %s║%s
%s║%s  %s████████╗██████╗  █████╗  ██████╗███████╗%s                   %s║%s
%s║%s  %s╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝%s                   %s║%s
%s║%s  %s   ██║   ██████╔╝███████║██║     █████╗%s                     %s║%s
%s║%s  %s   ██║   ██╔══██╗██╔══██║██║     ██╔══╝%s                     %s║%s
%s║%s  %s   ██║   ██║  ██║██║  ██║╚██████╗███████╗%s                   %s║%s
%s║%s  %s   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝%s                   %s║%s
%s║%s                                                               %s║%s
%s║%s  %s🔒 HTTP/HTTPS Security Analysis Tool%s                        %s║%s
%s║%s  %s📌 Version: %s%s                                               %s║%s
%s╚═══════════════════════════════════════════════════════════════╝%s

`,
			colorCyan, colorReset,
			colorCyan, colorReset, colorBold+colorBlue, colorReset, colorCyan, colorReset,
			colorCyan, colorReset, colorBold+colorBlue, colorReset, colorCyan, colorReset,
			colorCyan, colorReset, colorBold+colorBlue, colorReset, colorCyan, colorReset,
			colorCyan, colorReset, colorBold+colorBlue, colorReset, colorCyan, colorReset,
			colorCyan, colorReset, colorBold+colorBlue, colorReset, colorCyan, colorReset,
			colorCyan, colorReset, colorBold+colorBlue, colorReset, colorCyan, colorReset,
			colorCyan, colorReset, colorCyan, colorReset,
			colorCyan, colorReset, colorBold+colorMagenta, colorReset, colorCyan, colorReset,
			colorCyan, colorReset, colorBold+colorMagenta, colorReset, colorCyan, colorReset,
			colorCyan, colorReset, colorBold+colorMagenta, colorReset, colorCyan, colorReset,
			colorCyan, colorReset, colorBold+colorMagenta, colorReset, colorCyan, colorReset,
			colorCyan, colorReset, colorBold+colorMagenta, colorReset, colorCyan, colorReset,
			colorCyan, colorReset, colorBold+colorMagenta, colorReset, colorCyan, colorReset,
			colorCyan, colorReset, colorCyan, colorReset,
			colorCyan, colorReset, colorDim, colorReset, colorCyan, colorReset,
			colorCyan, colorReset, colorDim, types.Version, colorReset, colorCyan, colorReset,
			colorCyan, colorReset)
	}
}

func printVersion() {
	if useColors {
		fmt.Printf("%s%s%s v%s%s\n", colorBold, colorCyan, types.AppName, types.Version, colorReset)
		fmt.Printf("%s🔒 HTTP/HTTPS Security Analysis Tool%s\n", colorDim, colorReset)
		fmt.Printf("%s🌐 https://github.com/ismailtasdelen/securetrace%s\n", colorDim, colorReset)
	} else {
		fmt.Printf("%s v%s\n", types.AppName, types.Version)
		fmt.Printf("HTTP/HTTPS Security Analysis Tool\n")
		fmt.Printf("https://github.com/ismailtasdelen/securetrace\n")
	}
}

func printUsage() {
	if useColors {
		fmt.Printf(`%s%s%s v%s%s - HTTP/HTTPS Security Analysis Tool

%s📋 USAGE:%s
    securetrace [OPTIONS] <URL> [URL...]

%s⚡ COMMANDS:%s
    version     Print version information

%s🔧 OPTIONS:%s
    %s-o, --output%s <FORMAT>     Output format: text, json, html, csv (default: text)
    %s-f, --file%s <PATH>         Write output to file instead of stdout
    %s-A, --user-agent%s <UA>     User agent string or profile (chrome, firefox, safari, curl, wget)
    %s-t, --timeout%s <DURATION>  Request timeout (default: 30s)
    %s-x, --proxy%s <URL>         Proxy URL (http, https, or socks5)
    %s-c, --concurrency%s <N>     Number of concurrent requests (default: 5)
    %s-r, --retries%s <N>         Number of retries on failure (default: 3)
    %s-k, --insecure%s            Skip TLS certificate verification
    %s--no-redirect%s             Don't follow redirects
    %s--no-color%s                Disable colored output
    %s-v, --verbose%s             Enable verbose output
    %s--config%s <PATH>           Configuration file path
    %s-h, --help%s                Show this help message

%s📖 EXAMPLES:%s
    %s# Basic trace%s
    securetrace https://example.com

    %s# JSON output to file%s
    securetrace -o json -f report.json https://example.com

    %s# HTML report%s
    securetrace -o html -f report.html https://example.com

    %s# Multiple URLs with concurrency%s
    securetrace -c 10 https://site1.com https://site2.com https://site3.com

    %s# Use Chrome user agent with proxy%s
    securetrace -A chrome -x http://proxy:8080 https://example.com

    %s# Skip certificate verification%s
    securetrace -k https://self-signed.example.com

%s🔗 For more information: https://github.com/ismailtasdelen/securetrace%s
`,
			colorBold, colorCyan, types.AppName, types.Version, colorReset,
			colorBold+colorGreen, colorReset,
			colorBold+colorYellow, colorReset,
			colorBold+colorBlue, colorReset,
			colorCyan, colorReset,
			colorCyan, colorReset,
			colorCyan, colorReset,
			colorCyan, colorReset,
			colorCyan, colorReset,
			colorCyan, colorReset,
			colorCyan, colorReset,
			colorCyan, colorReset,
			colorCyan, colorReset,
			colorCyan, colorReset,
			colorCyan, colorReset,
			colorCyan, colorReset,
			colorCyan, colorReset,
			colorBold+colorMagenta, colorReset,
			colorDim, colorReset,
			colorDim, colorReset,
			colorDim, colorReset,
			colorDim, colorReset,
			colorDim, colorReset,
			colorDim, colorReset,
			colorDim, colorReset)
	} else {
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
}

func isTerminal() bool {
	fileInfo, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fileInfo.Mode() & os.ModeCharDevice) != 0
}

func truncateURL(u string, maxLen int) string {
	if len(u) <= maxLen {
		return u
	}
	return u[:maxLen-3] + "..."
}

// Spinner provides animated loading indicator
type Spinner struct {
	frames   []string
	message  string
	running  bool
	mu       sync.Mutex
	stopChan chan struct{}
}

// NewSpinner creates a new spinner
func NewSpinner(message string) *Spinner {
	return &Spinner{
		frames:   []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"},
		message:  message,
		stopChan: make(chan struct{}),
	}
}

// SetMessage updates the spinner message
func (s *Spinner) SetMessage(message string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.message = message
}

// Start begins the spinner animation
func (s *Spinner) Start() {
	s.running = true
	go func() {
		i := 0
		for {
			select {
			case <-s.stopChan:
				return
			default:
				s.mu.Lock()
				if useColors {
					fmt.Printf("\r%s%s%s %s", colorCyan, s.frames[i], colorReset, s.message)
				} else {
					fmt.Printf("\r%s %s", s.frames[i], s.message)
				}
				s.mu.Unlock()
				i = (i + 1) % len(s.frames)
				time.Sleep(80 * time.Millisecond)
			}
		}
	}()
}

// Stop stops the spinner
func (s *Spinner) Stop() {
	if s.running {
		s.running = false
		s.stopChan <- struct{}{}
		fmt.Print("\r\033[K") // Clear the line
	}
}

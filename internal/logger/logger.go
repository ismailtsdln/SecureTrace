package logger

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Level represents log severity levels
type Level int

const (
	DEBUG Level = iota
	INFO
	WARN
	ERROR
)

var levelNames = map[Level]string{
	DEBUG: "DEBUG",
	INFO:  "INFO",
	WARN:  "WARN",
	ERROR: "ERROR",
}

var levelColors = map[Level]string{
	DEBUG: "\033[36m", // Cyan
	INFO:  "\033[32m", // Green
	WARN:  "\033[33m", // Yellow
	ERROR: "\033[31m", // Red
}

const resetColor = "\033[0m"

// Logger provides structured logging with levels
type Logger struct {
	mu      sync.Mutex
	level   Level
	output  io.Writer
	colored bool
	prefix  string
}

// New creates a new Logger instance
func New() *Logger {
	return &Logger{
		level:   INFO,
		output:  os.Stdout,
		colored: isTerminal(),
	}
}

// SetLevel sets the minimum log level
func (l *Logger) SetLevel(level Level) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = level
}

// SetOutput sets the log output destination
func (l *Logger) SetOutput(w io.Writer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.output = w
}

// SetColored enables or disables colored output
func (l *Logger) SetColored(colored bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.colored = colored
}

// SetPrefix sets a prefix for all log messages
func (l *Logger) SetPrefix(prefix string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.prefix = prefix
}

// WithPrefix returns a new logger with the given prefix
func (l *Logger) WithPrefix(prefix string) *Logger {
	return &Logger{
		level:   l.level,
		output:  l.output,
		colored: l.colored,
		prefix:  prefix,
	}
}

// log writes a log message at the specified level
func (l *Logger) log(level Level, format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if level < l.level {
		return
	}

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	levelStr := levelNames[level]
	message := fmt.Sprintf(format, args...)

	var line string
	if l.colored {
		color := levelColors[level]
		if l.prefix != "" {
			line = fmt.Sprintf("%s%s%s [%s%-5s%s] [%s] %s\n",
				"\033[90m", timestamp, resetColor,
				color, levelStr, resetColor,
				l.prefix, message)
		} else {
			line = fmt.Sprintf("%s%s%s [%s%-5s%s] %s\n",
				"\033[90m", timestamp, resetColor,
				color, levelStr, resetColor,
				message)
		}
	} else {
		if l.prefix != "" {
			line = fmt.Sprintf("%s [%-5s] [%s] %s\n", timestamp, levelStr, l.prefix, message)
		} else {
			line = fmt.Sprintf("%s [%-5s] %s\n", timestamp, levelStr, message)
		}
	}

	fmt.Fprint(l.output, line)
}

// Debug logs a debug message
func (l *Logger) Debug(format string, args ...interface{}) {
	l.log(DEBUG, format, args...)
}

// Info logs an info message
func (l *Logger) Info(format string, args ...interface{}) {
	l.log(INFO, format, args...)
}

// Warn logs a warning message
func (l *Logger) Warn(format string, args ...interface{}) {
	l.log(WARN, format, args...)
}

// Error logs an error message
func (l *Logger) Error(format string, args ...interface{}) {
	l.log(ERROR, format, args...)
}

// isTerminal checks if stdout is a terminal
func isTerminal() bool {
	fileInfo, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fileInfo.Mode() & os.ModeCharDevice) != 0
}

// ParseLevel parses a string level to Level type
func ParseLevel(s string) Level {
	switch s {
	case "debug", "DEBUG":
		return DEBUG
	case "info", "INFO":
		return INFO
	case "warn", "WARN", "warning", "WARNING":
		return WARN
	case "error", "ERROR":
		return ERROR
	default:
		return INFO
	}
}

// Global logger instance
var defaultLogger = New()

// SetLevel sets the default logger level
func SetLevel(level Level) {
	defaultLogger.SetLevel(level)
}

// SetColored sets colored output for the default logger
func SetColored(colored bool) {
	defaultLogger.SetColored(colored)
}

// Debug logs using the default logger
func Debug(format string, args ...interface{}) {
	defaultLogger.Debug(format, args...)
}

// Info logs using the default logger
func Info(format string, args ...interface{}) {
	defaultLogger.Info(format, args...)
}

// Warn logs using the default logger
func Warn(format string, args ...interface{}) {
	defaultLogger.Warn(format, args...)
}

// Error logs using the default logger
func Error(format string, args ...interface{}) {
	defaultLogger.Error(format, args...)
}

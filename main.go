package main

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/projectdiscovery/goflags"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// zerologPrettySetup configures zerolog with a pretty console output
func zerologPrettySetup() {
	zerolog.TimeFieldFormat = time.RFC3339

	output := zerolog.ConsoleWriter{
		Out:        os.Stderr,
		TimeFormat: time.RFC3339,
		FormatMessage: func(i interface{}) string {
			return fmt.Sprintf(" %s", i)
		},
		FormatCaller: func(i interface{}) string {
			var s string
			if c, ok := i.(string); ok {
				s = c
			}
			if len(s) > 0 {
				if idx := strings.LastIndex(s, "/"); idx >= 0 {
					s = s[idx+1:]
				}
				if idx := strings.LastIndex(s, "\\"); idx >= 0 {
					s = s[idx+1:]
				}
			}
			return s
		},
	}

	log.Logger = zerolog.New(output).
		With().
		Timestamp().
		Caller().
		Logger()
}

var (
	// version is set via ldflags at build time
	version = "dev"
)

//go:embed trivy-template.html
var templateContent string

const (
	trivyCmd            = "trivy"
	trivySubCmd         = "image"
	trivyDownloadDB     = "--download-db-only"
	trivyDownloadJavaDB = "--download-java-db-only"
	trivySkipDB         = "--skip-db-update"
	trivySkipJavaDB     = "--skip-java-db-update"
	trivyInstallURL     = "https://aquasecurity.github.io/trivy/latest/getting-started/installation/"

	hashLength = 6

	// Retry configuration
	maxRetries        = 3
	initialBackoff    = 2 * time.Second
	maxBackoff        = 30 * time.Second
	backoffMultiplier = 2.0
	jitterFactor      = 0.1

	// Circuit breaker configuration
	circuitBreakerThreshold = 5
	circuitBreakerTimeout   = 30 * time.Second

	// Scan timeout per file
	scanTimeout = 10 * time.Minute
)

type options struct {
	Input          string
	Output         string
	Severity       string
	Concurrency    int
	SkipDBUpdate   bool
	SkipTrivyCheck bool
	Version        bool
	MaxRetries     int
	ScanTimeout    time.Duration
}

type scanResult struct {
	File       string
	OutputFile string
	Error      error
	Duration   time.Duration
	RetryCount int
}

// CircuitBreaker implements the circuit breaker pattern to prevent cascading failures
type CircuitBreaker struct {
	mu            sync.RWMutex
	failures      int32
	lastFailure   time.Time
	state         atomic.Int32 // 0: closed, 1: open, 2: half-open
	threshold     int32
	timeout       time.Duration
	onStateChange func(string, string)
}

const (
	circuitClosed   int32 = 0
	circuitOpen     int32 = 1
	circuitHalfOpen int32 = 2
)

func NewCircuitBreaker(threshold int, timeout time.Duration) *CircuitBreaker {
	cb := &CircuitBreaker{
		threshold: int32(threshold),
		timeout:   timeout,
	}
	cb.state.Store(circuitClosed)
	return cb
}

func (cb *CircuitBreaker) Allow() bool {
	state := cb.state.Load()

	switch state {
	case circuitClosed:
		return true
	case circuitOpen:
		// Check if timeout has passed to transition to half-open
		cb.mu.RLock()
		if time.Since(cb.lastFailure) > cb.timeout {
			cb.mu.RUnlock()
			cb.state.Store(circuitHalfOpen)
			if cb.onStateChange != nil {
				go cb.onStateChange("open", "half-open")
			}
			return true
		}
		cb.mu.RUnlock()
		return false
	case circuitHalfOpen:
		return true
	default:
		return false
	}
}

func (cb *CircuitBreaker) RecordSuccess() {
	if cb.state.Load() == circuitHalfOpen {
		cb.state.Store(circuitClosed)
		atomic.StoreInt32(&cb.failures, 0)
		if cb.onStateChange != nil {
			go cb.onStateChange("half-open", "closed")
		}
	}
}

func (cb *CircuitBreaker) RecordFailure() {
	atomic.AddInt32(&cb.failures, 1)
	cb.mu.Lock()
	cb.lastFailure = time.Now()
	cb.mu.Unlock()

	failures := atomic.LoadInt32(&cb.failures)
	if failures >= cb.threshold && cb.state.Load() != circuitOpen {
		cb.state.Store(circuitOpen)
		if cb.onStateChange != nil {
			go cb.onStateChange("closed", "open")
		}
	}
}

func (cb *CircuitBreaker) State() string {
	switch cb.state.Load() {
	case circuitClosed:
		return "closed"
	case circuitOpen:
		return "open"
	case circuitHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// calculateBackoff calculates exponential backoff with jitter
func calculateBackoff(attempt int) time.Duration {
	backoff := float64(initialBackoff) * math.Pow(backoffMultiplier, float64(attempt))
	if backoff > float64(maxBackoff) {
		backoff = float64(maxBackoff)
	}

	// Add jitter to prevent thundering herd
	jitter := backoff * jitterFactor * (2*math.Max(0, math.Min(1, float64(time.Now().UnixNano()%1000)/1000.0)) - 1)
	backoff += jitter

	return time.Duration(backoff)
}

// isRetryableError determines if an error should trigger a retry
func isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()

	// Retry on network-related errors, timeout errors, and transient failures
	retryablePatterns := []string{
		"context deadline exceeded",
		"context canceled",
		"connection refused",
		"connection reset",
		"temporary failure",
		"timeout",
		"i/o timeout",
		"no such host",
		"network",
		"connection",
	}

	for _, pattern := range retryablePatterns {
		if strings.Contains(strings.ToLower(errStr), strings.ToLower(pattern)) {
			return true
		}
	}

	return false
}

// runWithRetry executes a function with exponential backoff retry
func runWithRetry(ctx context.Context, operation string, fn func() error) error {
	maxAttempts := maxRetries

	for attempt := 0; attempt <= maxAttempts; attempt++ {
		select {
		case <-ctx.Done():
			return fmt.Errorf("%s cancelled: %w", operation, ctx.Err())
		default:
		}

		err := fn()
		if err == nil {
			return nil
		}

		// Check if we should retry
		if attempt >= maxAttempts || !isRetryableError(err) {
			return err
		}

		backoff := calculateBackoff(attempt)
		log.Warn().
			Int("attempt", attempt+1).
			Int("max_attempts", maxAttempts+1).
			Dur("backoff", backoff).
			Str("operation", operation).
			Err(err).
			Msg("Operation failed, will retry")

		// Wait with context cancellation support
		select {
		case <-ctx.Done():
			return fmt.Errorf("%s cancelled: %w", operation, ctx.Err())
		case <-time.After(backoff):
		}
	}

	return fmt.Errorf("%s failed after %d attempts", operation, maxAttempts+1)
}

func main() {
	opts := options{}

	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription("TrivyScan - Scan container images using Trivy")

	flagSet.CreateGroup("input", "Input",
		flagSet.StringVarP(&opts.Input, "input", "i", "", "input .tar file or directory of .tar files (required)"),
	)

	flagSet.CreateGroup("output", "Output",
		flagSet.StringVarP(&opts.Output, "output", "o", ".", "output directory for HTML reports"),
	)

	flagSet.CreateGroup("configs", "Configs",
		flagSet.IntVarP(&opts.Concurrency, "concurrency", "c", 3, "number of concurrent scans"),
		flagSet.StringVarP(&opts.Severity, "severity", "s", "MEDIUM,HIGH,CRITICAL", "severity levels to report"),
		flagSet.BoolVarP(&opts.SkipDBUpdate, "skip-db-update", "u", false, "skip trivy database update"),
		flagSet.BoolVarP(&opts.SkipTrivyCheck, "skip-trivy-check", "t", false, "skip trivy installation check"),
		flagSet.IntVarP(&opts.MaxRetries, "max-retries", "r", maxRetries, "maximum number of retry attempts per scan"),
	)

	flagSet.CreateGroup("info", "Info",
		flagSet.BoolVarP(&opts.Version, "version", "v", false, "show version information"),
	)

	// Configure zerolog with pretty output
	zerologPrettySetup()

	if err := flagSet.Parse(); err != nil {
		log.Fatal().Err(err).Msg("Error parsing flags")
	}

	if opts.Version {
		fmt.Printf("TrivyScan version %s\n", version)
		os.Exit(0)
	}

	if opts.Input == "" {
		log.Fatal().Msg("Input is required. Usage: -i file.tar OR -i ./directory")
	}

	// Create cancellable context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		sig := <-sigChan
		log.Warn().Str("signal", sig.String()).Msg("Received shutdown signal, cancelling operations...")
		cancel()
	}()

	// Check trivy installation
	if !opts.SkipTrivyCheck {
		if err := checkTrivyInstalled(ctx); err != nil {
			log.Fatal().Err(err).Msg("Trivy check failed")
		}
	}

	// Collect files
	files, err := collectFiles(opts.Input)
	if err != nil {
		log.Fatal().Err(err).Msg("Error collecting files")
	}
	if len(files) == 0 {
		log.Fatal().Msgf("No .tar files found in: %s", opts.Input)
	}

	log.Info().Str("version", version).Msg("TRIVY SCANNER")
	log.Info().Msg("Starting scan")

	// Update trivy database
	if !opts.SkipDBUpdate {
		if err := updateTrivyDB(ctx); err != nil {
			log.Warn().Err(err).Msg("Failed to update trivy database, continuing with existing database")
		}
	}

	// Create output directory
	if err := os.MkdirAll(opts.Output, 0755); err != nil {
		log.Fatal().Err(err).Msg("Error creating output directory")
	}

	log.Info().Int("workers", opts.Concurrency).Int("total_files", len(files)).Msg("Starting scan...")

	// Run concurrent scans with cancellation support
	startTime := time.Now()
	results := scanFilesAsync(ctx, files, opts.Output, opts.Severity, opts.Concurrency, opts.MaxRetries)

	var successResults, failResults []scanResult
	var completedCount int32

	for result := range results {
		atomic.AddInt32(&completedCount, 1)
		if result.Error != nil {
			failResults = append(failResults, result)
		} else {
			successResults = append(successResults, result)
		}
		log.Info().
			Int("completed", int(atomic.LoadInt32(&completedCount))).
			Int("total", len(files)).
			Msg("Progress")
	}

	elapsed := time.Since(startTime)

	log.Info().Msg("SCAN SUMMARY")

	if len(successResults) > 0 {
		log.Info().Int("count", len(successResults)).Msg("Successful scans")
		for _, r := range successResults {
			log.Info().
				Str("input", r.File).
				Str("output", r.OutputFile).
				Dur("duration", r.Duration.Round(time.Millisecond)).
				Int("retries", r.RetryCount).
				Msg("Success")
		}
	}

	if len(failResults) > 0 {
		log.Error().Int("count", len(failResults)).Msg("Failed scans")
		for _, r := range failResults {
			log.Error().
				Str("input", r.File).
				Str("error", r.Error.Error()).
				Int("retries", r.RetryCount).
				Msg("Failed")
		}
	}

	log.Info().
		Dur("total_duration", elapsed.Round(time.Second)).
		Int("success", len(successResults)).
		Int("failed", len(failResults)).
		Int("total", len(files)).
		Msg("Scan complete")

	if len(failResults) > 0 {
		os.Exit(1)
	}
}

// checkTrivyInstalled verifies trivy is installed, prints helpful install
// instructions if not found.
func checkTrivyInstalled(ctx context.Context) error {
	log.Info().Msg("Checking trivy installation...")

	return runWithRetry(ctx, "trivy version check", func() error {
		output, err := exec.CommandContext(ctx, trivyCmd, "--version").CombinedOutput()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return buildTrivyNotFoundError()
		}

		log.Info().Msgf("Trivy found \n%s", strings.TrimSpace(string(output)))
		return nil
	})
}

// buildTrivyNotFoundError returns a descriptive error with install instructions
// tailored to the current OS.
func buildTrivyNotFoundError() error {
	var sb strings.Builder

	sb.WriteString("Trivy is not installed or not in PATH.\n\n")

	switch runtime.GOOS {
	case "windows":
		sb.WriteString("  To install, run the bundled script:\n")
		sb.WriteString("    install.ps1\n\n")
	case "linux", "darwin":
		sb.WriteString("  To install, run the bundled script:\n")
		sb.WriteString("    chmod +x install.sh && ./install.sh\n\n")
	}

	sb.WriteString("  Or install manually:\n")
	sb.WriteString("    " + trivyInstallURL)

	return errors.New(sb.String())
}

// collectFiles collects .tar files from a file or directory path.
func collectFiles(input string) ([]string, error) {
	info, err := os.Stat(input)
	if err != nil {
		return nil, fmt.Errorf("cannot access '%s': %w", input, err)
	}

	if !info.IsDir() {
		if !strings.HasSuffix(strings.ToLower(input), ".tar") {
			return nil, fmt.Errorf("file '%s' is not a .tar file", input)
		}
		return []string{input}, nil
	}

	entries, err := os.ReadDir(input)
	if err != nil {
		return nil, fmt.Errorf("cannot read directory '%s': %w", input, err)
	}

	var files []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if strings.HasSuffix(strings.ToLower(entry.Name()), ".tar") {
			files = append(files, filepath.Join(input, entry.Name()))
		}
	}

	log.Info().Int("count", len(files)).Str("directory", input).Msg("Found .tar files")
	return files, nil
}

// updateTrivyDB updates the Trivy vulnerability and Java databases.
func updateTrivyDB(ctx context.Context) error {
	databases := []struct {
		name string
		flag string
	}{
		{"Vulnerability", trivyDownloadDB},
		{"Java", trivyDownloadJavaDB},
	}

	log.Info().Msg("Updating trivy databases...")

	for _, db := range databases {
		// Check if context was cancelled
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		dbName := db.name
		dbFlag := db.flag

		err := runWithRetry(ctx, "trivy database update", func() error {
			cmd := exec.CommandContext(ctx, trivyCmd, trivySubCmd, dbFlag)
			output, err := cmd.CombinedOutput()
			if err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				return fmt.Errorf("failed to update %s database: %w\nOutput: %s", dbName, err, output)
			}
			return nil
		})

		if err != nil {
			log.Error().Str("database", dbName).Err(err).Msg("Failed to update database")
			return fmt.Errorf("failed to update %s database: %w", dbName, err)
		}
		log.Info().Str("database", dbName).Msg("Updated")
	}

	return nil
}

// fileHash returns the first hashLength hex characters of the SHA-256 of a file.
func fileHash(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("failed to hash file: %w", err)
	}

	full := hex.EncodeToString(h.Sum(nil))
	if len(full) < hashLength {
		return full, nil
	}
	return full[:hashLength], nil
}

// outputFilename builds the report filename: <basename>_<hash>-report.html
func outputFilename(inputFile, outputDir string) string {
	hash, err := fileHash(inputFile)
	if err != nil {
		// Fallback to timestamp-based hash
		hash = fmt.Sprintf("%x", time.Now().Unix())[:hashLength]
	}

	base := strings.TrimSuffix(filepath.Base(inputFile), filepath.Ext(inputFile))
	return filepath.Join(outputDir, fmt.Sprintf("%s_%s-report.html", base, hash))
}

// scanFilesAsync runs scans concurrently using a worker pool with proper context handling
// and returns a channel of results that is closed when all scans complete.
func scanFilesAsync(ctx context.Context, files []string, outputDir, severity string, concurrency int, maxRetries int) <-chan scanResult {
	results := make(chan scanResult, len(files))
	jobs := make(chan string, len(files))

	// Create circuit breaker for handling transient failures
	cb := NewCircuitBreaker(circuitBreakerThreshold, circuitBreakerTimeout)
	cb.onStateChange = func(from, to string) {
		log.Warn().Str("from", from).Str("to", to).Msg("Circuit breaker state changed")
	}

	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for file := range jobs {
				// Check context before processing each job
				select {
				case <-ctx.Done():
					results <- scanResult{
						File:       file,
						Error:      ctx.Err(),
						Duration:   0,
						RetryCount: 0,
					}
					continue
				default:
				}

				start := time.Now()

				// Check circuit breaker
				if !cb.Allow() {
					results <- scanResult{
						File:       file,
						Error:      fmt.Errorf("circuit breaker is open, skipping scan"),
						Duration:   time.Since(start),
						RetryCount: 0,
					}
					continue
				}

				out, err := scanFileWithRetry(ctx, file, outputDir, severity, maxRetries)

				if err != nil {
					cb.RecordFailure()
				} else {
					cb.RecordSuccess()
				}

				results <- scanResult{
					File:       file,
					OutputFile: out,
					Error:      err,
					Duration:   time.Since(start),
					RetryCount: 0,
				}
			}
		}(i)
	}

	// Send jobs and close
	go func() {
		for _, f := range files {
			jobs <- f
		}
		close(jobs)
	}()

	// Wait for all workers and close results
	go func() {
		wg.Wait()
		close(results)
	}()

	return results
}

// scanFileWithRetry runs trivy scan with retry logic
func scanFileWithRetry(ctx context.Context, inputFile, outputDir, severity string, maxRetries int) (string, error) {
	var lastErr error
	var outputFile string

	for attempt := 0; attempt <= maxRetries; attempt++ {
		// Check context before each attempt
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		default:
		}

		out, err := scanFileWithTimeout(ctx, inputFile, outputDir, severity)
		if err == nil {
			return out, nil
		}

		lastErr = err

		// Don't retry if error is not retryable
		if !isRetryableError(err) {
			return "", err
		}

		// Don't wait after last attempt
		if attempt >= maxRetries {
			break
		}

		backoff := calculateBackoff(attempt)
		log.Warn().
			Str("file", filepath.Base(inputFile)).
			Int("attempt", attempt+1).
			Int("max_attempts", maxRetries+1).
			Dur("backoff", backoff).
			Err(err).
			Msg("Scan failed, will retry")

		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(backoff):
		}
	}

	return outputFile, fmt.Errorf("scan failed after %d attempts: %w", maxRetries+1, lastErr)
}

// scanFileWithTimeout runs trivy against a single .tar file with a timeout
func scanFileWithTimeout(ctx context.Context, inputFile, outputDir, severity string) (string, error) {
	// Create a timeout context for the scan
	scanCtx, cancel := context.WithTimeout(ctx, scanTimeout)
	defer cancel()

	if _, err := os.Stat(inputFile); os.IsNotExist(err) {
		return "", fmt.Errorf("file does not exist: %s", inputFile)
	}

	out := outputFilename(inputFile, outputDir)

	log.Info().Str("file", filepath.Base(inputFile)).Msg("Scanning")

	cmd := exec.CommandContext(scanCtx, trivyCmd, trivySubCmd,
		"--input", inputFile,
		"--severity", severity,
		"--format", "template",
		"--template", templateContent,
		"--output", out,
		trivySkipDB,
		trivySkipJavaDB,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		if scanCtx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("scan timed out after %v: %w", scanTimeout, err)
		}
		if scanCtx.Err() != nil {
			return "", scanCtx.Err()
		}
		return "", fmt.Errorf("trivy command failed: %w\nOutput: %s", err, output)
	}

	return out, nil
}

// scanFile runs trivy against a single .tar file and writes an HTML report.
func scanFile(inputFile, outputDir, severity string) (string, error) {
	if _, err := os.Stat(inputFile); os.IsNotExist(err) {
		return "", fmt.Errorf("file does not exist: %s", inputFile)
	}

	out := outputFilename(inputFile, outputDir)

	log.Info().Str("file", filepath.Base(inputFile)).Msg("Scanning")

	cmd := exec.Command(trivyCmd, trivySubCmd,
		"--input", inputFile,
		"--severity", severity,
		"--format", "template",
		"--template", templateContent,
		"--output", out,
		trivySkipDB,
		trivySkipJavaDB,
	)

	if output, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("trivy command failed: %w\nOutput: %s", err, output)
	}

	return out, nil
}

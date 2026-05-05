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

// Version is set via ldflags at build time
var version = "dev"

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
	hashLength          = 6
)

const (
	defaultMaxRetries        = 3
	defaultConcurrency       = 3
	defaultInitialBackoff    = 2 * time.Second
	defaultMaxBackoff        = 30 * time.Second
	defaultBackoffMultiplier = 2.0
	defaultJitterFactor      = 0.1
	defaultCBThreshold       = 5
	defaultCBTimeout         = 30 * time.Second
	defaultScanTimeout       = 10 * time.Minute
)

type options struct {
	Input          string
	Output         string
	Severity       string
	Scanner        string
	Concurrency    int
	SkipDBUpdate   bool
	SkipTrivyCheck bool
	Version        bool
	MaxRetries     int
}

type scanResult struct {
	File       string
	OutputFile string
	Error      error
	Duration   time.Duration
	Skipped    bool // true when file is invalid (not a Docker/OCI image)
}

// ---------------------------------------------------------------------------
// Semaphore
// ---------------------------------------------------------------------------

type Semaphore chan struct{}

func NewSemaphore(max int) Semaphore { return make(Semaphore, max) }

func (s Semaphore) Acquire(ctx context.Context) error {
	select {
	case s <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s Semaphore) Release() { <-s }

// ---------------------------------------------------------------------------
// CircuitBreaker — only trips on transient infrastructure errors,
// NOT on invalid-file errors.
// ---------------------------------------------------------------------------

const (
	stateClosed   int32 = 0
	stateOpen     int32 = 1
	stateHalfOpen int32 = 2
)

type CircuitBreaker struct {
	mu            sync.RWMutex
	failures      int32
	lastFailure   time.Time
	state         atomic.Int32
	threshold     int32
	timeout       time.Duration
	onStateChange func(from, to string)
}

func NewCircuitBreaker(threshold int, timeout time.Duration) *CircuitBreaker {
	cb := &CircuitBreaker{threshold: int32(threshold), timeout: timeout}
	cb.state.Store(stateClosed)
	return cb
}

func (cb *CircuitBreaker) Allow() bool {
	switch cb.state.Load() {
	case stateClosed:
		return true
	case stateOpen:
		cb.mu.RLock()
		elapsed := time.Since(cb.lastFailure)
		cb.mu.RUnlock()
		if elapsed > cb.timeout {
			cb.state.Store(stateHalfOpen)
			if cb.onStateChange != nil {
				go cb.onStateChange("open", "half-open")
			}
			return true
		}
		return false
	case stateHalfOpen:
		return true
	default:
		return false
	}
}

func (cb *CircuitBreaker) RecordSuccess() {
	if cb.state.Load() == stateHalfOpen {
		cb.state.Store(stateClosed)
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
	if atomic.LoadInt32(&cb.failures) >= cb.threshold && cb.state.Load() != stateOpen {
		cb.state.Store(stateOpen)
		if cb.onStateChange != nil {
			go cb.onStateChange("closed", "open")
		}
	}
}

// ---------------------------------------------------------------------------
// Error classification
// ---------------------------------------------------------------------------

// isInvalidImageError returns true when the tar file is not a valid Docker/OCI
// image — no point retrying, and must NOT trip the circuit breaker.
func isInvalidImageError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	for _, p := range []string{
		"manifest.json not found",
		"index.json: not a directory",
		"unable to initialize archive image",
		"unable to open",
	} {
		if strings.Contains(s, p) {
			return true
		}
	}
	return false
}

// isTransientError returns true for infrastructure / lock errors that should
// trip the circuit breaker and be retried.
func isTransientError(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	for _, p := range []string{
		"timeout", "i/o timeout", "context deadline exceeded",
		"connection refused", "connection reset", "no such host",
		"temporary failure", "network", "connection",
		"database is locked", "database locked",
		"sqlite_busy", "sqlite_locked",
		"cache may be in use",
	} {
		if strings.Contains(s, p) {
			return true
		}
	}
	return false
}

// isRetryableError returns true only for errors worth retrying.
// Invalid image errors are explicitly excluded.
func isRetryableError(err error) bool {
	if err == nil {
		return false
	}
	if isInvalidImageError(err) {
		return false
	}
	return isTransientError(err)
}

// ---------------------------------------------------------------------------
// Scan queue
// ---------------------------------------------------------------------------

// scanQueue fans out all files concurrently (bounded by sem), collects results.
func scanQueue(
	ctx context.Context,
	files []string,
	sem Semaphore,
	cb *CircuitBreaker,
	maxRetries int,
	processFn func(context.Context, string) (string, error),
) <-chan scanResult {
	out := make(chan scanResult, len(files))

	var wg sync.WaitGroup
	for _, f := range files {
		wg.Add(1)
		go func(file string) {
			defer wg.Done()

			start := time.Now()

			if !cb.Allow() {
				out <- scanResult{
					File:     file,
					Error:    fmt.Errorf("circuit breaker open"),
					Duration: time.Since(start),
				}
				return
			}

			outFile, err := runWithRetry(ctx, file, sem, maxRetries, processFn)

			switch {
			case err == nil:
				cb.RecordSuccess()
				out <- scanResult{File: file, OutputFile: outFile, Duration: time.Since(start)}

			case isInvalidImageError(err):
				// Invalid tar — log as warning, mark skipped, do NOT trip CB
				log.Warn().Str("file", filepath.Base(file)).Msg("Skipped: not a valid Docker/OCI image tar")
				out <- scanResult{File: file, Error: err, Duration: time.Since(start), Skipped: true}

			default:
				// Transient / unknown error — trip CB
				cb.RecordFailure()
				out <- scanResult{File: file, Error: err, Duration: time.Since(start)}
			}
		}(f)
	}

	go func() {
		wg.Wait()
		close(out)
	}()

	return out
}

// runWithRetry wraps processFn with semaphore + exponential back-off retry.
func runWithRetry(
	ctx context.Context,
	file string,
	sem Semaphore,
	maxRetries int,
	processFn func(context.Context, string) (string, error),
) (string, error) {
	var lastErr error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		default:
		}

		if err := sem.Acquire(ctx); err != nil {
			return "", fmt.Errorf("semaphore acquire: %w", err)
		}
		outFile, err := processFn(ctx, file)
		sem.Release()

		if err == nil {
			return outFile, nil
		}
		lastErr = err

		// Never retry invalid-image errors
		if !isRetryableError(err) || attempt >= maxRetries {
			return "", err
		}

		backoff := calculateBackoff(attempt)
		log.Warn().
			Str("file", filepath.Base(file)).
			Int("attempt", attempt+1).
			Dur("backoff", backoff).
			Err(err).
			Msg("Retry")

		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(backoff):
		}
	}

	return "", fmt.Errorf("failed after %d attempts: %w", maxRetries+1, lastErr)
}

// ---------------------------------------------------------------------------
// Trivy helpers
// ---------------------------------------------------------------------------

// trivyDefaultCacheDir returns the Trivy cache directory, respecting env vars.
func trivyDefaultCacheDir() string {
	if d := os.Getenv("TRIVY_CACHE_DIR"); d != "" {
		return d
	}
	if xdg := os.Getenv("XDG_CACHE_HOME"); xdg != "" {
		return filepath.Join(xdg, "trivy")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".cache", "trivy")
}

// copyTrivyDB hard-links (or copies) the shared "db" and "java-db" subdirs
// into destCacheDir so each scan process gets its own lock-free DB copy.
// The "fanal" layer cache is intentionally NOT copied — it is per-image and
// would cause lock contention if shared.
func copyTrivyDB(destCacheDir string) error {
	src := trivyDefaultCacheDir()
	for _, sub := range []string{"db", "java-db"} {
		srcSub := filepath.Join(src, sub)
		if _, err := os.Stat(srcSub); os.IsNotExist(err) {
			continue // not downloaded yet; scan will fail with a clear error
		}
		dstSub := filepath.Join(destCacheDir, sub)
		if err := os.MkdirAll(dstSub, 0755); err != nil {
			return err
		}
		entries, err := os.ReadDir(srcSub)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			s := filepath.Join(srcSub, e.Name())
			d := filepath.Join(dstSub, e.Name())
			// Hard-link is zero-cost and safe — DB files are read-only during scan
			if err := os.Link(s, d); err != nil {
				if err2 := copyFile(s, d); err2 != nil {
					return err2
				}
			}
		}
	}
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

// processScanWithOutput scans one tar and writes an HTML report.
// It creates an isolated Trivy cache dir to avoid lock contention.
func processScanWithOutput(ctx context.Context, inputFile, outputDir, severity, scanner string) (string, error) {
	scanCtx, cancel := context.WithTimeout(ctx, defaultScanTimeout)
	defer cancel()

	if _, err := os.Stat(inputFile); os.IsNotExist(err) {
		return "", fmt.Errorf("file not found: %s", inputFile)
	}

	// Isolated cache dir — prevents "cache may be in use by another process"
	cacheDir, err := os.MkdirTemp("", "trivy-cache-*")
	if err != nil {
		return "", fmt.Errorf("create cache dir: %w", err)
	}
	defer os.RemoveAll(cacheDir)

	if err := copyTrivyDB(cacheDir); err != nil {
		return "", fmt.Errorf("copy trivy db: %w", err)
	}

	outFile := outputFilenameCustom(inputFile, outputDir)
	log.Info().Str("file", filepath.Base(inputFile)).Msg("Scanning")

	args := []string{
		trivyCmd, trivySubCmd,
		"--cache-dir", cacheDir,
		"--input", inputFile,
		"--format", "template",
		"--template", templateContent,
		"--output", outFile,
		trivySkipDB, trivySkipJavaDB,
	}
	if severity != "" {
		args = append(args, "--severity", severity)
	}
	if scanner != "" {
		args = append(args, "--scanner", scanner)
	}

	output, err := exec.CommandContext(scanCtx, args[0], args[1:]...).CombinedOutput()
	if err != nil {
		if scanCtx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("scan timeout: %w", err)
		}
		return "", fmt.Errorf("trivy failed: %w\n%s", err, output)
	}
	return outFile, nil
}

// checkTrivyInstalled verifies Trivy is installed and reachable.
func checkTrivyInstalled(ctx context.Context) error {
	log.Info().Msg("Checking Trivy...")
	return retryOperation(ctx, "trivy version", func() error {
		output, err := exec.CommandContext(ctx, trivyCmd, "--version").CombinedOutput()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return buildTrivyNotFoundError()
		}
		log.Info().Msgf("Trivy: %s", strings.TrimSpace(string(output)))
		return nil
	})
}

func buildTrivyNotFoundError() error {
	var sb strings.Builder
	sb.WriteString("Trivy not found in PATH.\n\n")
	switch runtime.GOOS {
	case "windows":
		sb.WriteString("  Run: install.ps1\n\n")
	case "linux", "darwin":
		sb.WriteString("  Run: chmod +x install.sh && ./install.sh\n\n")
	}
	sb.WriteString("  Or: " + trivyInstallURL)
	return errors.New(sb.String())
}

// updateTrivyDB downloads the vulnerability and Java databases.
func updateTrivyDB(ctx context.Context) error {
	log.Info().Msg("Updating databases...")
	for _, db := range []struct{ name, flag string }{
		{"Vulnerability", trivyDownloadDB},
		{"Java", trivyDownloadJavaDB},
	} {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		err := retryOperation(ctx, "db update", func() error {
			output, err := exec.CommandContext(ctx, trivyCmd, trivySubCmd, db.flag).CombinedOutput()
			if err != nil {
				return fmt.Errorf("%s db failed: %w\n%s", db.name, err, output)
			}
			return nil
		})
		if err != nil {
			log.Error().Str("database", db.name).Err(err).Msg("Update failed")
			return err
		}
		log.Info().Str("database", db.name).Msg("Updated")
	}
	return nil
}

// collectFiles gathers .tar files from a file path or directory.
func collectFiles(input string) ([]string, error) {
	info, err := os.Stat(input)
	if err != nil {
		return nil, fmt.Errorf("cannot access %q: %w", input, err)
	}
	if !info.IsDir() {
		if !strings.HasSuffix(strings.ToLower(input), ".tar") {
			return nil, fmt.Errorf("not a .tar file: %s", input)
		}
		return []string{input}, nil
	}

	var files []string
	err = filepath.WalkDir(input, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(strings.ToLower(d.Name()), ".tar") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("cannot walk directory: %w", err)
	}

	log.Info().Int("count", len(files)).Str("directory", input).Msg("Found .tar files")
	return files, nil
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

func retryOperation(ctx context.Context, operation string, fn func() error) error {
	for attempt := 0; attempt <= defaultMaxRetries; attempt++ {
		select {
		case <-ctx.Done():
			return fmt.Errorf("%s cancelled: %w", operation, ctx.Err())
		default:
		}
		err := fn()
		if err == nil {
			return nil
		}
		if attempt >= defaultMaxRetries || !isRetryableError(err) {
			return err
		}
		backoff := calculateBackoff(attempt)
		log.Warn().Int("attempt", attempt+1).Dur("backoff", backoff).Str("operation", operation).Err(err).Msg("Retry")
		select {
		case <-ctx.Done():
			return fmt.Errorf("%s cancelled: %w", operation, ctx.Err())
		case <-time.After(backoff):
		}
	}
	return fmt.Errorf("%s failed", operation)
}

func calculateBackoff(attempt int) time.Duration {
	b := float64(defaultInitialBackoff) * math.Pow(defaultBackoffMultiplier, float64(attempt))
	if b > float64(defaultMaxBackoff) {
		b = float64(defaultMaxBackoff)
	}
	jitter := b * defaultJitterFactor * (2*math.Max(0, math.Min(1, float64(time.Now().UnixNano()%1000)/1000.0)) - 1)
	return time.Duration(b + jitter)
}

func fileHash(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	hash := hex.EncodeToString(h.Sum(nil))
	if len(hash) < hashLength {
		return hash, nil
	}
	return hash[:hashLength], nil
}

func outputFilenameCustom(inputFile, outputDir string) string {
	hash, err := fileHash(inputFile)
	if err != nil {
		hash = fmt.Sprintf("%x", time.Now().Unix())[:hashLength]
	}
	base := strings.TrimSuffix(filepath.Base(inputFile), filepath.Ext(inputFile))
	return filepath.Join(outputDir, fmt.Sprintf("%s_%s-report.html", base, hash))
}

func zerologPrettySetup() {
	zerolog.TimeFieldFormat = time.RFC3339
	log.Logger = zerolog.New(zerolog.ConsoleWriter{
		Out:           os.Stderr,
		TimeFormat:    time.RFC3339,
		FormatMessage: func(i interface{}) string { return fmt.Sprintf(" %s", i) },
		FormatCaller: func(i interface{}) string {
			s, _ := i.(string)
			if idx := strings.LastIndexAny(s, `/\`); idx >= 0 {
				s = s[idx+1:]
			}
			return s
		},
	}).With().Timestamp().Caller().Logger()
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func main() {
	opts := options{}

	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription("TrivyScan - Scan container images using Trivy")
	flagSet.CreateGroup("input", "Input",
		flagSet.StringVarP(&opts.Input, "input", "i", "", "input .tar file or directory (required)"),
	)
	flagSet.CreateGroup("output", "Output",
		flagSet.StringVarP(&opts.Output, "output", "o", ".", "output directory for HTML reports"),
	)
	flagSet.CreateGroup("configs", "Configs",
		flagSet.IntVarP(&opts.Concurrency, "concurrency", "c", defaultConcurrency, "number of concurrent scans"),
		flagSet.StringVarP(&opts.Severity, "severity", "s", "MEDIUM,HIGH,CRITICAL", "severity levels"),
		flagSet.StringVarP(&opts.Scanner, "scanner", "S", "", "scanner to use (vuln,misconfig,secret,license)"),
		flagSet.BoolVarP(&opts.SkipDBUpdate, "skip-db-update", "u", false, "skip database update"),
		flagSet.BoolVarP(&opts.SkipTrivyCheck, "skip-trivy-check", "t", false, "skip trivy installation check"),
		flagSet.IntVarP(&opts.MaxRetries, "max-retries", "r", defaultMaxRetries, "max retry attempts"),
	)
	flagSet.CreateGroup("info", "Info",
		flagSet.BoolVarP(&opts.Version, "version", "v", false, "show version"),
	)

	zerologPrettySetup()

	if err := flagSet.Parse(); err != nil {
		log.Fatal().Err(err).Msg("Flag parse error")
	}

	if opts.Version {
		fmt.Printf("TrivyScan version %s\n", version)
		os.Exit(0)
	}

	if opts.Input == "" {
		log.Fatal().Msg("Input required: -i file.tar OR -i ./directory")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		sig := <-sigChan
		log.Warn().Str("signal", sig.String()).Msg("Shutdown signal received")
		cancel()
	}()

	if !opts.SkipTrivyCheck {
		if err := checkTrivyInstalled(ctx); err != nil {
			log.Fatal().Err(err).Msg("Trivy check failed")
		}
	}

	if !opts.SkipDBUpdate {
		if err := updateTrivyDB(ctx); err != nil {
			log.Warn().Err(err).Msg("DB update failed, continuing with existing DB")
		}
	}

	files, err := collectFiles(opts.Input)
	if err != nil {
		log.Fatal().Err(err).Msg("Error collecting files")
	}
	if len(files) == 0 {
		log.Fatal().Msgf("No .tar files found in: %s", opts.Input)
	}

	if err := os.MkdirAll(opts.Output, 0755); err != nil {
		log.Fatal().Err(err).Msg("Cannot create output directory")
	}

	log.Info().Str("version", version).Int("files", len(files)).Int("concurrency", opts.Concurrency).Msg("Starting scan")

	cb := NewCircuitBreaker(defaultCBThreshold, defaultCBTimeout)
	cb.onStateChange = func(from, to string) {
		log.Warn().Str("from", from).Str("to", to).Msg("Circuit breaker state changed")
	}

	sem := NewSemaphore(opts.Concurrency)
	results := scanQueue(ctx, files, sem, cb, opts.MaxRetries, func(ctx context.Context, file string) (string, error) {
		return processScanWithOutput(ctx, file, opts.Output, opts.Severity, opts.Scanner)
	})

	startTime := time.Now()
	var (
		successResults []scanResult
		skippedResults []scanResult
		failResults    []scanResult
		completed      int
	)

	for result := range results {
		completed++
		switch {
		case result.Error == nil:
			successResults = append(successResults, result)
		case result.Skipped:
			skippedResults = append(skippedResults, result)
		default:
			failResults = append(failResults, result)
		}
		if completed%5 == 0 || completed == len(files) {
			log.Info().Int("done", completed).Int("total", len(files)).Msg("Progress")
		}
	}

	elapsed := time.Since(startTime)

	log.Info().Msg("── SCAN SUMMARY ──────────────────────────────")
	for _, r := range successResults {
		log.Info().Str("input", r.File).Str("output", r.OutputFile).Dur("duration", r.Duration).Msg("OK")
	}
	for _, r := range skippedResults {
		log.Warn().Str("input", r.File).Msg("SKIPPED (invalid Docker/OCI tar)")
	}
	for _, r := range failResults {
		log.Error().Str("input", r.File).Err(r.Error).Msg("FAILED")
	}
	log.Info().
		Dur("duration", elapsed).
		Int("success", len(successResults)).
		Int("skipped", len(skippedResults)).
		Int("failed", len(failResults)).
		Int("total", len(files)).
		Msg("Complete")

	if len(failResults) > 0 {
		os.Exit(1)
	}
}

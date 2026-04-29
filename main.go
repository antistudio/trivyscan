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

// TemplateContent holds the HTML template for Trivy reports
//
//go:embed trivy-template.html
var templateContent string

// Command constants
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

// Default configuration values
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

// CLI options
type options struct {
	Input          string
	Output         string
	Severity       string
	Concurrency    int
	SkipDBUpdate   bool
	SkipTrivyCheck bool
	Version        bool
	MaxRetries     int
}

// Scan result
type scanResult struct {
	File       string
	OutputFile string
	Error      error
	Duration   time.Duration
	RetryCount int
}

// Semaphore is a channel-based counting semaphore — no mutex/cond, no deadlock risk
type Semaphore chan struct{}

// NewSemaphore creates a new semaphore with given capacity
func NewSemaphore(max int) Semaphore {
	return make(Semaphore, max)
}

// Acquire takes a slot; returns error if context is cancelled
func (s Semaphore) Acquire(ctx context.Context) error {
	select {
	case s <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Release returns a slot
func (s Semaphore) Release() {
	<-s
}

// CircuitBreaker states
const (
	stateClosed   int32 = 0
	stateOpen     int32 = 1
	stateHalfOpen int32 = 2
)

// CircuitBreaker prevents cascading failures
type CircuitBreaker struct {
	mu            sync.RWMutex
	failures      int32
	lastFailure   time.Time
	state         atomic.Int32
	threshold     int32
	timeout       time.Duration
	onStateChange func(string, string)
}

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(threshold int, timeout time.Duration) *CircuitBreaker {
	cb := &CircuitBreaker{
		threshold: int32(threshold),
		timeout:   timeout,
	}
	cb.state.Store(stateClosed)
	return cb
}

// Allow checks if operation is allowed
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

// RecordSuccess resets the circuit breaker
func (cb *CircuitBreaker) RecordSuccess() {
	if cb.state.Load() == stateHalfOpen {
		cb.state.Store(stateClosed)
		atomic.StoreInt32(&cb.failures, 0)
		if cb.onStateChange != nil {
			go cb.onStateChange("half-open", "closed")
		}
	}
}

// RecordFailure records a failure and may trip the circuit
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

// WorkerPool manages a pool of workers for concurrent processing
type WorkerPool struct {
	ctx        context.Context
	cancel     context.CancelFunc
	jobs       chan string
	results    chan scanResult
	wg         sync.WaitGroup
	cb         *CircuitBreaker
	semaphore  Semaphore
	maxRetries int
}

// NewWorkerPool creates a new worker pool
func NewWorkerPool(ctx context.Context, concurrency, maxRetries int, cb *CircuitBreaker) *WorkerPool {
	poolCtx, cancel := context.WithCancel(ctx)
	return &WorkerPool{
		ctx:        poolCtx,
		cancel:     cancel,
		jobs:       make(chan string),
		results:    make(chan scanResult, concurrency*2),
		cb:         cb,
		semaphore:  NewSemaphore(concurrency),
		maxRetries: maxRetries,
	}
}

// Start launches worker goroutines
func (p *WorkerPool) Start(numWorkers int, processFn func(context.Context, string) (string, error)) {
	for i := 0; i < numWorkers; i++ {
		p.wg.Add(1)
		go p.worker(processFn)
	}
}

// worker is the main worker loop
func (p *WorkerPool) worker(processFn func(context.Context, string) (string, error)) {
	defer p.wg.Done()

	for job := range p.jobs {
		select {
		case <-p.ctx.Done():
			p.results <- scanResult{File: job, Error: p.ctx.Err()}
			continue
		default:
		}

		start := time.Now()

		if !p.cb.Allow() {
			p.results <- scanResult{
				File:     job,
				Error:    fmt.Errorf("circuit breaker open"),
				Duration: time.Since(start),
			}
			continue
		}

		out, err := p.runWithRetry(job, processFn)

		if err != nil {
			p.cb.RecordFailure()
		} else {
			p.cb.RecordSuccess()
		}

		p.results <- scanResult{
			File:       job,
			OutputFile: out,
			Error:      err,
			Duration:   time.Since(start),
		}
	}
}

// runWithRetry executes with retry logic
func (p *WorkerPool) runWithRetry(job string, processFn func(context.Context, string) (string, error)) (string, error) {
	var lastErr error

	for attempt := 0; attempt <= p.maxRetries; attempt++ {
		select {
		case <-p.ctx.Done():
			return "", p.ctx.Err()
		default:
		}

		if err := p.semaphore.Acquire(p.ctx); err != nil {
			return "", fmt.Errorf("semaphore acquire failed: %w", err)
		}

		out, err := processFn(p.ctx, job)
		p.semaphore.Release()

		if err == nil {
			return out, nil
		}

		lastErr = err

		if !isRetryableError(err) || attempt >= p.maxRetries {
			return "", err
		}

		backoff := calculateBackoff(attempt)
		log.Warn().
			Str("file", filepath.Base(job)).
			Int("attempt", attempt+1).
			Dur("backoff", backoff).
			Err(err).
			Msg("Retry")

		select {
		case <-p.ctx.Done():
			return "", p.ctx.Err()
		case <-time.After(backoff):
		}
	}

	return "", fmt.Errorf("failed after %d attempts: %w", p.maxRetries+1, lastErr)
}

// SubmitBatch adds multiple jobs to the pool
func (p *WorkerPool) SubmitBatch(jobs []string) {
	for _, j := range jobs {
		p.jobs <- j
	}
}

// Close closes the job channel and waits for completion
func (p *WorkerPool) Close() {
	close(p.jobs)
	p.wg.Wait()
	close(p.results)
}

// Results returns the results channel
func (p *WorkerPool) Results() <-chan scanResult {
	return p.results
}

// Cancel cancels all workers
func (p *WorkerPool) Cancel() {
	p.cancel()
}

// zerologPrettySetup configures zerolog console output
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
	log.Logger = zerolog.New(output).With().Timestamp().Caller().Logger()
}

// calculateBackoff computes exponential backoff with jitter
func calculateBackoff(attempt int) time.Duration {
	backoff := float64(defaultInitialBackoff) * math.Pow(defaultBackoffMultiplier, float64(attempt))
	if backoff > float64(defaultMaxBackoff) {
		backoff = float64(defaultMaxBackoff)
	}
	jitter := backoff * defaultJitterFactor * (2*math.Max(0, math.Min(1, float64(time.Now().UnixNano()%1000)/1000.0)) - 1)
	return time.Duration(backoff + jitter)
}

// isRetryableError checks if error warrants retry
func isRetryableError(err error) bool {
	if err == nil {
		return false
	}
	errStr := strings.ToLower(err.Error())
	retryablePatterns := []string{
		"context deadline exceeded", "context canceled",
		"connection refused", "connection reset",
		"temporary failure", "timeout", "i/o timeout",
		"no such host", "network", "connection",
		"database is locked", "database locked",
		"sqlite_busy", "sqlite_locked",
	}
	for _, p := range retryablePatterns {
		if strings.Contains(errStr, p) {
			return true
		}
	}
	return false
}

// runWithRetry executes operation with retry
func runWithRetry(ctx context.Context, operation string, fn func() error) error {
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
		log.Warn().
			Int("attempt", attempt+1).
			Dur("backoff", backoff).
			Str("operation", operation).
			Err(err).
			Msg("Retry failed, will retry")

		select {
		case <-ctx.Done():
			return fmt.Errorf("%s cancelled: %w", operation, ctx.Err())
		case <-time.After(backoff):
		}
	}
	return fmt.Errorf("%s failed", operation)
}

// processScanWithOutput scans a tar file and writes the HTML report to outputDir
func processScanWithOutput(ctx context.Context, inputFile, outputDir string) (string, error) {
	scanCtx, cancel := context.WithTimeout(ctx, defaultScanTimeout)
	defer cancel()

	if _, err := os.Stat(inputFile); os.IsNotExist(err) {
		return "", fmt.Errorf("file not found: %s", inputFile)
	}

	out := outputFilenameCustom(inputFile, outputDir)
	log.Info().Str("file", filepath.Base(inputFile)).Msg("Scanning")

	cmd := exec.CommandContext(scanCtx, trivyCmd, trivySubCmd,
		"--input", inputFile,
		"--severity", "MEDIUM,HIGH,CRITICAL",
		"--format", "template",
		"--template", templateContent,
		"--output", out,
		trivySkipDB, trivySkipJavaDB,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		if scanCtx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("scan timeout: %w", err)
		}
		return "", fmt.Errorf("trivy failed: %w\n%s", err, output)
	}

	return out, nil
}

// checkTrivyInstalled verifies Trivy is installed
func checkTrivyInstalled(ctx context.Context) error {
	log.Info().Msg("Checking Trivy...")
	return runWithRetry(ctx, "trivy version", func() error {
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

// buildTrivyNotFoundError creates installation instructions
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

// collectFiles gathers .tar files from input path
func collectFiles(input string) ([]string, error) {
	info, err := os.Stat(input)
	if err != nil {
		return nil, fmt.Errorf("cannot access '%s': %w", input, err)
	}

	if !info.IsDir() {
		if !strings.HasSuffix(strings.ToLower(input), ".tar") {
			return nil, fmt.Errorf("not a .tar file: %s", input)
		}
		return []string{input}, nil
	}

	entries, err := os.ReadDir(input)
	if err != nil {
		return nil, fmt.Errorf("cannot read directory: %w", err)
	}

	var files []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(strings.ToLower(entry.Name()), ".tar") {
			files = append(files, filepath.Join(input, entry.Name()))
		}
	}

	log.Info().Int("count", len(files)).Str("directory", input).Msg("Found .tar files")
	return files, nil
}

// updateTrivyDB updates Trivy databases
func updateTrivyDB(ctx context.Context) error {
	databases := []struct {
		name string
		flag string
	}{
		{"Vulnerability", trivyDownloadDB},
		{"Java", trivyDownloadJavaDB},
	}

	log.Info().Msg("Updating databases...")

	for _, db := range databases {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		err := runWithRetry(ctx, "db update", func() error {
			cmd := exec.CommandContext(ctx, trivyCmd, trivySubCmd, db.flag)
			output, err := cmd.CombinedOutput()
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

// fileHash computes SHA-256 hash of file
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

// outputFilenameCustom generates output filename with custom directory
func outputFilenameCustom(inputFile, outputDir string) string {
	hash, err := fileHash(inputFile)
	if err != nil {
		hash = fmt.Sprintf("%x", time.Now().Unix())[:hashLength]
	}
	base := strings.TrimSuffix(filepath.Base(inputFile), filepath.Ext(inputFile))
	return filepath.Join(outputDir, fmt.Sprintf("%s_%s-report.html", base, hash))
}

// main entry point
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
		flagSet.BoolVarP(&opts.SkipDBUpdate, "skip-db-update", "u", false, "skip database update"),
		flagSet.BoolVarP(&opts.SkipTrivyCheck, "skip-trivy-check", "t", false, "skip trivy check"),
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

	files, err := collectFiles(opts.Input)
	if err != nil {
		log.Fatal().Err(err).Msg("Error collecting files")
	}
	if len(files) == 0 {
		log.Fatal().Msgf("No .tar files in: %s", opts.Input)
	}

	log.Info().Str("version", version).Msg("TRIVY SCANNER")
	log.Info().Msg("Starting scan")

	if !opts.SkipDBUpdate {
		if err := updateTrivyDB(ctx); err != nil {
			log.Warn().Err(err).Msg("DB update failed, continuing")
		}
	}

	if err := os.MkdirAll(opts.Output, 0755); err != nil {
		log.Fatal().Err(err).Msg("Output dir error")
	}

	cb := NewCircuitBreaker(defaultCBThreshold, defaultCBTimeout)
	cb.onStateChange = func(from, to string) {
		log.Warn().Str("from", from).Str("to", to).Msg("Circuit breaker")
	}

	log.Info().Int("workers", opts.Concurrency).Int("files", len(files)).Msg("Starting scan...")

	pool := NewWorkerPool(ctx, opts.Concurrency, opts.MaxRetries, cb)
	pool.Start(opts.Concurrency, func(ctx context.Context, file string) (string, error) {
		return processScanWithOutput(ctx, file, opts.Output)
	})

	go func() {
		pool.SubmitBatch(files)
		pool.Close()
	}()

	startTime := time.Now()
	var successResults, failResults []scanResult
	completed := 0

	for result := range pool.Results() {
		completed++
		if result.Error != nil {
			failResults = append(failResults, result)
		} else {
			successResults = append(successResults, result)
		}
		if completed%5 == 0 || completed == len(files) {
			log.Info().Int("done", completed).Int("total", len(files)).Msg("Progress")
		}
	}

	elapsed := time.Since(startTime)

	log.Info().Msg("SCAN SUMMARY")

	for _, r := range successResults {
		log.Info().Str("input", r.File).Str("output", r.OutputFile).Dur("duration", r.Duration).Msg("Success")
	}

	for _, r := range failResults {
		log.Error().Str("input", r.File).Err(r.Error).Msg("Failed")
	}

	log.Info().
		Dur("duration", elapsed).
		Int("success", len(successResults)).
		Int("failed", len(failResults)).
		Int("total", len(files)).
		Msg("Complete")

	if len(failResults) > 0 {
		os.Exit(1)
	}
}

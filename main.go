package main

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/charlievieth/fastwalk"

	"github.com/projectdiscovery/goflags"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

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
	defaultInitialBackoff    = 2 * time.Second
	defaultMaxBackoff        = 30 * time.Second
	defaultBackoffMultiplier = 2.0
	defaultJitterFactor      = 0.1
	defaultScanTimeout       = 10 * time.Minute
)

type options struct {
	Input          string
	Output         string
	Severity       string
	Scanner        string
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
	Skipped    bool
}

// ---------------------------------------------------------------------------
// Error classification
// ---------------------------------------------------------------------------

// isInvalidImageError returns true when the tar is not a valid Docker/OCI image.
// These errors should be skipped, not retried.
func isInvalidImageError(err error) bool {
	if err == nil {
		return false
	}
	for _, p := range []string{
		"manifest.json not found",
		"index.json: not a directory",
		"unable to initialize archive image",
		"unable to open",
	} {
		if strings.Contains(err.Error(), p) {
			return true
		}
	}
	return false
}

// isRetryableError returns true for transient infrastructure errors.
func isRetryableError(err error) bool {
	if err == nil || isInvalidImageError(err) {
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

// ---------------------------------------------------------------------------
// Scan — sequential queue, one file at a time
// ---------------------------------------------------------------------------

// scanFile scans a single tar file with retry, returns a scanResult.
func scanFile(ctx context.Context, file, outputDir, severity, scanner string, maxRetries int) scanResult {
	start := time.Now()

	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		select {
		case <-ctx.Done():
			return scanResult{File: file, Error: ctx.Err(), Duration: time.Since(start)}
		default:
		}

		outFile, err := processScan(ctx, file, outputDir, severity, scanner)
		if err == nil {
			return scanResult{File: file, OutputFile: outFile, Duration: time.Since(start)}
		}

		// Invalid image — skip immediately, no retry
		if isInvalidImageError(err) {
			log.Warn().Str("file", filepath.Base(file)).Msg("Skipped: not a valid Docker/OCI image tar")
			return scanResult{File: file, Error: err, Duration: time.Since(start), Skipped: true}
		}

		lastErr = err

		if !isRetryableError(err) || attempt >= maxRetries {
			break
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
			return scanResult{File: file, Error: ctx.Err(), Duration: time.Since(start)}
		case <-time.After(backoff):
		}
	}

	return scanResult{File: file, Error: lastErr, Duration: time.Since(start)}
}

// processScan runs trivy against one tar file and writes the HTML report.
func processScan(ctx context.Context, inputFile, outputDir, severity, scanner string) (string, error) {
	scanCtx, cancel := context.WithTimeout(ctx, defaultScanTimeout)
	defer cancel()

	if _, err := os.Stat(inputFile); os.IsNotExist(err) {
		return "", fmt.Errorf("file not found: %s", inputFile)
	}

	outFile := outputFilenameCustom(inputFile, outputDir)
	log.Info().Str("file", filepath.Base(inputFile)).Msg("Scanning")

	args := []string{
		trivyCmd, trivySubCmd,
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

// ---------------------------------------------------------------------------
// Trivy setup
// ---------------------------------------------------------------------------

func checkTrivyInstalled(ctx context.Context) error {
	log.Info().Msg("Checking Trivy...")
	output, err := exec.CommandContext(ctx, trivyCmd, "--version").CombinedOutput()
	if err != nil {
		return buildTrivyNotFoundError()
	}
	log.Info().Msgf("Trivy: %s", strings.TrimSpace(string(output)))
	return nil
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
		log.Info().Str("database", db.name).Msg("Downloading...")
		output, err := exec.CommandContext(ctx, trivyCmd, trivySubCmd, db.flag).CombinedOutput()
		if err != nil {
			log.Error().Str("database", db.name).Msgf("Update failed: %s", output)
			return fmt.Errorf("%s db failed: %w", db.name, err)
		}
		log.Info().Str("database", db.name).Msg("Updated")
	}
	return nil
}

// ---------------------------------------------------------------------------
// File collection
// ---------------------------------------------------------------------------

const maxWalkDepth = 5

func collectFiles(input string) ([]string, error) {
	info, err := os.Stat(input)
	if err != nil {
		return nil, fmt.Errorf("cannot access %q: %w", input, err)
	}

	// Single file input
	if !info.IsDir() {
		if !strings.HasSuffix(strings.ToLower(input), ".tar") {
			return nil, fmt.Errorf("not a .tar file: %s", input)
		}
		return []string{input}, nil
	}

	// Directory input — walk up to maxWalkDepth levels using fastwalk
	baseDepth := strings.Count(filepath.Clean(input), string(os.PathSeparator))

	var (
		files []string
		mu    sync.Mutex
	)

	conf := fastwalk.Config{Follow: false}
	err = fastwalk.Walk(&conf, input, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			log.Warn().Str("path", path).Err(err).Msg("Skipping inaccessible path")
			return nil
		}

		depth := strings.Count(filepath.Clean(path), string(os.PathSeparator)) - baseDepth
		if d.IsDir() {
			if depth >= maxWalkDepth {
				log.Debug().Str("dir", path).Msg("Max depth reached, skipping")
				return filepath.SkipDir
			}
			return nil
		}

		if strings.HasSuffix(strings.ToLower(d.Name()), ".tar") {
			mu.Lock()
			files = append(files, path)
			mu.Unlock()
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("cannot walk directory: %w", err)
	}

	log.Info().Int("count", len(files)).Str("directory", input).Int("max_depth", maxWalkDepth).Msg("Found .tar files")
	return files, nil
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

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
// main / run
// ---------------------------------------------------------------------------

func main() {
	zerologPrettySetup()
	os.Exit(run())
}

// run contains all application logic and returns an exit code.
// Using a separate function keeps main clean and ensures defers always execute.
func run() int {
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
		flagSet.StringVarP(&opts.Severity, "severity", "s", "MEDIUM,HIGH,CRITICAL", "severity levels"),
		flagSet.StringVarP(&opts.Scanner, "scanner", "S", "", "scanner to use (vuln,misconfig,secret,license)"),
		flagSet.BoolVarP(&opts.SkipDBUpdate, "skip-db-update", "u", false, "skip database update"),
		flagSet.BoolVarP(&opts.SkipTrivyCheck, "skip-trivy-check", "t", false, "skip trivy installation check"),
		flagSet.IntVarP(&opts.MaxRetries, "max-retries", "r", defaultMaxRetries, "max retry attempts"),
	)
	flagSet.CreateGroup("info", "Info",
		flagSet.BoolVarP(&opts.Version, "version", "v", false, "show version"),
	)

	if err := flagSet.Parse(); err != nil {
		log.Fatal().Err(err).Msg("Flag parse error")
	}

	if opts.Version {
		fmt.Printf("TrivyScan version %s\n", version)
		return 0
	}
	if opts.Input == "" {
		log.Error().Msg("Input required: -i file.tar OR -i ./directory")
		return 1
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
			log.Error().Err(err).Msg("Trivy check failed")
			return 1
		}
	}

	if !opts.SkipDBUpdate {
		if err := updateTrivyDB(ctx); err != nil {
			log.Warn().Err(err).Msg("DB update failed, continuing with existing DB")
		}
	}

	files, err := collectFiles(opts.Input)
	if err != nil {
		log.Error().Err(err).Msg("Error collecting files")
		return 1
	}
	if len(files) == 0 {
		log.Error().Msgf("No .tar files found in: %s", opts.Input)
		return 1
	}

	if err := os.MkdirAll(opts.Output, 0755); err != nil {
		log.Error().Err(err).Msg("Cannot create output directory")
		return 1
	}

	log.Info().Str("version", version).Int("files", len(files)).Msg("Starting scan")

	startTime := time.Now()
	var (
		successResults []scanResult
		skippedResults []scanResult
		failResults    []scanResult
	)

	for i, file := range files {
		if ctx.Err() != nil {
			log.Warn().Msg("Scan cancelled")
			break
		}

		log.Info().Int("current", i+1).Int("total", len(files)).Str("file", filepath.Base(file)).Msg("Progress")

		result := scanFile(ctx, file, opts.Output, opts.Severity, opts.Scanner, opts.MaxRetries)
		switch {
		case result.Error == nil:
			successResults = append(successResults, result)
		case result.Skipped:
			skippedResults = append(skippedResults, result)
		default:
			log.Error().Str("file", result.File).Err(result.Error).Msg("Failed, continuing to next file")
			failResults = append(failResults, result)
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
		return 1
	}
	return 0
}

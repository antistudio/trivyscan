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

// inputType describes what kind of input was provided
type inputType int

const (
	inputTypeTar   inputType = iota // local .tar file
	inputTypeImage                  // image reference e.g. nginx:latest
	inputTypeDir                    // directory of .tar files
)

// scanTarget is a single unit of work for the scanner
type scanTarget struct {
	Input string
	Kind  inputType
}

type scanResult struct {
	Target     scanTarget
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

// scanTarget scans a single target with retry, returns a scanResult.
func scanOne(ctx context.Context, target scanTarget, outputDir, severity, scanner string, maxRetries int) scanResult {
	start := time.Now()

	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		select {
		case <-ctx.Done():
			return scanResult{Target: target, Error: ctx.Err(), Duration: time.Since(start)}
		default:
		}

		outFile, err := processScan(ctx, target, outputDir, severity, scanner)
		if err == nil {
			return scanResult{Target: target, OutputFile: outFile, Duration: time.Since(start)}
		}

		// Invalid tar — skip immediately, no retry (not applicable to image refs)
		if target.Kind == inputTypeTar && isInvalidImageError(err) {
			log.Warn().Str("file", target.Input).Msg("Skipped: not a valid Docker/OCI image (tar/tar.gz/tgz)")
			return scanResult{Target: target, Error: err, Duration: time.Since(start), Skipped: true}
		}

		lastErr = err

		if !isRetryableError(err) || attempt >= maxRetries {
			break
		}

		backoff := calculateBackoff(attempt)
		log.Warn().
			Str("input", target.Input).
			Int("attempt", attempt+1).
			Dur("backoff", backoff).
			Err(err).
			Msg("Retry")

		select {
		case <-ctx.Done():
			return scanResult{Target: target, Error: ctx.Err(), Duration: time.Since(start)}
		case <-time.After(backoff):
		}
	}

	return scanResult{Target: target, Error: lastErr, Duration: time.Since(start)}
}

// processScan runs trivy against a scanTarget and writes the HTML report.
func processScan(ctx context.Context, target scanTarget, outputDir, severity, scanner string) (string, error) {
	scanCtx, cancel := context.WithTimeout(ctx, defaultScanTimeout)
	defer cancel()

	outFile := outputFilenameCustom(target.Input, outputDir)
	log.Info().Str("input", target.Input).Str("kind", target.kindString()).Msg("Scanning")

	args := []string{
		trivyCmd, trivySubCmd,
		"--format", "template",
		"--template", templateContent,
		"--output", outFile,
		trivySkipDB, trivySkipJavaDB,
	}

	switch target.Kind {
	case inputTypeTar:
		if _, err := os.Stat(target.Input); os.IsNotExist(err) {
			return "", fmt.Errorf("file not found: %s", target.Input)
		}
		args = append(args, "--input", target.Input)
	case inputTypeImage:
		// image reference is positional arg, no --input flag
		args = append(args, target.Input)
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

func (t scanTarget) kindString() string {
	switch t.Kind {
	case inputTypeTar:
		return "tar"
	case inputTypeImage:
		return "image"
	default:
		return "unknown"
	}
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
// Input resolution
// ---------------------------------------------------------------------------

const maxWalkDepth = 5

// isTarFile returns true if the filename ends with .tar, .tar.gz, or .tgz.
func isTarFile(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz") || strings.HasSuffix(lower, ".tar")
}

// isTarGzFile returns true if the filename ends with .tar.gz or .tgz.
func isTarGzFile(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz")
}

// resolveTargets classifies the input and returns a list of scanTargets.
//
//   - image reference (nginx:latest, registry/img@sha256:...) → single inputTypeImage
//   - existing .tar file                                       → single inputTypeTar
//   - existing directory                                       → walk for .tar files
func resolveTargets(input string) ([]scanTarget, error) {
	info, err := os.Stat(input)
	if err != nil {
		if os.IsNotExist(err) {
			// Path does not exist on disk — treat as image reference
			if !isImageReference(input) {
				return nil, fmt.Errorf("input %q not found on disk and does not look like an image reference", input)
			}
			log.Info().Str("image", input).Msg("Detected image reference")
			return []scanTarget{{Input: input, Kind: inputTypeImage}}, nil
		}
		return nil, fmt.Errorf("cannot access %q: %w", input, err)
	}

	// Single .tar / .tar.gz file
	if !info.IsDir() {
		if !isTarFile(input) {
			return nil, fmt.Errorf("not a .tar, .tar.gz, or .tgz file: %s", input)
		}
		return []scanTarget{{Input: input, Kind: inputTypeTar}}, nil
	}

	// Directory — walk up to maxWalkDepth levels
	baseDepth := strings.Count(filepath.Clean(input), string(os.PathSeparator))

	var (
		targets []scanTarget
		mu      sync.Mutex
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
		if isTarFile(d.Name()) {
			mu.Lock()
			targets = append(targets, scanTarget{Input: path, Kind: inputTypeTar})
			mu.Unlock()
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("cannot walk directory: %w", err)
	}

	log.Info().Int("count", len(targets)).Str("directory", input).Int("max_depth", maxWalkDepth).Msg("Found .tar/.tar.gz/.tgz files")
	return targets, nil
}

// isImageReference returns true if s looks like a container image reference:
// optional registry host, image name, and optional tag or digest.
// Examples: nginx, nginx:1.25, registry.io/myapp:latest, repo/img@sha256:abc
func isImageReference(s string) bool {
	// Must not be an existing path — caller already checked os.Stat
	// Simple heuristic: contains ":" (tag) or "@" (digest), or is a bare name
	// with no path separator characters that would indicate a filesystem path.
	if strings.Contains(s, "@") {
		return true // digest reference
	}
	if strings.Contains(s, ":") {
		// Could be "image:tag" or "/path/to/file" — reject if it looks like a tar file
		return !isTarFile(s)
	}
	// Bare name like "nginx" or "myrepo/myimage" — valid if no OS path separators
	return !strings.ContainsAny(s, `\/`)
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

func outputFilenameCustom(input, outputDir string) string {
	// For image references (e.g. nginx:latest), hash the string itself
	// since there is no file to read.
	var hash string
	if _, err := os.Stat(input); err == nil {
		h, err := fileHash(input)
		if err == nil {
			hash = h
		}
	}
	if hash == "" {
		h := sha256.Sum256([]byte(input))
		hash = hex.EncodeToString(h[:])[:hashLength]
	}

	// Sanitize input name for use in filename (replace / : @ with _)
	base := filepath.Base(input)
	lowerBase := strings.ToLower(base)
	if strings.HasSuffix(lowerBase, ".tar.gz") {
		base = base[:len(base)-7] // strip .tar.gz (case-sensitive to preserve original)
	} else if strings.HasSuffix(lowerBase, ".tgz") {
		base = base[:len(base)-4] // strip .tgz (case-sensitive to preserve original)
	} else {
		base = strings.TrimSuffix(base, filepath.Ext(base))
	}
	base = strings.NewReplacer("/", "_", ":", "_", "@", "_").Replace(base)
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
		flagSet.StringVarP(&opts.Input, "input", "i", "", "input .tar/.tar.gz/.tgz file or directory (required)"),
	)
	flagSet.CreateGroup("output", "Output",
		flagSet.StringVarP(&opts.Output, "output", "o", ".", "output directory for HTML reports"),
	)
	flagSet.CreateGroup("configs", "Configs",
		flagSet.StringVarP(&opts.Severity, "severity", "s", "", "severity levels"),
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
		log.Error().Msg("Input required: -i file.tar OR -i file.tar.gz OR -i file.tgz OR -i ./directory")
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

	targets, err := resolveTargets(opts.Input)
	if err != nil {
		log.Error().Err(err).Msg("Error resolving input")
		return 1
	}
	if len(targets) == 0 {
		log.Error().Msgf("No scannable targets found in: %s", opts.Input)
		return 1
	}

	if err := os.MkdirAll(opts.Output, 0755); err != nil {
		log.Error().Err(err).Msg("Cannot create output directory")
		return 1
	}

	log.Info().Str("version", version).Int("targets", len(targets)).Msg("Starting scan")

	startTime := time.Now()
	var (
		successResults []scanResult
		skippedResults []scanResult
		failResults    []scanResult
	)

	for i, target := range targets {
		if ctx.Err() != nil {
			log.Warn().Msg("Scan cancelled")
			break
		}

		log.Info().Int("current", i+1).Int("total", len(targets)).Str("input", target.Input).Str("kind", target.kindString()).Msg("Progress")

		result := scanOne(ctx, target, opts.Output, opts.Severity, opts.Scanner, opts.MaxRetries)
		switch {
		case result.Error == nil:
			successResults = append(successResults, result)
		case result.Skipped:
			skippedResults = append(skippedResults, result)
		default:
			log.Error().Str("input", result.Target.Input).Err(result.Error).Msg("Failed, continuing to next target")
			failResults = append(failResults, result)
		}
	}

	elapsed := time.Since(startTime)

	log.Info().Msg("── SCAN SUMMARY ──────────────────────────────")
	for _, r := range successResults {
		log.Info().Str("input", r.Target.Input).Str("output", r.OutputFile).Dur("duration", r.Duration).Msg("OK")
	}
	for _, r := range skippedResults {
		log.Warn().Str("input", r.Target.Input).Msg("SKIPPED (invalid Docker/OCI tar)")
	}
	for _, r := range failResults {
		log.Error().Str("input", r.Target.Input).Err(r.Error).Msg("FAILED")
	}
	log.Info().
		Dur("duration", elapsed).
		Int("success", len(successResults)).
		Int("skipped", len(skippedResults)).
		Int("failed", len(failResults)).
		Int("total", len(targets)).
		Msg("Complete")

	if len(failResults) > 0 {
		return 1
	}
	return 0
}

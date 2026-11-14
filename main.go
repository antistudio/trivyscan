package main

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
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
	"sort"
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

// Output layout: <out>/json/<stem>.json, <out>/html/<stem>.html, <out>/summary.html
const (
	jsonSubdir  = "json"
	htmlSubdir  = "html"
	summaryFile = "summary.html"
)

const (
	defaultMaxRetries        = 3
	defaultMaxDepth          = 5
	defaultInitialBackoff    = 2 * time.Second
	defaultMaxBackoff        = 30 * time.Second
	defaultBackoffMultiplier = 2.0
	defaultJitterFactor      = 0.1
	defaultScanTimeout       = 10 * time.Minute
	scanTimeoutGrace         = 30 * time.Second
)

type options struct {
	Input          string
	Output         string
	Severity       string
	Scanner        string
	OnlyUpdate     bool
	SkipDBUpdate   bool
	SkipTrivyCheck bool
	Force          bool
	Version        bool
	MaxRetries     int
	MaxDepth       int
	Timeout        time.Duration
}

// inputType describes what kind of input was provided
type inputType int

const (
	inputTypeTar   inputType = iota // local .tar/.tar.gz/.tgz file
	inputTypeImage                  // image reference e.g. nginx:latest
)

// scanTarget is a single unit of work for the scanner
type scanTarget struct {
	Input string
	Kind  inputType
	Stem  string // report file name without extension, see reportStem
}

type scanResult struct {
	Target   scanTarget
	JSONFile string
	HTMLFile string
	Error    error
	Duration time.Duration
	Skipped  bool
	Cached   bool // existing JSON reused, trivy not run
}

// ---------------------------------------------------------------------------
// Error classification
// ---------------------------------------------------------------------------

// errScanTimeout marks a scan that hit the timeout. Retrying would only hit it again.
var errScanTimeout = errors.New("scan timeout")

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
	if err == nil || isInvalidImageError(err) || errors.Is(err, errScanTimeout) {
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

// scanOne scans a single target into jsonPath with retry, returns a scanResult.
func scanOne(ctx context.Context, target scanTarget, jsonPath, scanner string, timeout time.Duration, maxRetries int) scanResult {
	start := time.Now()

	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		select {
		case <-ctx.Done():
			return scanResult{Target: target, Error: ctx.Err(), Duration: time.Since(start)}
		default:
		}

		err := processScan(ctx, target, jsonPath, scanner, timeout)
		if err == nil {
			return scanResult{Target: target, JSONFile: jsonPath, Duration: time.Since(start)}
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

// processScan runs trivy against a scanTarget and writes the full JSON report
// (all severities; -s is applied at render time).
func processScan(ctx context.Context, target scanTarget, jsonPath, scanner string, timeout time.Duration) error {
	// trivy gets its own --timeout; ours adds a grace period so trivy can fail
	// cleanly instead of being killed mid-write.
	scanCtx, cancel := context.WithTimeout(ctx, timeout+scanTimeoutGrace)
	defer cancel()

	log.Info().Str("input", target.Input).Str("kind", target.kindString()).Msg("Scanning")

	// Write to .tmp and rename on success, so a failed or interrupted scan
	// never leaves a truncated JSON behind.
	tmpFile := jsonPath + ".tmp"
	defer os.Remove(tmpFile)

	args := []string{
		trivySubCmd,
		"--quiet",
		"--format", "json",
		"--list-all-pkgs=false",
		"--timeout", timeout.String(),
		"--output", tmpFile,
		trivySkipDB, trivySkipJavaDB,
	}

	switch target.Kind {
	case inputTypeTar:
		if _, err := os.Stat(target.Input); os.IsNotExist(err) {
			return fmt.Errorf("file not found: %s", target.Input)
		}
		args = append(args, "--input", target.Input)
	case inputTypeImage:
		// image reference is positional arg, no --input flag
		args = append(args, target.Input)
	}

	if scanner != "" {
		args = append(args, "--scanners", scanner)
	}

	output, err := exec.CommandContext(scanCtx, trivyCmd, args...).CombinedOutput()
	if err != nil {
		msg := trivyErrorMessage(output)
		if scanCtx.Err() == context.DeadlineExceeded || strings.Contains(msg, "context deadline exceeded") {
			return fmt.Errorf("%w after %s: %s", errScanTimeout, timeout, msg)
		}
		return fmt.Errorf("trivy failed: %w: %s", err, msg)
	}
	return os.Rename(tmpFile, jsonPath)
}

// trivyErrorMessage trims trivy output to the FATAL message, so error
// classification does not match words from unrelated log lines.
func trivyErrorMessage(output []byte) string {
	s := strings.TrimSpace(string(output))
	if i := strings.Index(s, "FATAL"); i >= 0 {
		s = s[i:]
	}
	return s
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

// trivyCacheDir mirrors trivy's default: $TRIVY_CACHE_DIR or <user cache dir>/trivy.
func trivyCacheDir() string {
	if dir := os.Getenv("TRIVY_CACHE_DIR"); dir != "" {
		return dir
	}
	dir, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "trivy")
}

// dbDownloadedAt returns when the local trivy databases last changed.
// ok is false when the vulnerability DB metadata cannot be read.
func dbDownloadedAt() (t time.Time, ok bool) {
	cacheDir := trivyCacheDir()
	if cacheDir == "" {
		return time.Time{}, false
	}
	for _, db := range []struct {
		dir      string
		required bool
	}{
		{"db", true},
		{"java-db", false},
	} {
		data, err := os.ReadFile(filepath.Join(cacheDir, db.dir, "metadata.json"))
		if err != nil {
			if db.required {
				return time.Time{}, false
			}
			continue
		}
		var meta struct{ DownloadedAt time.Time }
		if err := json.Unmarshal(data, &meta); err != nil {
			if db.required {
				return time.Time{}, false
			}
			continue
		}
		if meta.DownloadedAt.After(t) {
			t = meta.DownloadedAt
		}
	}
	return t, true
}

// isReportFresh reports whether jsonPath was written after the databases last changed.
// The stem already contains the input's content hash, so the result cannot differ.
func isReportFresh(jsonPath string, dbTime time.Time) bool {
	info, err := os.Stat(jsonPath)
	return err == nil && info.ModTime().After(dbTime)
}

// ---------------------------------------------------------------------------
// Input resolution
// ---------------------------------------------------------------------------

// isTarFile returns true if the filename ends with .tar, .tar.gz, or .tgz.
func isTarFile(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz") || strings.HasSuffix(lower, ".tar")
}

// resolveTargets classifies the input and returns a list of scanTargets.
//
//   - image reference (nginx:latest, registry/img@sha256:...) → single inputTypeImage
//   - existing .tar file                                       → single inputTypeTar
//   - existing directory                                       → walk for .tar files (sorted)
func resolveTargets(input string, maxDepth int) ([]scanTarget, error) {
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

	// Directory — walk up to maxDepth levels
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
			if depth >= maxDepth {
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
	// fastwalk is concurrent; sort for a stable scan order across runs
	sort.Slice(targets, func(i, j int) bool { return targets[i].Input < targets[j].Input })

	log.Info().Int("count", len(targets)).Str("directory", input).Int("max_depth", maxDepth).Msg("Found .tar/.tar.gz/.tgz files")
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

// reportStem returns the report file name without extension: <base>_<hash6>.
func reportStem(input string) string {
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
	} else if strings.HasSuffix(lowerBase, ".tar") {
		base = base[:len(base)-4] // strip .tar (case-sensitive to preserve original)
	}
	base = strings.NewReplacer("/", "_", ":", "_", "@", "_").Replace(base)
	return fmt.Sprintf("%s_%s", base, hash)
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

// publishReport renders the detail page for one JSON report and returns its summary row.
func publishReport(outputDir, stem, jsonPath string, sev severitySet) (string, summaryRow, error) {
	rep, err := loadReport(jsonPath)
	if err != nil {
		return "", summaryRow{}, err
	}
	htmlPath := filepath.Join(outputDir, htmlSubdir, stem+".html")
	if err := writeFileAtomic(htmlPath, func(w io.Writer) error { return renderDetail(w, rep, sev) }); err != nil {
		return "", summaryRow{}, fmt.Errorf("render %s: %w", htmlPath, err)
	}
	return htmlPath, summarize(stem, jsonPath, rep, sev), nil
}

// loadPreviousReports re-renders JSON reports from earlier runs that are not
// part of this run, so the summary and detail pages reflect the current -s.
func loadPreviousReports(outputDir string, targets []scanTarget, sev severitySet, rows map[string]summaryRow) {
	current := make(map[string]bool, len(targets))
	for _, t := range targets {
		current[t.Stem] = true
	}
	files, _ := filepath.Glob(filepath.Join(outputDir, jsonSubdir, "*.json"))
	for _, jsonPath := range files {
		stem := strings.TrimSuffix(filepath.Base(jsonPath), ".json")
		if current[stem] {
			continue
		}
		if _, row, err := publishReport(outputDir, stem, jsonPath, sev); err != nil {
			log.Warn().Str("file", jsonPath).Err(err).Msg("Skipping unreadable report from previous run")
		} else {
			rows[stem] = row
		}
	}
	if len(rows) > 0 {
		log.Info().Int("count", len(rows)).Msg("Loaded reports from previous runs")
	}
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
		flagSet.StringVarP(&opts.Output, "output", "o", ".", "output directory (json/, html/, summary.html)"),
	)
	flagSet.CreateGroup("configs", "Configs",
		flagSet.StringVarP(&opts.Severity, "severity", "s", "", "severity levels to show in reports (default all)"),
		flagSet.StringVarP(&opts.Scanner, "scanner", "S", "", "scanners to use (vuln,misconfig,secret,license)"),
		flagSet.BoolVarP(&opts.OnlyUpdate, "update", "u", false, "only update database and exit"),
		flagSet.BoolVarP(&opts.SkipDBUpdate, "skip-db-update", "sd", false, "skip database update"),
		flagSet.BoolVarP(&opts.SkipTrivyCheck, "skip-trivy-check", "st", false, "skip trivy installation check"),
		flagSet.BoolVarP(&opts.Force, "force", "f", false, "rescan even if an up-to-date JSON report exists"),
		flagSet.IntVarP(&opts.MaxRetries, "max-retries", "rt", defaultMaxRetries, "max retry attempts"),
		flagSet.IntVarP(&opts.MaxDepth, "max-depth", "md", defaultMaxDepth, "max directory depth"),
		flagSet.DurationVarP(&opts.Timeout, "timeout", "t", defaultScanTimeout, "timeout per scan"),
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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if opts.OnlyUpdate {
		if err := updateTrivyDB(ctx); err != nil {
			log.Error().Err(err).Msg("DB update failed")
			return 1
		}
		return 0
	}

	if opts.Input == "" {
		log.Error().Msg("Input required: -i file.tar OR -i file.tar.gz OR -i file.tgz OR -i ./directory")
		return 1
	}
	if opts.MaxDepth < 1 {
		log.Error().Int("max_depth", opts.MaxDepth).Msg("--max-depth must be at least 1")
		return 1
	}
	if opts.Timeout <= 0 {
		log.Error().Dur("timeout", opts.Timeout).Msg("--timeout must be positive")
		return 1
	}

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

	targets, err := resolveTargets(opts.Input, opts.MaxDepth)
	if err != nil {
		log.Error().Err(err).Msg("Error resolving input")
		return 1
	}
	if len(targets) == 0 {
		log.Error().Msgf("No scannable targets found in: %s", opts.Input)
		return 1
	}

	jsonDir := filepath.Join(opts.Output, jsonSubdir)
	if err := os.MkdirAll(jsonDir, 0755); err != nil {
		log.Error().Err(err).Msg("Cannot create output directory")
		return 1
	}

	// Hash each input once; the stem is reused for retries and all output files.
	log.Info().Int("targets", len(targets)).Msg("Hashing inputs")
	for i := range targets {
		targets[i].Stem = reportStem(targets[i].Input)
	}

	sev := parseSeverity(opts.Severity)
	rows := map[string]summaryRow{}
	summaryPath := filepath.Join(opts.Output, summaryFile)
	summaryFailed := false
	writeSummary := func() {
		if err := writeFileAtomic(summaryPath, func(w io.Writer) error { return renderSummary(w, rows, sev) }); err != nil {
			log.Error().Err(err).Str("file", summaryPath).Msg("Summary write failed")
			summaryFailed = true
		}
	}

	loadPreviousReports(opts.Output, targets, sev, rows)

	dbTime, haveDBTime := dbDownloadedAt()
	if !haveDBTime && !opts.Force {
		log.Debug().Msg("Trivy DB metadata unavailable, every target will be scanned")
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

		jsonPath := filepath.Join(jsonDir, target.Stem+".json")
		var result scanResult
		// Image references can change upstream under the same name, so only tars are reused.
		if !opts.Force && haveDBTime && target.Kind == inputTypeTar && isReportFresh(jsonPath, dbTime) {
			log.Info().Str("input", target.Input).Str("json", jsonPath).Msg("Report up to date, skipping scan (use --force to rescan)")
			result = scanResult{Target: target, JSONFile: jsonPath, Cached: true}
		} else {
			result = scanOne(ctx, target, jsonPath, opts.Scanner, opts.Timeout, opts.MaxRetries)
		}

		if result.Error == nil {
			htmlPath, row, err := publishReport(opts.Output, target.Stem, jsonPath, sev)
			if err != nil {
				result.Error = err
			} else {
				result.HTMLFile = htmlPath
				rows[target.Stem] = row
				writeSummary()
			}
		}

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

	// Always write the summary at the end, also when nothing succeeded this run.
	writeSummary()

	elapsed := time.Since(startTime)

	cached := 0
	log.Info().Msg("── SCAN SUMMARY ──────────────────────────────")
	for _, r := range successResults {
		if r.Cached {
			cached++
		}
		log.Info().Str("input", r.Target.Input).Str("html", r.HTMLFile).Bool("cached", r.Cached).Dur("duration", r.Duration).Msg("OK")
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
		Int("cached", cached).
		Int("skipped", len(skippedResults)).
		Int("failed", len(failResults)).
		Int("total", len(targets)).
		Str("summary", summaryPath).
		Msg("Complete")

	if len(failResults) > 0 || summaryFailed {
		return 1
	}
	return 0
}

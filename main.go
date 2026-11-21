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
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strconv"
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
	minTrivyVersion     = "0.70.0"
)

// Output layout: <out>/json/<stem>.json, <out>/html/<stem>.html, <out>/html/summary.html
const (
	jsonSubdir    = "json"
	htmlSubdir    = "html"
	summaryFile   = "summary.html"
	hashCacheFile = ".hashes.json" // inside jsonSubdir; dot prefix keeps it apart from reports
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
	Inputs         goflags.StringSlice
	ListFile       string
	Output         string
	Severity       string
	Scanner        string
	OnlyUpdate     bool
	SkipDBUpdate   bool
	SkipTrivyCheck bool
	Force          bool
	Prune          bool
	FailOn         string
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

// containsAny reports whether s contains at least one of subs.
func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// isInvalidImageError returns true when the tar is not a valid Docker/OCI image.
// These errors should be skipped, not retried.
func isInvalidImageError(err error) bool {
	if err == nil {
		return false
	}
	return containsAny(err.Error(),
		"manifest.json not found",
		"index.json: not a directory",
		"unable to initialize archive image",
		"unable to open",
	)
}

// isImageNotFoundError returns true when the registry definitively rejected an
// image reference (unknown name/tag, or no access). Retrying cannot help.
func isImageNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	return containsAny(err.Error(), "MANIFEST_UNKNOWN", "NAME_UNKNOWN", "UNAUTHORIZED", "DENIED")
}

// isDockerDigestError returns true when the Docker daemon knows the tag but
// cannot export it because a manifest digest is missing from its store.
func isDockerDigestError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return containsAny(s, "unable to create manifests file") ||
		(containsAny(s, "content digest") && containsAny(s, "not found"))
}

// isRetryableError returns true for transient infrastructure errors.
func isRetryableError(err error) bool {
	if err == nil || isInvalidImageError(err) || isImageNotFoundError(err) || isDockerDigestError(err) || errors.Is(err, errScanTimeout) {
		return false
	}
	return containsAny(strings.ToLower(err.Error()),
		"timeout", "i/o timeout", "context deadline exceeded",
		"connection refused", "connection reset", "no such host",
		"temporary failure", "network", "connection",
		"database is locked", "database locked",
		"sqlite_busy", "sqlite_locked",
		"cache may be in use",
	)
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
			return scanResult{Target: target, Duration: time.Since(start)}
		}
		// trivy was killed because the run was cancelled, not because the scan failed
		if ctx.Err() != nil {
			return scanResult{Target: target, Error: fmt.Errorf("cancelled: %w", ctx.Err()), Duration: time.Since(start)}
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

	if scanner != "" {
		args = append(args, "--scanners", scanner)
	}

	var source []string
	switch target.Kind {
	case inputTypeTar:
		if _, err := os.Stat(target.Input); os.IsNotExist(err) {
			return fmt.Errorf("file not found: %s", target.Input)
		}
		source = []string{"--input", target.Input}
	case inputTypeImage:
		// image reference is positional arg, no --input flag
		source = []string{target.Input}
	}

	err := runTrivy(scanCtx, slices.Concat(args, source), tmpFile, jsonPath, timeout)
	if err == nil || target.Kind != inputTypeImage || !isDockerDigestError(err) {
		return err
	}

	// The daemon lists the tag but cannot export it (manifest digest missing
	// from its store). trivy exports by name, so point it at a tag that
	// resolves to the image ID instead.
	log.Warn().Str("input", target.Input).Msg("Docker cannot export the image by tag, retrying by image ID")
	tmpTag, cleanup, tagErr := tagImageByID(scanCtx, target.Input)
	if tagErr != nil {
		log.Debug().Err(tagErr).Msg("Cannot retag image")
		return fmt.Errorf("%w (hint: docker image store may be corrupt, run: docker pull %s)", err, target.Input)
	}
	defer cleanup()

	return runTrivy(scanCtx, slices.Concat(args, []string{tmpTag}), tmpFile, jsonPath, timeout)
}

// runTrivy executes trivy and publishes the report atomically on success.
func runTrivy(scanCtx context.Context, args []string, tmpFile, jsonPath string, timeout time.Duration) error {
	out, err := runCommand(scanCtx, trivyCmd, args...)
	if err != nil {
		msg := trivyErrorMessage(out)
		if scanCtx.Err() == context.DeadlineExceeded || strings.Contains(msg, "context deadline exceeded") {
			return fmt.Errorf("%w after %s: %s", errScanTimeout, timeout, msg)
		}
		return fmt.Errorf("trivy failed: %w: %s", err, msg)
	}
	return os.Rename(tmpFile, jsonPath)
}

// tagImageByID resolves ref to its local image ID and tags that ID under a
// temporary name, so the daemon exports the image rather than a broken
// manifest-list digest. cleanup removes the temporary tag.
func tagImageByID(ctx context.Context, ref string) (string, func(), error) {
	noop := func() {}

	id, err := runCommand(ctx, "docker", "image", "inspect", "--format", "{{.Id}}", ref)
	if err != nil {
		return "", noop, fmt.Errorf("docker image inspect %s: %w: %s", ref, err, id)
	}
	if !strings.HasPrefix(id, "sha256:") {
		return "", noop, fmt.Errorf("docker image inspect %s: unexpected image ID %q", ref, id)
	}

	sum := sha256.Sum256([]byte(ref))
	tag := fmt.Sprintf("trivyscan-tmp:%s-%d", hex.EncodeToString(sum[:])[:hashLength], os.Getpid())

	if out, err := runCommand(ctx, "docker", "tag", id, tag); err != nil {
		return "", noop, fmt.Errorf("docker tag %s: %w: %s", id, err, out)
	}

	cleanup := func() {
		if out, err := runCommand(context.Background(), "docker", "rmi", tag); err != nil {
			log.Warn().Str("tag", tag).Msgf("Cannot remove temporary tag: %s", out)
		}
	}
	return tag, cleanup, nil
}

// trivyErrorMessage trims trivy output to the FATAL message, so error
// classification does not match words from unrelated log lines.
func trivyErrorMessage(s string) string {
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
	output, err := runCommand(ctx, trivyCmd, "--version")
	if err != nil {
		return buildTrivyNotFoundError()
	}
	log.Info().Msgf("Trivy: %s", output)
	if v := trivyVersionRe.FindStringSubmatch(output); v != nil && versionLess(v[1], minTrivyVersion) {
		log.Warn().Str("version", v[1]).Str("minimum", minTrivyVersion).Msg("Trivy is older than the tested minimum, results may differ")
	}
	return nil
}

var trivyVersionRe = regexp.MustCompile(`Version:\s*v?(\d+\.\d+\.\d+)`)

// versionLess compares dotted numeric versions like 0.76.2.
func versionLess(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) && i < len(pb); i++ {
		na, _ := strconv.Atoi(pa[i])
		nb, _ := strconv.Atoi(pb[i])
		if na != nb {
			return na < nb
		}
	}
	return len(pa) < len(pb)
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
		output, err := runCommand(ctx, trivyCmd, trivySubCmd, db.flag)
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

// resolveInputs resolves every -i item (and -l line) into scanTargets,
// keeping the given order and dropping duplicates.
func resolveInputs(inputs []string, maxDepth int) ([]scanTarget, error) {
	var (
		targets []scanTarget
		seen    = map[string]bool{}
	)
	for _, input := range inputs {
		resolved, err := resolveTargets(input, maxDepth)
		if err != nil {
			return nil, err
		}
		for _, t := range resolved {
			key := t.Input
			if t.Kind == inputTypeTar {
				// ./a.tar, a.tar and a symlinked path are the same file
				if real, err := filepath.EvalSymlinks(t.Input); err == nil {
					if abs, err := filepath.Abs(real); err == nil {
						key = abs
					}
				}
			}
			if seen[key] {
				log.Debug().Str("input", t.Input).Msg("Duplicate target, skipping")
				continue
			}
			seen[key] = true
			targets = append(targets, t)
		}
	}
	return targets, nil
}

// readTargetList reads one input per line from path; blank lines and # comments are ignored.
// Relative paths that exist next to the list file are resolved against its directory;
// anything else (image references, cwd-relative paths) is kept as written.
func readTargetList(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read target list: %w", err)
	}
	var inputs []string
	for _, line := range strings.Split(string(data), "\n") {
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		if line = strings.TrimSpace(line); line == "" {
			continue
		}
		if !filepath.IsAbs(line) {
			if candidate := filepath.Join(filepath.Dir(path), line); candidate != line {
				if _, err := os.Stat(candidate); err == nil {
					line = candidate
				}
			}
		}
		inputs = append(inputs, line)
	}
	return inputs, nil
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

// imageRefRe follows the Docker reference grammar (distribution/reference):
// [registry[:port]/]path-component[/path-component...][:tag][@digest]
// Path components are lowercase, so paths like ./Images or C:\x never match.
var imageRefRe = regexp.MustCompile(`^` +
	`(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*(?::[0-9]+)?/)?` + // registry
	`[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*` + // repository path
	`(?::[\w][\w.-]{0,127})?` + // tag
	`(?:@[A-Za-z][A-Za-z0-9]*(?:[-_+.][A-Za-z][A-Za-z0-9]*)*:[0-9a-fA-F]{32,})?` + // digest
	`$`)

// isImageReference returns true if s is a valid container image reference.
// Examples: nginx, nginx:1.25, myrepo/app, registry.io:5000/team/app:dev, repo/img@sha256:abc...
func isImageReference(s string) bool {
	// app.tar is a valid reference by grammar, but a missing tar is far more likely
	return len(s) <= 255 && !isTarFile(s) && imageRefRe.MatchString(s)
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

// runCommand runs name with args and returns trimmed combined output.
func runCommand(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func calculateBackoff(attempt int) time.Duration {
	b := float64(defaultInitialBackoff) * math.Pow(defaultBackoffMultiplier, float64(attempt))
	if b > float64(defaultMaxBackoff) {
		b = float64(defaultMaxBackoff)
	}
	jitter := b * defaultJitterFactor * (2*math.Max(0, math.Min(1, float64(time.Now().UnixNano()%1000)/1000.0)) - 1)
	return time.Duration(b + jitter)
}

// fileHash returns the first hashLength hex chars of the file's SHA-256.
// It reads in chunks so a large tar can be interrupted with Ctrl+C.
func fileHash(ctx context.Context, filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	buf := make([]byte, 1<<20)
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		n, err := f.Read(buf)
		h.Write(buf[:n])
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(h.Sum(nil))[:hashLength], nil
}

// hashCache remembers tar hashes by absolute path, size and mtime, so unchanged
// tars are not re-read on every run.
type hashCache struct {
	path    string
	entries map[string]hashEntry
}

type hashEntry struct {
	Size    int64
	ModTime time.Time
	Hash    string
}

// loadHashCache reads the cache; a missing or corrupt file starts an empty one.
func loadHashCache(path string) *hashCache {
	c := &hashCache{path: path, entries: map[string]hashEntry{}}
	if data, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(data, &c.entries); err != nil {
			log.Warn().Str("file", path).Err(err).Msg("Ignoring corrupt hash cache")
			c.entries = map[string]hashEntry{}
		}
	}
	return c
}

// hash returns the content hash of file, reusing the cached value when size
// and mtime are unchanged (unless force).
func (c *hashCache) hash(ctx context.Context, file string, force bool) (string, error) {
	abs, err := filepath.Abs(file)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", err
	}
	if e, ok := c.entries[abs]; ok && !force && e.Size == info.Size() && e.ModTime.Equal(info.ModTime()) {
		log.Debug().Str("file", file).Msg("Hash cached")
		return e.Hash, nil
	}
	h, err := fileHash(ctx, abs)
	if err != nil {
		return "", err
	}
	c.entries[abs] = hashEntry{Size: info.Size(), ModTime: info.ModTime(), Hash: h}
	return h, nil
}

// save writes the cache, dropping entries whose file no longer exists
// and, when keep is not nil, entries not in keep.
func (c *hashCache) save(keep map[string]bool) error {
	for p := range c.entries {
		if _, err := os.Stat(p); err != nil || (keep != nil && !keep[p]) {
			delete(c.entries, p)
		}
	}
	return writeFileAtomic(c.path, func(w io.Writer) error {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(c.entries)
	})
}

// reportStem returns the report file name without extension: <base>_<hash6>.
// contentHash is the tar's hash; empty for image references, which are hashed
// by their name since there is no file to read.
func reportStem(input, contentHash string) string {
	hash := contentHash
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
		name := filepath.Base(jsonPath)
		stem := strings.TrimSuffix(name, ".json")
		// Go's Glob matches dotfiles too; .hashes.json is not a report.
		if strings.HasPrefix(name, ".") || current[stem] {
			continue
		}
		if _, row, err := publishReport(outputDir, stem, jsonPath, sev); err != nil {
			log.Warn().Str("file", jsonPath).Err(err).Msg("Skipping unreadable report from previous run")
		} else {
			row.Status = statusPrevious
			rows[stem] = row
		}
	}
	if len(rows) > 0 {
		log.Info().Int("count", len(rows)).Msg("Loaded reports from previous runs")
	}
}

// pruneReports removes JSON/HTML reports whose stem is not in keep, plus any
// leftover .tmp files. Only files directly in json/ and html/ are touched.
func pruneReports(outputDir string, keep map[string]bool) {
	for _, dir := range []struct{ name, ext string }{{jsonSubdir, ".json"}, {htmlSubdir, ".html"}} {
		entries, err := os.ReadDir(filepath.Join(outputDir, dir.name))
		if err != nil {
			continue
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || strings.HasPrefix(name, ".") || (dir.name == htmlSubdir && name == summaryFile) {
				continue
			}
			stale := strings.HasSuffix(name, ".tmp")
			if !stale && strings.HasSuffix(name, dir.ext) {
				stale = !keep[strings.TrimSuffix(name, dir.ext)]
			}
			if !stale {
				continue
			}
			path := filepath.Join(outputDir, dir.name, name)
			if err := os.Remove(path); err != nil {
				log.Warn().Str("file", path).Err(err).Msg("Prune failed")
			} else {
				log.Info().Str("file", path).Msg("Pruned")
			}
		}
	}
}

// loadOptions parses flags and validates them. A non-negative code means the
// program should exit immediately; otherwise (-1) a scan should proceed.
func loadOptions() (options, severitySet, string, int) {
	opts := options{}

	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription("TrivyScan - Scan container images using Trivy")
	flagSet.CreateGroup("input", "Input",
		flagSet.StringSliceVarP(&opts.Inputs, "input", "i", nil, "images (nginx:latest), .tar/.tar.gz/.tgz files or directories, comma-separated or repeated", goflags.CommaSeparatedStringSliceOptions),
		flagSet.StringVarP(&opts.ListFile, "list", "l", "", "file with one input per line (# comments allowed)"),
	)
	flagSet.CreateGroup("output", "Output",
		flagSet.StringVarP(&opts.Output, "output", "o", ".", "output directory (json/, html/ with summary.html)"),
	)
	flagSet.CreateGroup("configs", "Configs",
		flagSet.StringVarP(&opts.Severity, "severity", "s", "", "severity levels to show in reports (default all)"),
		flagSet.StringVarP(&opts.Scanner, "scanner", "S", "", "scanners to use (vuln,misconfig,secret,license)"),
		flagSet.BoolVarP(&opts.OnlyUpdate, "update", "u", false, "only update database and exit"),
		flagSet.BoolVarP(&opts.SkipDBUpdate, "skip-db-update", "sd", false, "skip database update"),
		flagSet.BoolVarP(&opts.SkipTrivyCheck, "skip-trivy-check", "st", false, "skip trivy installation check"),
		flagSet.BoolVarP(&opts.Force, "force", "f", false, "rescan (and rehash) even if an up-to-date JSON report exists"),
		flagSet.BoolVarP(&opts.Prune, "prune", "p", false, "delete reports in the output directory that are not part of this run"),
		flagSet.StringVarP(&opts.FailOn, "fail-on", "fo", "", "exit 2 when a vulnerability at or above this severity is found (e.g. HIGH)"),
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
		return opts, nil, "", 0
	}

	sev, err := parseSeverity(opts.Severity)
	if err != nil {
		log.Error().Err(err).Msg("Invalid --severity")
		return opts, nil, "", 1
	}
	failOn := strings.ToUpper(strings.TrimSpace(opts.FailOn))
	if failOn != "" && !isSeverity(failOn) {
		log.Error().Str("fail_on", opts.FailOn).Strs("valid", summarySeverities).Msg("Invalid --fail-on")
		return opts, nil, "", 1
	}
	return opts, sev, failOn, -1
}

// signalContext cancels on SIGINT/SIGTERM; a second signal keeps the default
// handling and terminates immediately.
func signalContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		sig := <-sigChan
		signal.Stop(sigChan)
		log.Warn().Str("signal", sig.String()).Msg("Shutdown signal received, finishing up (press Ctrl+C again to force exit)")
		cancel()
	}()
	return ctx, cancel
}

// collectInputs merges -i values with the lines read from -l.
func collectInputs(opts options) ([]string, error) {
	var inputs []string
	for _, in := range opts.Inputs {
		if in = strings.TrimSpace(in); in != "" {
			inputs = append(inputs, in)
		}
	}
	if opts.ListFile != "" {
		listed, err := readTargetList(opts.ListFile)
		if err != nil {
			return nil, err
		}
		inputs = append(inputs, listed...)
	}
	return inputs, nil
}

// setupTrivy verifies the trivy installation and refreshes the databases,
// honouring --skip-trivy-check and --skip-db-update. It reports whether the run
// may continue.
func setupTrivy(ctx context.Context, opts options) bool {
	if !opts.SkipTrivyCheck {
		if err := checkTrivyInstalled(ctx); err != nil {
			log.Error().Err(err).Msg("Trivy check failed")
			return false
		}
	}
	if !opts.SkipDBUpdate {
		if err := updateTrivyDB(ctx); err != nil {
			log.Warn().Err(err).Msg("DB update failed, continuing with existing DB")
		}
	}
	return true
}

// prepareTargets resolves the inputs, creates the JSON directory and assigns
// every target its report stem, hashing each tar once (cached by size+mtime).
func prepareTargets(ctx context.Context, inputs []string, opts options) ([]scanTarget, string, bool) {
	targets, err := resolveInputs(inputs, opts.MaxDepth)
	if err != nil {
		log.Error().Err(err).Msg("Error resolving input")
		return nil, "", false
	}
	if len(targets) == 0 {
		log.Error().Strs("inputs", inputs).Msg("No scannable targets found")
		return nil, "", false
	}

	jsonDir := filepath.Join(opts.Output, jsonSubdir)
	if err := os.MkdirAll(jsonDir, 0755); err != nil {
		log.Error().Err(err).Msg("Cannot create output directory")
		return nil, "", false
	}

	log.Info().Int("targets", len(targets)).Msg("Hashing inputs")
	hashes := loadHashCache(filepath.Join(jsonDir, hashCacheFile))
	usedHashes := map[string]bool{}
	for i := range targets {
		var h string
		if targets[i].Kind == inputTypeTar {
			h, err = hashes.hash(ctx, targets[i].Input, opts.Force)
			if ctx.Err() != nil {
				log.Warn().Msg("Cancelled while hashing inputs")
				return nil, "", false
			}
			if err != nil {
				log.Warn().Str("input", targets[i].Input).Err(err).Msg("Cannot hash input, naming report by path")
			}
			if abs, err := filepath.Abs(targets[i].Input); err == nil {
				usedHashes[abs] = true
			}
		}
		targets[i].Stem = reportStem(targets[i].Input, h)
	}
	var keepHashes map[string]bool // nil keeps cached hashes of other tars
	if opts.Prune {
		keepHashes = usedHashes
	}
	if err := hashes.save(keepHashes); err != nil {
		log.Warn().Err(err).Msg("Cannot save hash cache")
	}
	return targets, jsonDir, true
}

// scanAll scans every target sequentially, filling rows and refreshing the
// summary after each target, and returns the results grouped by status.
func scanAll(ctx context.Context, targets []scanTarget, jsonDir string, opts options, sev severitySet, rows map[string]summaryRow, writeSummary func()) (success, skipped, failed []scanResult) {
	dbTime, haveDBTime := dbDownloadedAt()
	if !haveDBTime && !opts.Force {
		log.Debug().Msg("Trivy DB metadata unavailable, every target will be scanned")
	}

	log.Info().Str("version", version).Int("targets", len(targets)).Msg("Starting scan")

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
			result = scanResult{Target: target, Cached: true}
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
			success = append(success, result)
		case result.Skipped:
			skipped = append(skipped, result)
			rows[target.Stem] = errorRow(target, statusSkipped, result.Error)
			writeSummary()
		default:
			log.Error().Str("input", result.Target.Input).Err(result.Error).Msg("Failed, continuing to next target")
			failed = append(failed, result)
			rows[target.Stem] = errorRow(target, statusFailed, result.Error)
			writeSummary()
		}
	}
	return success, skipped, failed
}

// pruneStaleReports removes reports that are not part of this run, unless the
// run was cancelled.
func pruneStaleReports(ctx context.Context, outputDir string, targets []scanTarget) {
	if ctx.Err() != nil {
		log.Warn().Msg("Run was cancelled, skipping --prune")
		return
	}
	keep := make(map[string]bool, len(targets))
	for _, t := range targets {
		keep[t.Stem] = true
	}
	pruneReports(outputDir, keep)
}

// logScanSummary logs per-target results and the totals line.
func logScanSummary(success, skipped, failed []scanResult, elapsed time.Duration, total int, summaryPath string) {
	cached := 0
	log.Info().Msg("── SCAN SUMMARY ──────────────────────────────")
	for _, r := range success {
		if r.Cached {
			cached++
		}
		log.Info().Str("input", r.Target.Input).Str("html", r.HTMLFile).Bool("cached", r.Cached).Dur("duration", r.Duration).Msg("OK")
	}
	for _, r := range skipped {
		log.Warn().Str("input", r.Target.Input).Msg("SKIPPED (invalid Docker/OCI tar)")
	}
	for _, r := range failed {
		log.Error().Str("input", r.Target.Input).Err(r.Error).Msg("FAILED")
	}
	log.Info().
		Dur("duration", elapsed).
		Int("success", len(success)).
		Int("cached", cached).
		Int("skipped", len(skipped)).
		Int("failed", len(failed)).
		Int("total", total).
		Str("summary", summaryPath).
		Msg("Complete")
}

// scanExitCode returns 1 when a target or the summary failed, 2 when --fail-on
// is hit, and 0 otherwise.
func scanExitCode(failOn string, success, failed []scanResult, rows map[string]summaryRow, summaryFailed bool) int {
	if len(failed) > 0 || summaryFailed {
		return 1
	}
	if failOn == "" {
		return 0
	}
	var over []string
	for _, r := range success {
		if w := rows[r.Target.Stem].Worst; w != "" && atLeast(w, failOn) {
			over = append(over, r.Target.Input)
		}
	}
	if len(over) > 0 {
		log.Error().Str("fail_on", failOn).Strs("targets", over).Msg("Vulnerabilities at or above threshold")
		return 2
	}
	return 0
}

// run contains all application logic and returns an exit code.
// Using a separate function keeps main clean and ensures defers always execute.
func run() int {
	opts, sev, failOn, code := loadOptions()
	if code >= 0 {
		return code
	}

	ctx, cancel := signalContext()
	defer cancel()

	if opts.OnlyUpdate {
		if err := updateTrivyDB(ctx); err != nil {
			log.Error().Err(err).Msg("DB update failed")
			return 1
		}
		return 0
	}

	inputs, err := collectInputs(opts)
	if err != nil {
		log.Error().Err(err).Msg("Error reading -l")
		return 1
	}
	if len(inputs) == 0 {
		log.Error().Msg("Input required: -i nginx:latest,app:dev OR -i image.tar OR -i ./directory OR -l images.txt")
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

	if !setupTrivy(ctx, opts) {
		return 1
	}

	targets, jsonDir, ok := prepareTargets(ctx, inputs, opts)
	if !ok {
		return 1
	}

	rows := map[string]summaryRow{}
	summaryPath := filepath.Join(opts.Output, htmlSubdir, summaryFile)
	summaryFailed := false
	writeSummary := func() {
		if err := writeSummaryFile(summaryPath, rows, sev); err != nil {
			log.Error().Err(err).Str("file", summaryPath).Msg("Summary write failed")
			summaryFailed = true
		}
	}

	if !opts.Prune {
		loadPreviousReports(opts.Output, targets, sev, rows)
	}

	startTime := time.Now()
	success, skipped, failed := scanAll(ctx, targets, jsonDir, opts, sev, rows, writeSummary)

	if opts.Prune {
		pruneStaleReports(ctx, opts.Output, targets)
	}

	// Always write the summary at the end, also when nothing succeeded this run.
	writeSummary()

	logScanSummary(success, skipped, failed, time.Since(startTime), len(targets), summaryPath)
	return scanExitCode(failOn, success, failed, rows, summaryFailed)
}

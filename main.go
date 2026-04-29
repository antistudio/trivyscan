package main

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/goflags"
)

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
)

type options struct {
	Input          string
	Output         string
	Severity       string
	Concurrency    int
	SkipDBUpdate   bool
	SkipTrivyCheck bool
	Version        bool
}

type scanResult struct {
	File       string
	OutputFile string
	Error      error
	Duration   time.Duration
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
	)

	flagSet.CreateGroup("info", "Info",
		flagSet.BoolVarP(&opts.Version, "version", "v", false, "show version information"),
	)

	if err := flagSet.Parse(); err != nil {
		log.Fatalf("Error parsing flags: %s", err)
	}

	if opts.Version {
		fmt.Printf("TrivyScan version %s\n", version)
		os.Exit(0)
	}

	if opts.Input == "" {
		log.Fatal("Input is required. Usage: -i file.tar OR -i ./directory")
	}

	// Check trivy installation
	if !opts.SkipTrivyCheck {
		if err := checkTrivyInstalled(); err != nil {
			log.Fatal(err)
		}
	}

	// Collect files
	files, err := collectFiles(opts.Input)
	if err != nil {
		log.Fatalf("Error collecting files: %s", err)
	}
	if len(files) == 0 {
		log.Fatalf("No .tar files found in: %s", opts.Input)
	}

	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Println("                   TRIVY SCANNER")
	fmt.Println("═══════════════════════════════════════════════════════════")

	// Update trivy database
	if !opts.SkipDBUpdate {
		if err := updateTrivyDB(); err != nil {
			log.Printf("⚠ Warning: Failed to update trivy database: %s", err)
			log.Println("Continuing with existing database...")
		}
		fmt.Println()
	}

	// Create output directory
	if err := os.MkdirAll(opts.Output, 0755); err != nil {
		log.Fatalf("✗ Error creating output directory: %s", err)
	}

	fmt.Println("───────────────────────────────────────────────────────────")
	fmt.Printf("Starting scan with %d workers...\n", opts.Concurrency)
	fmt.Printf("Total files to scan: %d\n", len(files))
	fmt.Println("───────────────────────────────────────────────────────────")
	fmt.Println()

	// Run concurrent scans
	startTime := time.Now()
	results := scanFilesAsync(files, opts.Output, opts.Severity, opts.Concurrency)

	var successResults, failResults []scanResult
	for result := range results {
		if result.Error != nil {
			failResults = append(failResults, result)
		} else {
			successResults = append(successResults, result)
		}
	}

	elapsed := time.Since(startTime)

	// Print summary
	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Println("                    SCAN SUMMARY")
	fmt.Println("═══════════════════════════════════════════════════════════")

	if len(successResults) > 0 {
		fmt.Println()
		fmt.Printf("✓ SUCCESSFUL SCANS (%d):\n", len(successResults))
		fmt.Println("───────────────────────────────────────────────────────────")
		for i, r := range successResults {
			fmt.Printf("%d. Input:  %s\n", i+1, r.File)
			fmt.Printf("   Output: %s\n", r.OutputFile)
			fmt.Printf("   Time:   %s\n", r.Duration.Round(time.Millisecond))
			if i < len(successResults)-1 {
				fmt.Println()
			}
		}
	}

	if len(failResults) > 0 {
		fmt.Println()
		fmt.Printf("✗ FAILED SCANS (%d):\n", len(failResults))
		fmt.Println("───────────────────────────────────────────────────────────")
		for i, r := range failResults {
			fmt.Printf("%d. Input: %s\n", i+1, r.File)
			fmt.Printf("   Error: %s\n", r.Error)
			if i < len(failResults)-1 {
				fmt.Println()
			}
		}
	}

	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Printf("Total Duration: %s\n", elapsed.Round(time.Second))
	fmt.Printf("Success: %d | Failed: %d | Total: %d\n",
		len(successResults), len(failResults), len(files))
	fmt.Println("═══════════════════════════════════════════════════════════")

	if len(failResults) > 0 {
		os.Exit(1)
	}
}

// checkTrivyInstalled verifies trivy is installed, prints helpful install
// instructions if not found.
func checkTrivyInstalled() error {
	fmt.Println("Checking trivy installation...")

	output, err := exec.Command(trivyCmd, "--version").CombinedOutput()
	if err != nil {
		return buildTrivyNotFoundError()
	}

	fmt.Println("✓ Trivy found:")
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			fmt.Printf("  %s\n", line)
		}
	}
	fmt.Println()

	return nil
}

// buildTrivyNotFoundError returns a descriptive error with install instructions
// tailored to the current OS.
func buildTrivyNotFoundError() error {
	var sb strings.Builder

	sb.WriteString("✗ Trivy is not installed or not in PATH.\n\n")

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

	return fmt.Errorf("%s", sb.String())
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

	fmt.Printf("Found %d .tar file(s) in directory: %s\n", len(files), input)
	return files, nil
}

// updateTrivyDB updates the Trivy vulnerability and Java databases.
func updateTrivyDB() error {
	databases := []struct {
		name string
		flag string
	}{
		{"Vulnerability", trivyDownloadDB},
		{"Java", trivyDownloadJavaDB},
	}

	fmt.Println("Updating trivy databases...")
	for _, db := range databases {
		fmt.Printf("  • %s database... ", db.name)
		if output, err := exec.Command(trivyCmd, trivySubCmd, db.flag).CombinedOutput(); err != nil {
			fmt.Println("✗ FAILED")
			return fmt.Errorf("failed to update %s database: %w\nOutput: %s", db.name, err, output)
		}
		fmt.Println("✓ DONE")
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

// scanFilesAsync runs scans concurrently using a worker pool and returns a
// channel of results that is closed when all scans complete.
func scanFilesAsync(files []string, outputDir, severity string, concurrency int) <-chan scanResult {
	results := make(chan scanResult, len(files))
	jobs := make(chan string, len(files))

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for file := range jobs {
				start := time.Now()
				out, err := scanFile(file, outputDir, severity)
				results <- scanResult{
					File:       file,
					OutputFile: out,
					Error:      err,
					Duration:   time.Since(start),
				}
			}
		}()
	}

	go func() {
		for _, f := range files {
			jobs <- f
		}
		close(jobs)
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	return results
}

// scanFile runs trivy against a single .tar file and writes an HTML report.
func scanFile(inputFile, outputDir, severity string) (string, error) {
	if _, err := os.Stat(inputFile); os.IsNotExist(err) {
		return "", fmt.Errorf("file does not exist: %s", inputFile)
	}

	out := outputFilename(inputFile, outputDir)

	fmt.Printf("[SCANNING] %s\n", filepath.Base(inputFile))

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

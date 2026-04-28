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
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/goflags"
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
	trivyInstallURL     = "https://aquasecurity.github.io/trivy/"

	hashLength = 6
)

type options struct {
	Input          string
	Output         string
	Severity       string
	Concurrency    int
	SkipDBUpdate   bool
	SkipTrivyCheck bool
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
	flagSet.SetDescription("Scan trivy")

	flagSet.CreateGroup("input", "Input",
		flagSet.StringVarP(&opts.Input, "input", "i", "", "input file or directory (required)"),
	)

	flagSet.CreateGroup("output", "Output",
		flagSet.StringVarP(&opts.Output, "output", "o", ".", "output directory"),
	)

	flagSet.CreateGroup("configs", "Configs",
		flagSet.IntVarP(&opts.Concurrency, "concurrency", "c", 3, "number of concurrent scans"),
		flagSet.StringVarP(&opts.Severity, "severity", "s", "MEDIUM,HIGH,CRITICAL", "severity levels"),
		flagSet.BoolVarP(&opts.SkipDBUpdate, "skip-db-update", "u", false, "skip trivy database update"),
		flagSet.BoolVarP(&opts.SkipTrivyCheck, "skip-trivy-check", "t", false, "skip trivy installation check"),
	)

	if err := flagSet.Parse(); err != nil {
		log.Fatalf("Error parsing flags: %s", err)
	}

	if opts.Input == "" {
		log.Fatal("Input is required. Usage: -i file.tar OR -i ./directory")
	}

	// Collect files from input (file or directory)
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

	// Check trivy installation
	if !opts.SkipTrivyCheck {
		if err := checkTrivyInstalled(); err != nil {
			log.Fatalf("✗ Trivy check failed: %s", err)
		}
		fmt.Println()
	}

	// Update trivy database
	if !opts.SkipDBUpdate {
		if err := updateTrivyDB(); err != nil {
			log.Printf("⚠ Warning: Failed to update trivy database: %s", err)
			log.Println("Continuing with existing database...")
		}
		fmt.Println()
	}

	// Create output directory if not exists
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

	// Process results
	var successResults []scanResult
	var failResults []scanResult

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

	// Print successful scans
	if len(successResults) > 0 {
		fmt.Println()
		fmt.Printf("✓ SUCCESSFUL SCANS (%d):\n", len(successResults))
		fmt.Println("───────────────────────────────────────────────────────────")
		for i, result := range successResults {
			fmt.Printf("%d. Input:  %s\n", i+1, result.File)
			fmt.Printf("   Output: %s\n", result.OutputFile)
			fmt.Printf("   Time:   %s\n", result.Duration.Round(time.Millisecond))
			if i < len(successResults)-1 {
				fmt.Println()
			}
		}
	}

	// Print failed scans
	if len(failResults) > 0 {
		fmt.Println()
		fmt.Printf("✗ FAILED SCANS (%d):\n", len(failResults))
		fmt.Println("───────────────────────────────────────────────────────────")
		for i, result := range failResults {
			fmt.Printf("%d. Input: %s\n", i+1, result.File)
			fmt.Printf("   Error: %s\n", result.Error)
			if i < len(failResults)-1 {
				fmt.Println()
			}
		}
	}

	// Print statistics
	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Printf("Total Duration: %s\n", elapsed.Round(time.Second))
	fmt.Printf("Success: %d | Failed: %d | Total: %d\n",
		len(successResults), len(failResults), len(files))
	fmt.Println("═══════════════════════════════════════════════════════════")

	// Exit with error code if any scan failed
	if len(failResults) > 0 {
		os.Exit(1)
	}
}

// collectFiles collects .tar files from input (file or directory)
func collectFiles(input string) ([]string, error) {
	info, err := os.Stat(input)
	if err != nil {
		return nil, fmt.Errorf("cannot access '%s': %w", input, err)
	}

	var files []string

	if info.IsDir() {
		// Input is a directory - scan for .tar files
		entries, err := os.ReadDir(input)
		if err != nil {
			return nil, fmt.Errorf("cannot read directory '%s': %w", input, err)
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}

			// Check if file has .tar extension
			name := entry.Name()
			if strings.HasSuffix(strings.ToLower(name), ".tar") {
				fullPath := filepath.Join(input, name)
				files = append(files, fullPath)
			}
		}

		fmt.Printf("Found %d .tar file(s) in directory: %s\n", len(files), input)
	} else {
		// Input is a file
		if !strings.HasSuffix(strings.ToLower(input), ".tar") {
			return nil, fmt.Errorf("file '%s' is not a .tar file", input)
		}
		files = append(files, input)
	}

	return files, nil
}

// checkTrivyInstalled verifies trivy is installed and accessible
func checkTrivyInstalled() error {
	fmt.Println("Checking trivy installation...")

	cmd := exec.Command(trivyCmd, "--version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("trivy is not installed or not in PATH. Please install from: %s", trivyInstallURL)
	}

	// Parse version info
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	fmt.Printf("✓ Trivy found:\n")
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			fmt.Printf("  %s\n", strings.TrimSpace(line))
		}
	}

	return nil
}

// updateTrivyDB updates trivy databases (vulnerability + Java)
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

		cmd := exec.Command(trivyCmd, trivySubCmd, db.flag)
		if output, err := cmd.CombinedOutput(); err != nil {
			fmt.Println("✗ FAILED")
			return fmt.Errorf("failed to update %s database: %w, output: %s", db.name, err, string(output))
		}

		fmt.Println("✓ DONE")
	}

	return nil
}

// calculateFileHash calculates SHA256 hash of a file and returns first N characters
func calculateFileHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("failed to calculate hash: %w", err)
	}

	fullHash := hex.EncodeToString(hash.Sum(nil))

	// Return first N characters of hash
	if len(fullHash) < hashLength {
		return fullHash, nil
	}
	return fullHash[:hashLength], nil
}

// generateOutputFilename generates output filename with hash
// Format: basename_hash-report.html (e.g., service_6dy3u7-report.html)
func generateOutputFilename(inputFile, outputDir string) (string, error) {
	// Calculate file hash
	fileHash, err := calculateFileHash(inputFile)
	if err != nil {
		// If hash fails, use timestamp as fallback
		timestamp := time.Now().Unix()
		fileHash = fmt.Sprintf("%x", timestamp)[:hashLength]
	}

	// Get base filename without extension
	baseName := filepath.Base(inputFile)
	baseName = strings.TrimSuffix(baseName, filepath.Ext(baseName))

	// Generate output filename: basename_hash-report.html
	outputFilename := fmt.Sprintf("%s_%s-report.html", baseName, fileHash)
	outputPath := filepath.Join(outputDir, outputFilename)

	return outputPath, nil
}

// scanFilesAsync performs concurrent scanning with worker pool pattern
func scanFilesAsync(files []string, outputDir, severity string, concurrency int) <-chan scanResult {
	// Buffered channel to avoid blocking when sending results
	results := make(chan scanResult, len(files))

	// Buffered channel for job queue to avoid blocking producers
	jobs := make(chan string, len(files))

	// WaitGroup to track worker completion
	var wg sync.WaitGroup

	// Start worker pool
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go worker(jobs, results, outputDir, severity, &wg)
	}

	// Send jobs to workers
	go func() {
		for _, file := range files {
			jobs <- file
		}
		close(jobs) // Close jobs channel when all jobs are sent
	}()

	// Close results channel when all workers are done
	go func() {
		wg.Wait()
		close(results)
	}()

	return results
}

// worker processes scan jobs from the jobs channel
func worker(jobs <-chan string, results chan<- scanResult, outputDir, severity string, wg *sync.WaitGroup) {
	defer wg.Done()

	// Process jobs until channel is closed
	for file := range jobs {
		startTime := time.Now()
		outputFile, err := scanFile(file, outputDir, severity)
		duration := time.Since(startTime)

		results <- scanResult{
			File:       file,
			OutputFile: outputFile,
			Error:      err,
			Duration:   duration,
		}
	}
}

// scanFile executes trivy scan for a single file
// Returns output file path and error
func scanFile(inputFile, outputDir, severity string) (string, error) {
	// Check if file exists
	if _, err := os.Stat(inputFile); os.IsNotExist(err) {
		return "", fmt.Errorf("file does not exist: %s", inputFile)
	}

	// Generate output filename with hash
	outputFile, err := generateOutputFilename(inputFile, outputDir)
	if err != nil {
		return "", fmt.Errorf("failed to generate output filename: %w", err)
	}

	fmt.Printf("[SCANNING] %s\n", filepath.Base(inputFile))

	// Prepare trivy command
	cmd := exec.Command(trivyCmd, trivySubCmd,
		"--input", inputFile,
		"--severity", severity,
		"--format", "template",
		"--template", templateContent,
		"--output", outputFile,
		trivySkipDB,     // Skip DB update per scan (already updated once at start)
		trivySkipJavaDB, // Skip Java DB update per scan
	)

	// Capture output for better error reporting
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("trivy command failed: %w\nOutput: %s", err, string(output))
	}

	return outputFile, nil
}

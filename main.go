package main

import (
	_ "embed"
	"fmt"
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

type options struct {
	Files          goflags.StringSlice
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
		flagSet.StringSliceVarP(&opts.Files, "input", "i", nil, "file or list file",
			goflags.CommaSeparatedStringSliceOptions),
	)

	flagSet.CreateGroup("output", "Output",
		flagSet.StringVarP(&opts.Output, "output", "o", ".", "output directory (required)"),
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

	if len(opts.Files) == 0 {
		log.Fatal("Input is required")
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
	fmt.Printf("Total files to scan: %d\n", len(opts.Files))
	fmt.Println("───────────────────────────────────────────────────────────")
	fmt.Println()

	// Run concurrent scans
	startTime := time.Now()
	results := scanFilesAsync(opts.Files, opts.Output, opts.Severity, opts.Concurrency)

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
		len(successResults), len(failResults), len(opts.Files))
	fmt.Println("═══════════════════════════════════════════════════════════")

	// Exit with error code if any scan failed
	if len(failResults) > 0 {
		os.Exit(1)
	}
}

// checkTrivyInstalled verifies trivy is installed and accessible
func checkTrivyInstalled() error {
	fmt.Println("Checking trivy installation...")

	cmd := exec.Command("trivy", "--version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("trivy is not installed or not in PATH. Please install from: https://aquasecurity.github.io/trivy/")
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
		{"Vulnerability", "--download-db-only"},
		{"Java", "--download-java-db-only"},
	}

	fmt.Println("Updating trivy databases...")
	for _, db := range databases {
		fmt.Printf("  • %s database... ", db.name)

		cmd := exec.Command("trivy", "image", db.flag)
		if output, err := cmd.CombinedOutput(); err != nil {
			fmt.Println("✗ FAILED")
			return fmt.Errorf("failed to update %s database: %w, output: %s", db.name, err, string(output))
		}

		fmt.Println("✓ DONE")
	}

	return nil
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

	// Generate output filename based on input filename
	baseName := filepath.Base(inputFile)
	baseName = strings.TrimSuffix(baseName, filepath.Ext(baseName))
	outputFile := filepath.Join(outputDir, fmt.Sprintf("%s-report.html", baseName))

	fmt.Printf("[SCANNING] %s\n", filepath.Base(inputFile))

	// Prepare trivy command
	cmd := exec.Command("trivy", "image",
		"--input", inputFile,
		"--severity", severity,
		"--format", "template",
		"--template", templateContent,
		"--output", outputFile,
		"--skip-db-update",      // Skip DB update per scan (already updated once at start)
		"--skip-java-db-update", // Skip Java DB update per scan
	)

	// Capture output for better error reporting
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("trivy command failed: %w\nOutput: %s", err, string(output))
	}

	return outputFile, nil
}

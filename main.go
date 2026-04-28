package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/projectdiscovery/goflags"
)

type options struct {
	Files       goflags.StringSlice
	Output      string
	Severity    string
	Concurrency int
}

type scanResult struct {
	File  string
	Error error
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
		flagSet.StringVarP(&opts.Severity, "severity", "s", "MEDIUM,HIGH,CRITICAL", "severity"),
	)

	if err := flagSet.Parse(); err != nil {
		log.Fatalf("Error parsing flags: %s", err)
	}

	if len(opts.Files) == 0 {
		log.Fatal("Input is required")
	}

	// Create output directory if not exists
	if err := os.MkdirAll(opts.Output, 0755); err != nil {
		log.Fatalf("Error creating output directory: %s", err)
	}

	// Run concurrent scans
	results := scanFilesAsync(opts.Files, opts.Output, opts.Severity, opts.Concurrency)

	// Process results
	successCount := 0
	failCount := 0
	for result := range results {
		if result.Error != nil {
			log.Printf("✗ Failed to scan %s: %s", result.File, result.Error)
			failCount++
		} else {
			fmt.Printf("✓ Successfully scanned: %s\n", result.File)
			successCount++
		}
	}

	fmt.Printf("\nScan completed: %d succeeded, %d failed\n", successCount, failCount)
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
		err := scanFile(file, outputDir, severity)
		results <- scanResult{
			File:  file,
			Error: err,
		}
	}
}

// scanFile executes trivy scan for a single file
func scanFile(inputFile, outputDir, severity string) error {
	// Check if file exists
	if _, err := os.Stat(inputFile); os.IsNotExist(err) {
		return fmt.Errorf("file does not exist: %s", inputFile)
	}

	// Generate output filename based on input filename
	baseName := filepath.Base(inputFile)
	baseName = strings.TrimSuffix(baseName, filepath.Ext(baseName))
	outputFile := filepath.Join(outputDir, fmt.Sprintf("%s-report.html", baseName))

	fmt.Printf("Scanning %s...\n", inputFile)

	// Prepare trivy command
	cmd := exec.Command("trivy", "image",
		"--input", inputFile,
		"--severity", severity,
		"--format", "template",
		"--template", "@trivy-template.html",
		"--output", outputFile,
	)

	// Capture output for better error reporting
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("trivy command failed: %w, output: %s", err, string(output))
	}

	return nil
}

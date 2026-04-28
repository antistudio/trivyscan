package main

import (
	"log"

	"github.com/projectdiscovery/goflags"
)

type options struct {
	Files  goflags.StringSlice
	Output string
}

func main() {
	opts := &options{}

	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription("Scan trivy")

	flagSet.CreateGroup("input", "Input",
		flagSet.StringSliceVarP(&opts.Files, "input", "i", nil, "file or list file",
			goflags.CommaSeparatedStringSliceOptions),
	)

	flagSet.CreateGroup("output", "Output",
		flagSet.StringVarP(&opts.Output, "output", "o", ".", "output directory (required)"),
	)

	if err := flagSet.Parse(); err != nil {
		log.Fatalf("Error parsing flags: %s", err)
	}

	if len(opts.Files) == 0 {
		log.Fatal("Input is required")
	}
}

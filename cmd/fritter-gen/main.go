package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	fritterwasm "github.com/sliverarmory/Fritter/dist"
	fritterwazero "github.com/sliverarmory/Fritter/wazero"
)

var version = "dev"

func main() {
	var (
		inputPath = flag.String("input", "", "path to the input EXE/DLL/VBS/JS")
		method    = flag.String("method", "", "DLL export to invoke")
		output    = flag.String("output", "loader.bin", "path to the output artifact")
		wasmPath  = flag.String("wasm", os.Getenv("FRITTER_WASM_PATH"), "path to a Fritter WASM module (overrides the embedded module)")
		showVer   = flag.Bool("version", false, "print version information")
	)
	flag.Parse()

	if *showVer {
		fmt.Printf("fritter-gen %s\n", version)
		return
	}

	if *inputPath == "" {
		fmt.Fprintln(os.Stderr, "missing required -input")
		os.Exit(2)
	}

	ctx := context.Background()

	var (
		runner *fritterwazero.Runner
		err    error
	)
	if *wasmPath == "" {
		runner, err = fritterwazero.New(ctx, fritterwasm.Module)
	} else {
		runner, err = fritterwazero.NewFromPath(ctx, *wasmPath)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "create runner: %v\n", err)
		os.Exit(1)
	}
	defer runner.Close(ctx)

	result, err := runner.Generate(ctx, fritterwazero.Options{
		InputPath:  *inputPath,
		Method:     *method,
		OutputName: filepath.Base(*output),
		Entropy:    fritterwazero.EntropyNone,
		Chunked:    fritterwazero.Bool(false),
	})
	if err != nil {
		if result.Stdout != "" {
			fmt.Fprintln(os.Stderr, result.Stdout)
		}
		if result.Stderr != "" {
			fmt.Fprintln(os.Stderr, result.Stderr)
		}
		fmt.Fprintf(os.Stderr, "generate artifact: %v\n", err)
		os.Exit(1)
	}

	if err := os.MkdirAll(filepath.Dir(*output), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "create output directory: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*output, result.Output, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write output: %v\n", err)
		os.Exit(1)
	}

	fmt.Print(result.Stdout)
	if result.Stderr != "" {
		fmt.Fprint(os.Stderr, result.Stderr)
	}
	fmt.Printf("wrote %s (%d bytes)\n", *output, len(result.Output))
}

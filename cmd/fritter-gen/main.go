package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	fritterwazero "github.com/sliverarmory/Fritter/wazero"
)

func main() {
	var (
		inputPath = flag.String("input", "", "path to the input EXE/DLL/VBS/JS")
		method    = flag.String("method", "", "DLL export to invoke")
		output    = flag.String("output", "loader.bin", "path to the output artifact")
		wasmPath  = flag.String("wasm", fritterwazero.DefaultModulePath(), "path to dist/fritter.wasm")
	)
	flag.Parse()

	if *inputPath == "" {
		fmt.Fprintln(os.Stderr, "missing required -input")
		os.Exit(2)
	}

	ctx := context.Background()

	runner, err := fritterwazero.NewFromPath(ctx, *wasmPath)
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

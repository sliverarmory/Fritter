package fritterwazero

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestOptionsArgsCoversReadmeSurface(t *testing.T) {
	chunked := Bool(false)
	opts := Options{
		InputPath:  "/tmp/payload.js",
		Parameters: "arg1 arg2",
		Class:      "Test.Namespace.Loader",
		Method:     "Run",
		Runtime:    "v4.0.30319",
		Domain:     "APPDOM1",
		OutputName: "out.hex",
		Format:     FormatHex,
		Exit:       ExitProcess,
		ForkOffset: 0x1234,
		Entropy:    EntropyNone,
		Headers:    HeadersKeep,
		Chunked:    chunked,
		Unicode:    true,
		Thread:     true,
		DecoyPath:  "/tmp/decoy.dll",
		ModuleName: "MOD12345",
		ServerURL:  "https://example.com/stage/",
	}

	got := opts.Args()
	want := []string{
		"fritter",
		"-k", "2",
		"-c", "Test.Namespace.Loader",
		"-d", "APPDOM1",
		"-e", "1",
		"-f", "8",
		"-i", "payload.js",
		"-m", "Run",
		"-n", "MOD12345",
		"-j", "decoy.dll",
		"-o", "out.hex",
		"-p", "arg1 arg2",
		"-r", "v4.0.30319",
		"-s", "https://example.com/stage/",
		"-t",
		"-w",
		"-x", "2",
		"-y", "1234",
		"-g", "0",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected args:\nwant: %#v\ngot:  %#v", want, got)
	}
}

func TestOutputFileNameDefaults(t *testing.T) {
	cases := map[Format]string{
		FormatBinary:     "loader.bin",
		FormatBase64:     "loader.b64",
		FormatC:          "loader.c",
		FormatRuby:       "loader.rb",
		FormatPython:     "loader.py",
		FormatPowerShell: "loader.ps1",
		FormatCSharp:     "loader.cs",
		FormatHex:        "loader.hex",
	}

	for format, want := range cases {
		got := (Options{InputPath: "payload.js", Format: format}).OutputFileName()
		if got != want {
			t.Fatalf("format %d: want %q, got %q", format, want, got)
		}
	}
}

func TestUsage(t *testing.T) {
	runner := newRunnerOrSkip(t)
	defer runner.Close(context.Background())

	usage, err := runner.Usage(context.Background())
	if err != nil {
		t.Fatalf("usage returned error: %v", err)
	}

	if !strings.Contains(usage, "USAGE") {
		t.Fatalf("usage output did not include usage header:\n%s", usage)
	}
	if !strings.Contains(usage, "--input") {
		t.Fatalf("usage output did not include expected flag list:\n%s", usage)
	}
}

func TestGenerateBinaryOutput(t *testing.T) {
	runner := newRunnerOrSkip(t)
	defer runner.Close(context.Background())

	result, err := runner.Generate(context.Background(), Options{
		InputPath: filepath.Join("testdata", "hello.js"),
		Entropy:   EntropyNone,
		Chunked:   Bool(false),
	})
	if err != nil {
		t.Fatalf("generate returned error: %v\nstdout:\n%s\nstderr:\n%s", err, result.Stdout, result.Stderr)
	}

	if len(result.Output) == 0 {
		t.Fatalf("expected output bytes")
	}
	if result.OutputName != "loader.bin" {
		t.Fatalf("unexpected output name %q", result.OutputName)
	}
	if !strings.Contains(result.Stdout, "JScript") {
		t.Fatalf("stdout did not mention JScript module type:\n%s", result.Stdout)
	}
}

func TestGenerateHexOutputAndStagingModule(t *testing.T) {
	runner := newRunnerOrSkip(t)
	defer runner.Close(context.Background())

	result, err := runner.Generate(context.Background(), Options{
		InputPath:  filepath.Join("testdata", "hello.vbs"),
		OutputName: "payload.hex",
		Format:     FormatHex,
		ServerURL:  "https://example.com/stage/",
		ModuleName: "STAGE123",
		Entropy:    EntropyNone,
		Chunked:    Bool(false),
	})
	if err != nil {
		t.Fatalf("generate returned error: %v\nstdout:\n%s\nstderr:\n%s", err, result.Stdout, result.Stderr)
	}

	if len(result.Output) == 0 || result.OutputName != "payload.hex" {
		t.Fatalf("unexpected output artifact: %#v", result)
	}
	if len(result.Module) == 0 || result.ModuleName != "STAGE123" {
		t.Fatalf("unexpected staging artifact: %#v", result)
	}
	if !isHexLike(result.Output) {
		t.Fatalf("expected hex-encoded output, got %q", string(result.Output[:min(64, len(result.Output))]))
	}
}

func TestInvalidServerURLReturnsCLIError(t *testing.T) {
	runner := newRunnerOrSkip(t)
	defer runner.Close(context.Background())

	_, err := runner.Generate(context.Background(), Options{
		InputPath: filepath.Join("testdata", "hello.js"),
		ServerURL: "ftp://example.invalid/stage/",
		Entropy:   EntropyNone,
	})
	if err == nil {
		t.Fatal("expected error")
	}

	var cliErr *CLIError
	if !errors.As(err, &cliErr) {
		t.Fatalf("expected CLIError, got %T", err)
	}
	if cliErr.ExitCode == 0 {
		t.Fatalf("expected non-zero exit code")
	}
	if !strings.Contains(cliErr.Stdout, "Invalid URL.") {
		t.Fatalf("expected invalid-url message, got:\n%s", cliErr.Stdout)
	}
}

func newRunnerOrSkip(t *testing.T) *Runner {
	t.Helper()

	wasmPath := DefaultModulePath()
	if _, err := os.Stat(wasmPath); err != nil {
		t.Skipf("wasm artifact not present at %s", wasmPath)
	}

	runner, err := NewFromPath(context.Background(), wasmPath)
	if err != nil {
		t.Fatalf("create runner: %v", err)
	}
	return runner
}

func isHexLike(data []byte) bool {
	if len(data) == 0 {
		return false
	}

	for _, b := range data {
		switch {
		case b >= '0' && b <= '9':
		case b >= 'a' && b <= 'f':
		case b >= 'A' && b <= 'F':
		case b == '\\':
		case b == 'x':
		case b == '\n':
		case b == '\r':
		default:
			return false
		}
	}

	return true
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

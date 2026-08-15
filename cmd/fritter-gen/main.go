package main

import (
	"bytes"
	"context"
	"debug/pe"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sliverarmory/Fritter"
)

var version = "dev"

type stringListFlag []string

func (values *stringListFlag) String() string {
	return strings.Join(*values, ",")
}

func (values *stringListFlag) Set(value string) error {
	*values = append(*values, value)
	return nil
}

type payloadOptions struct {
	arguments      []string
	class          string
	method         string
	runtimeVersion string
	appDomain      string
	parameter      string
	utf16Parameter bool
}

func main() {
	var arguments stringListFlag
	var (
		inputPath = flag.String("input", "", "path to the input EXE/DLL/VBS/JS")
		class     = flag.String("class", "", ".NET DLL class to invoke")
		method    = flag.String("method", "", "native DLL export or .NET DLL method to invoke")
		runtime   = flag.String("runtime", "", ".NET runtime version override")
		domain    = flag.String("domain", "", ".NET AppDomain name")
		parameter = flag.String("parameter", "", "raw native DLL export parameter")
		utf16     = flag.Bool("utf16-parameter", false, "pass the native DLL parameter as UTF-16")
		output    = flag.String("output", "loader.bin", "path to the output artifact")
		wasmPath  = flag.String("wasm", os.Getenv("FRITTER_WASM_PATH"), "path to a Fritter WASM module (overrides the embedded module)")
		showVer   = flag.Bool("version", false, "print version information")
	)
	flag.Var(&arguments, "arg", "target argument; may be repeated")
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
	payloadBytes, err := os.ReadFile(*inputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read input: %v\n", err)
		os.Exit(1)
	}
	payload, err := payloadForPath(*inputPath, payloadBytes, payloadOptions{
		arguments:      arguments,
		class:          *class,
		method:         *method,
		runtimeVersion: *runtime,
		appDomain:      *domain,
		parameter:      *parameter,
		utf16Parameter: *utf16,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "configure payload: %v\n", err)
		os.Exit(2)
	}

	var (
		generator *fritter.Generator
	)
	if *wasmPath == "" {
		generator, err = fritter.New(ctx)
	} else {
		wasm, readErr := os.ReadFile(*wasmPath)
		if readErr != nil {
			fmt.Fprintf(os.Stderr, "read WASM module: %v\n", readErr)
			os.Exit(1)
		}
		generator, err = fritter.NewWithWASM(ctx, wasm)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "create generator: %v\n", err)
		os.Exit(1)
	}
	defer generator.Close()

	// Preserve fritter-gen's historical default. Library callers get
	// EntropyDefault when no option is supplied.
	result, err := generator.Generate(ctx, payload,
		fritter.WithEntropy(fritter.EntropyNone),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "generate artifact: %v\n", err)
		os.Exit(1)
	}

	if err := os.MkdirAll(filepath.Dir(*output), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "create output directory: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*output, result.Loader, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write output: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("wrote %s (%d bytes)\n", *output, len(result.Loader))
}

func payloadForPath(path string, data []byte, options payloadOptions) (fritter.Payload, error) {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".exe":
		managed, dll, err := inspectPE(data)
		if err != nil {
			return nil, err
		}
		if dll {
			return nil, fmt.Errorf("input has an .exe name but PE contents identify a DLL")
		}
		if options.class != "" || options.method != "" || options.parameter != "" || options.utf16Parameter {
			return nil, fmt.Errorf("DLL invocation flags are only valid with a DLL input")
		}
		if managed {
			return fritter.DotNetExecutable{
				Data:           data,
				Arguments:      options.arguments,
				RuntimeVersion: options.runtimeVersion,
				AppDomain:      options.appDomain,
			}, nil
		}
		if options.runtimeVersion != "" || options.appDomain != "" {
			return nil, fmt.Errorf("-runtime and -domain are only valid with a .NET input")
		}
		return fritter.NativeExecutable{Data: data, Arguments: options.arguments}, nil
	case ".dll":
		managed, dll, err := inspectPE(data)
		if err != nil {
			return nil, err
		}
		if !dll {
			return nil, fmt.Errorf("input has a .dll name but PE contents identify an executable")
		}
		if managed {
			if options.parameter != "" || options.utf16Parameter {
				return nil, fmt.Errorf("-parameter and -utf16-parameter are only valid with a native DLL")
			}
			return fritter.DotNetDLL{
				Data:           data,
				Class:          options.class,
				Method:         options.method,
				Arguments:      options.arguments,
				RuntimeVersion: options.runtimeVersion,
				AppDomain:      options.appDomain,
			}, nil
		}
		if options.class != "" || options.runtimeVersion != "" || options.appDomain != "" || len(options.arguments) != 0 {
			return nil, fmt.Errorf("-class, -runtime, -domain, and -arg are only valid with a .NET DLL")
		}
		return fritter.NativeDLL{
			Data:           data,
			Export:         options.method,
			Parameter:      options.parameter,
			UTF16Parameter: options.utf16Parameter,
		}, nil
	case ".vbs":
		if options.hasInvocationOptions() {
			return nil, fmt.Errorf("invocation flags are not valid with a script input")
		}
		return fritter.VBScript{Source: data}, nil
	case ".js":
		if options.hasInvocationOptions() {
			return nil, fmt.Errorf("invocation flags are not valid with a script input")
		}
		return fritter.JScript{Source: data}, nil
	default:
		return nil, fmt.Errorf("unsupported input extension %q", filepath.Ext(path))
	}
}

func (options payloadOptions) hasInvocationOptions() bool {
	return len(options.arguments) != 0 || options.class != "" || options.method != "" ||
		options.runtimeVersion != "" || options.appDomain != "" || options.parameter != "" ||
		options.utf16Parameter
}

func inspectPE(data []byte) (managed bool, dll bool, err error) {
	file, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		return false, false, fmt.Errorf("parse PE input: %w", err)
	}
	defer file.Close()

	dll = file.Characteristics&pe.IMAGE_FILE_DLL != 0
	const comDescriptor = pe.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR
	switch header := file.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		managed = header.NumberOfRvaAndSizes > comDescriptor && header.DataDirectory[comDescriptor].VirtualAddress != 0
	case *pe.OptionalHeader64:
		managed = header.NumberOfRvaAndSizes > comDescriptor && header.DataDirectory[comDescriptor].VirtualAddress != 0
	default:
		return false, false, fmt.Errorf("parse PE input: unsupported optional header type %T", file.OptionalHeader)
	}
	return managed, dll, nil
}

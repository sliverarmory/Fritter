# Fritter Go package

The root package, `github.com/sliverarmory/Fritter`, generates Fritter loaders entirely in process. It embeds the canonical Fritter WebAssembly module and runs it through wazero, so consumers do not need a Fritter executable, a WASM sidecar, a C toolchain, or CGO at runtime.

The API accepts payload bytes and returns artifact bytes. Host input and output paths belong to the calling application; they are not part of the library contract. Internally, the package invokes Fritter's direct WebAssembly generation bridge rather than constructing or parsing a Fritter command line.

Generated loaders target 64-bit Windows, regardless of the operating system on which the Go package runs.

Fritter requires Go 1.24 or newer.

## Install

```sh
go get github.com/sliverarmory/Fritter@latest
```

```go
import "github.com/sliverarmory/Fritter"
```

## Generate a loader

Pass the concrete payload directly to `Generate`:

```go
result, err := fritter.Generate(ctx,
	fritter.NativeExecutable(payload),
	fritter.WithArguments("arg1", "arg2"),
)
```

No request or loader-configuration struct is needed. With no options, Fritter returns a raw binary loader that embeds the payload, uses the normal entropy mode, and exits the current thread after the payload returns.

The package-level `Generate` function compiles the embedded module, performs one generation, closes the WebAssembly runtime, and returns the generated artifacts. A complete file-oriented caller can keep all host filesystem access outside Fritter:

```go
package main

import (
	"context"
	"log"
	"os"

	"github.com/sliverarmory/Fritter"
)

func main() {
	payload, err := os.ReadFile("payload.exe")
	if err != nil {
		log.Fatal(err)
	}

	result, err := fritter.Generate(context.Background(),
		fritter.NativeExecutable(payload),
		fritter.WithArguments("--config", `C:\Program Files\Example\config.json`),
	)
	if err != nil {
		log.Fatal(err)
	}

	if err := os.WriteFile("loader.bin", result.Loader, 0o600); err != nil {
		log.Fatal(err)
	}
}
```

The package never writes a generated artifact to the host filesystem. The caller decides whether and where to store `Result.Loader` and an optional staged module.

## Payload, options, and result

Both generation entry points take a concrete `Payload` followed by optional typed settings:

```go
func Generate(ctx context.Context, payload Payload, options ...GenerateOption) (Result, error)
func (g *Generator) Generate(ctx context.Context, payload Payload, options ...GenerateOption) (Result, error)
```

`Payload` is a sealed interface implemented by six byte-slice marker types. Convert payload bytes to the marker that describes their format; the conversion does not copy the bytes. `Generate` does not mutate or retain them, but callers must not modify the backing slice concurrently with an active call. Fritter verifies that PE contents match the selected native or managed EXE/DLL marker.

`GenerateOption` is opaque. Invocation options are described below; generation-wide options are `WithFormat`, `WithExit`, `WithForkRVA`, `WithEntropy`, `PreservePEHeaders`, `WithDecoyModulePath`, and `WithHTTPStaging`. Options are applied from left to right, so the last occurrence of the same setting wins. Option values returned by this package can be reused across calls, including concurrent calls.

A successful call returns:

```go
type Result struct {
	Loader       []byte
	StagedModule *StagedModule
}

type StagedModule struct {
	Name string
	URL  url.URL
	Data []byte
}
```

`Loader` contains the requested output representation. `StagedModule` is `nil` when the payload is embedded in the loader; when present, its `Data` is the opaque module body and is not affected by `WithFormat`. Returned byte slices belong to the caller, and generation does not mutate the payload bytes.

## Payloads and invocation options

Convert a byte slice to exactly one payload marker, then add only the invocation options supported by that marker:

| Marker expression | Payload bytes | Compatible invocation options |
| --- | --- | --- |
| `NativeExecutable(data)` | Native x64 Windows executable | `WithArguments`, `RunInThread` |
| `NativeDLL(data)` | Native x64 Windows DLL | `WithExport`, `WithParameter`, `WithUTF16Parameter` |
| `DotNetExecutable(data)` | Compatible .NET executable assembly | `WithArguments`, `WithRuntimeVersion`, `WithAppDomain` |
| `DotNetDLL(data)` | Compatible .NET library assembly | `WithMethod` (required), `WithArguments`, `WithRuntimeVersion`, `WithAppDomain` |
| `VBScript(source)` | VBScript source | None |
| `JScript(source)` | JScript source | None |

Passing an invocation option to an incompatible payload returns a `*ValidationError`. This check uses whether the option was supplied, not whether its value happens to be empty, so configuration mistakes do not silently become defaults.

### Arguments

`WithArguments(arguments ...string)` supplies target arguments without exposing a command-line string:

```go
fritter.WithArguments("first", "two words", "")
```

It is valid for native executables, .NET executables, and .NET DLLs. Pass an existing slice as `WithArguments(arguments...)`. The option clones its variadic values when constructed, so it can be safely reused and is unaffected by later changes to the caller's slice.

Omitting `WithArguments` means no arguments. `WithArguments()` also means no arguments and clears an earlier `WithArguments` option. `WithArguments("")` is different: it supplies one empty argument.

Fritter composes a Windows command line that round-trips through `CommandLineToArgvW`; it does not join values with a plain space. Arguments containing whitespace or quotes are quoted, and backslashes before a quote or at the end of a quoted argument are doubled according to Windows parsing rules. Invalid UTF-8 and NUL bytes are rejected.

A native executable receives these values as `argv[1:]`; Fritter supplies a private synthetic `argv[0]`. A .NET executable receives them through a `Main(string[])` entry point, and each value supplied to a .NET DLL becomes a separate static-method argument.

The fully encoded argument list must fit within Fritter's 250-byte native buffer. Validation fails instead of silently truncating it. A native executable that reads its narrow command line can still observe conversion through the target process's active Windows code page.

### Native executable thread mode

`RunInThread()` runs a native executable's unmanaged entry point on a new thread and intercepts common process-exit imports where possible. It is not valid for native DLLs, .NET assemblies, or scripts.

### Native DLL exports and parameters

Fritter always invokes a native DLL's `DllMain`. Use `WithExport` to invoke one named export afterward:

```go
result, err := fritter.Generate(ctx,
	fritter.NativeDLL(dll),
	fritter.WithExport("Run"),
	fritter.WithUTF16Parameter("example"),
)
```

With no parameter option, the selected export is called with no arguments. `WithParameter` passes one pointer to a NUL-terminated narrow UTF-8 buffer. `WithUTF16Parameter` accepts a Go UTF-8 string, converts it on the target, and passes one pointer to a NUL-terminated UTF-16 buffer. Neither option parses, quotes, or splits its value as arguments.

Native export invocation is intentionally low-level:

- A parameter requires `WithExport`.
- Parameter text must be non-empty, valid UTF-8, NUL-free, and at most 250 encoded bytes. An empty parameter buffer cannot be represented; omit the parameter option to make a no-argument call.
- Repeated narrow or UTF-16 parameter options replace one another, and the last option determines both the value and encoding.
- The export must actually have a compatible no-argument or single-pointer signature. Fritter cannot validate or adapt the function signature.
- Any export return value is ignored.
- The parameter pointer is borrowed for the duration of the export call. The export must not retain it after returning.

`WithExport` performs an exact, case-sensitive name lookup. Export names must be valid UTF-8 without NUL bytes and are limited to 255 bytes.

After `DllMain` and any selected export return, the generated loader intentionally keeps the native DLL's mapped image resident while the host process remains alive. Native DLLs may retain threads, callbacks, runtime state, or pointers into their code and data, so immediately unmapping the image would make those references invalid. Account for that target-side residual memory when invoking native DLLs; the Go generator itself still retains no payload bytes after `Generate` returns.

### .NET invocation

A .NET executable runs its assembly entry point. A .NET DLL requires one `WithMethod(class, method)` option identifying the namespace-qualified class and static method:

```go
result, err := fritter.Generate(ctx,
	fritter.DotNetDLL(assembly),
	fritter.WithMethod("Example.Commands", "Run"),
	fritter.WithArguments("first", "second"),
	fritter.WithRuntimeVersion("v4.0.30319"),
	fritter.WithAppDomain("example"),
)
```

`WithRuntimeVersion` and `WithAppDomain` are valid for either .NET marker. Omitting the runtime version uses the assembly metadata; omitting the AppDomain uses Fritter's default behavior. Supplying an empty value restores that default when replacing an earlier option.

Class, method, and runtime-version strings are limited to 255 bytes. A class and method are both required and must not be blank for a .NET DLL. An explicit AppDomain is limited to eight bytes. These strings must be valid UTF-8 and NUL-free, and the target loader converts them to UTF-16.

### Scripts

`VBScript(source)` and `JScript(source)` pass source bytes to the corresponding Windows Active Scripting engine and accept no invocation options. The target loader decodes source through the target process's active Windows code page; supply source in that encoding when it contains non-ASCII text.

## Generation options

Omit all options for the normal defaults:

| Setting | Default | Non-default option |
| --- | --- | --- |
| Loader representation | `FormatBinary` | `WithFormat(format)` |
| Exit behavior | `ExitThread` | `WithExit(exit)` |
| Host-image continuation | Disabled | `WithForkRVA(rva)` |
| Entropy | `EntropyDefault` | `WithEntropy(entropy)` |
| Mapped PE headers | Overwrite | `PreservePEHeaders()` |
| Module overloading | Disabled | `WithDecoyModulePath(path)` |
| Payload placement | Embedded | `WithHTTPStaging(baseURL, ...)` |

For example:

```go
result, err := fritter.Generate(ctx, fritter.NativeExecutable(payload),
	fritter.WithFormat(fritter.FormatBase64),
	fritter.WithExit(fritter.ExitProcess),
	fritter.WithForkRVA(0x1234),
	fritter.WithEntropy(fritter.EntropyNames),
	fritter.PreservePEHeaders(),
	fritter.WithDecoyModulePath(`C:\Windows\System32\version.dll`),
)
```

`WithForkRVA` applies to the host image and may be used with any payload type. `PreservePEHeaders` and `WithDecoyModulePath` apply only to native PE payloads; using either with a .NET assembly or script returns a validation error.

The path passed to `WithDecoyModulePath` is the exact Windows path that the generated loader will use on the target. It is not a host-side input file, and the Go package does not read or stage it. The loader consumes it through a narrow Windows file API, so non-ASCII target paths follow the target process's active code page.

### Exit behavior

| Constant | Behavior |
| --- | --- |
| `ExitThread` | Exit the current thread after execution. This is the default. |
| `ExitProcess` | Terminate the host process. |
| `ExitBlock` | Block after execution without normal cleanup or return. |

### Entropy

| Constant | Behavior |
| --- | --- |
| `EntropyDefault` | Random names plus cryptographic protection. This is the default. |
| `EntropyNames` | Random names without the optional module-encryption layer. |
| `EntropyNone` | Disable the optional name and cryptographic-randomization axes. |

The WebAssembly runtime still supplies secure randomness for generation machinery that always requires it, even when `EntropyNone` is selected.

## Output formats

Pass `WithFormat` to control the representation placed in `Result.Loader`:

| Constant | Representation |
| --- | --- |
| `FormatBinary` | Raw loader bytes. This is the zero-value default. |
| `FormatBase64` | Base64 text. |
| `FormatC` | C source representation. |
| `FormatRuby` | Ruby source representation. |
| `FormatPython` | Python 3 source representation using a `bytes` value. |
| `FormatPowerShell` | PowerShell source representation. |
| `FormatCSharp` | C# source representation. |
| `FormatHex` | Hexadecimal text. |
| `FormatUUID` | UUID strings. |

All representations are returned as `[]byte`; text formats are not written to files automatically.

## HTTP staging

By default, the generated loader embeds the payload. Pass `WithHTTPStaging` to return the payload module separately from the loader:

```go
stageURL, err := url.Parse("https://example.com/fritter/")
if err != nil {
	return err
}

result, err := fritter.Generate(ctx,
	fritter.JScript(source),
	fritter.WithHTTPStaging(stageURL,
		fritter.WithStagedModuleName("MOD12345"),
	),
)
```

```go
func WithHTTPStaging(baseURL *url.URL, options ...HTTPStagingOption) GenerateOption
func WithStagedModuleName(name string) HTTPStagingOption
```

The base URL must use HTTP or HTTPS and include a valid ASCII hostname; use an IDNA hostname for internationalized domains. Its path is treated as a directory and is restricted to unescaped URL-safe ASCII path characters. Query strings, fragments, explicitly escaped paths, and non-ASCII serialized URLs are rejected because the native loader appends the module name and parses the result with WinINet. URL user information is preserved for Fritter's HTTP Basic Authentication support; decoded usernames and passwords must use printable ASCII and are each limited to 63 bytes. Fritter clones the URL, so the option does not retain the caller's mutable `url.URL` value.

After scheme normalization and addition of a trailing slash, the base URL must not exceed 247 bytes. This leaves room for Fritter's eight-byte module name in the native configuration.

`WithStagedModuleName` is optional. Its value must be at most eight URL-safe ASCII bytes and contain no path separators. When the option is omitted, the package generates an eight-character name; `EntropyNone` uses the deterministic compatibility name `AAAAAAAA`, while the other entropy modes use secure randomness. The final entropy setting is used regardless of whether `WithEntropy` appears before or after `WithHTTPStaging`. `Result.StagedModule` reports the final name, the URL embedded in the loader, and the bytes that must be served there.

The current target loader intentionally accepts invalid HTTPS certificates, including name, date, trust-chain, usage, and revocation failures. Treat HTTPS staging as transport encryption without server-authentication enforcement by the loader unless you build a custom module with a stricter HTTP client. It does not follow redirects, and the configured module URL must return HTTP 200 directly.

Generation never uploads the module and makes no network request. Hosting `StagedModule.Data` at `StagedModule.URL` is the caller's responsibility.

## Reusing a generator

The package-level `Generate` function is convenient for a single artifact. When generating more than one artifact, compile the embedded module once:

```go
ctx := context.Background()

generator, err := fritter.New(ctx)
if err != nil {
	return err
}
defer generator.Close()

first, err := generator.Generate(ctx, fritter.JScript(firstSource))
if err != nil {
	return err
}

second, err := generator.Generate(ctx, fritter.VBScript(secondSource),
	fritter.WithFormat(fritter.FormatBase64),
)
if err != nil {
	return err
}

_, _ = first, second
```

Each call creates a fresh WebAssembly instance and isolated guest filesystem while reusing the compiled module. A `Generator` may service concurrent `Generate` calls. `Close` is also concurrency-safe: it waits for active calls, releases the compiled module and runtime, and may be called more than once. The owner remains responsible for closing the generator when it is no longer needed.

Each embedded guest starts with 64 MiB of linear memory, so applications generating many loaders concurrently should bound their parallelism.

Generation observes context cancellation and deadlines. `Close` has no context argument and completes runtime cleanup synchronously.

## Custom WebAssembly modules

`NewWithWASM` creates a reusable generator from caller-supplied module bytes:

```go
wasm, err := os.ReadFile("custom-fritter.wasm")
if err != nil {
	return err
}

generator, err := fritter.NewWithWASM(ctx, wasm)
if err != nil {
	return err
}
defer generator.Close()
```

A custom module must implement the same direct Fritter bridge ABI as the embedded module. Required exports and their signatures are validated during initialization. `New` always uses the embedded module and does not consult `FRITTER_WASM_PATH`; selecting a custom module is explicit.

## Errors and validation

Invalid payloads or generation options return `*ValidationError` before generation begins:

```go
type ValidationError struct {
	Field   string
	Problem string
}
```

Validation includes, among other checks:

- a non-nil supported payload with non-empty bytes;
- non-zero generation and HTTP staging options;
- invocation options compatible with the selected payload marker;
- required .NET DLL class and method names;
- a native DLL export and compatible non-empty text when a parameter is supplied;
- valid enum values and string-size limits;
- NUL-free arguments, names, and target paths;
- native-PE-only header and decoy options used with a native payload;
- a valid HTTP staging URL and module name.

`ValidationError.Field` names the payload or option directly; invocation fields are flat and do not refer to removed payload-struct fields:

| Area | Field values |
| --- | --- |
| Payload | `payload` |
| Invocation | `arguments`, `arguments[n]`, `runInThread`, `export`, `parameter`, `class`, `method`, `runtimeVersion`, `appDomain` |
| Generation | `format`, `exit`, `entropy`, `preservePEHeaders`, `decoyModulePath` |
| Staging and option plumbing | `staging.baseURL`, `staging.moduleName`, `options[n]`, `staging.options[n]` |

Errors reported by the Fritter generation core use `*GenerationError`:

```go
type GenerationError struct {
	Code ErrorCode
}
```

The generation engine validates the payload contents, including PE structure and architecture, requested DLL exports, and unsupported mixed assemblies. The error text describes a failure, while `Code` permits programmatic handling without parsing a message:

```go
result, err := generator.Generate(ctx, fritter.NativeExecutable(executable))
if err != nil {
	var validationErr *fritter.ValidationError
	var generationErr *fritter.GenerationError

	switch {
	case errors.As(err, &validationErr):
		log.Printf("invalid %s: %s", validationErr.Field, validationErr.Problem)
	case errors.As(err, &generationErr):
		log.Printf("Fritter generation failed with code %d", generationErr.Code)
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	default:
		return err
	}
	return err
}
_ = result
```

`ErrorCode.String` returns the description used by `GenerationError`. The exported codes are:

| Constant | Code | Meaning |
| --- | ---: | --- |
| `ErrorFileNotFound` | 1 | An expected guest file was not found. |
| `ErrorFileEmpty` | 2 | The payload is empty. |
| `ErrorFileAccess` | 3 | A guest artifact could not be opened. |
| `ErrorFileInvalid` | 4 | The payload format or structure is invalid. |
| `ErrorDotNetParameters` | 5 | A .NET DLL is missing its class or method. |
| `ErrorOutOfMemory` | 6 | Native generation could not allocate memory. |
| `ErrorInvalidArchitecture` | 7 | The selected architecture is invalid. |
| `ErrorInvalidURL` | 8 | The staging URL is invalid. |
| `ErrorURLTooLong` | 9 | The staging URL exceeds the native limit. |
| `ErrorInvalidParameter` | 10 | A native bridge parameter is invalid. |
| `ErrorRandom` | 11 | Secure random generation failed. |
| `ErrorDLLExport` | 12 | The requested native DLL export was not found. |
| `ErrorArchitectureMismatch` | 13 | The payload architecture is unsupported. |
| `ErrorDLLParameter` | 14 | A native DLL parameter was supplied without an export. |
| `ErrorInvalidFormat` | 16 | The output format is invalid. |
| `ErrorCompressionEngine` | 17 | The compression engine is invalid. |
| `ErrorCompression` | 18 | Payload compression failed. |
| `ErrorInvalidEntropy` | 19 | The entropy mode is invalid. |
| `ErrorMixedAssembly` | 20 | A mixed native and managed assembly is unsupported. |
| `ErrorInvalidHeaders` | 21 | The PE-header option is invalid. |
| `ErrorInvalidDecoy` | 22 | The decoy module path is invalid. |
| `ErrorPayloadTypeMismatch` | 23 | The payload bytes do not match the selected concrete payload type. |

WebAssembly compilation, ABI, allocation, and runtime failures are returned as wrapped Go errors. Context cancellation and deadline errors remain compatible with `errors.Is`. No loader or staged module should be used when generation returns an error.

Calling `Generate` after `Generator.Close` returns `ErrClosed`, which can be detected with `errors.Is`.

## Embedded module behavior

- Importing the root package embeds the canonical `dist/fritter.wasm` artifact in the final Go program.
- The embedded artifact is a WASI/WASMFS reactor with no mounted host filesystem. Payload bytes enter its isolated memory only for the duration of a generation call.
- WASI randomness is backed by `crypto/rand`.
- The WASM build does not use aPLib compression, unlike native builds linked with the bundled aPLib library.
- The canonical embedded module shares its per-build polymorphism constants with every program importing that Fritter version. Build and supply a fresh module when unique per-build constants are required.

To rebuild the canonical module after changing the native implementation:

```sh
scripts/build-loader-blobs.sh
scripts/build-wasm.sh
go test ./...
```

Consumers do not need these build tools unless they are producing a custom Fritter WebAssembly module.

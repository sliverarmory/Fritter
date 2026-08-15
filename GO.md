# Fritter Go package

The root package, `github.com/sliverarmory/Fritter`, generates 64-bit Windows Fritter loaders entirely in process. It embeds the canonical Fritter WebAssembly module and runs it with wazero, so consumers do not need a Fritter executable, a WASM sidecar, a C toolchain, or CGO at runtime.

The API accepts payload bytes in domain-specific request structs and returns artifact bytes. Host input and output paths belong to the calling application; Fritter never reads or writes them.

Fritter requires Go 1.24 or newer.

## Install

```sh
go get github.com/sliverarmory/Fritter@latest
```

```go
import "github.com/sliverarmory/Fritter"
```

## Generate a loader

Describe the payload and its entrypoint directly:

```go
result, err := fritter.Generate(ctx, fritter.Request{
	Payload: fritter.NativeDLL{
		Image: dll,
		Export: &fritter.NativeDLLExport{
			Name: "Run",
		},
	},
})
```

This request always invokes the DLL's `DllMain`, then invokes the exact, case-sensitive, parameterless export named `Run`. With no other fields set, Fritter returns a raw binary loader with the payload embedded, uses its normal entropy mode, and exits the current thread after execution.

The package-level function is the one-shot API:

```go
func Generate(ctx context.Context, request Request) (Result, error)
```

It compiles the embedded module, performs one generation, closes the runtime, and returns the artifacts. Use a reusable `Generator` when producing multiple loaders.

## Deliberate invocation boundary

The root Go package intentionally does not expose target command-line, argv, or parameter serialization:

- Native executables receive no caller-supplied arguments. Fritter supplies only its private synthetic `argv[0]`.
- A .NET executable entrypoint that declares `string[]` receives an empty array.
- A native DLL export must be parameterless.
- A .NET DLL entrypoint must be a parameterless public static method.
- There is no raw-command-line escape hatch.

This is an API boundary, not an omitted convenience helper. The standalone native Fritter engine has lower-level string transports, but the Go package does not surface them as domain concepts.

## Request and result

```go
type Request struct {
	Payload Payload
	Format  Format
	Loader  LoaderConfig
	Staging *HTTPStaging
}

type LoaderConfig struct {
	Exit             ExitBehavior
	Entropy          Entropy
	HostContinuation *HostImageContinuation
}

type HostImageContinuation struct {
	EntryPointRVA uint32
}
```

`Payload` is a sealed interface implemented by `NativeExecutable`, `NativeDLL`, `DotNetExecutable`, `DotNetDLL`, `VBScript`, and `JScript`. The concrete struct identifies the payload format and makes payload-specific settings available only where they apply.

Request fields use these zero-value defaults:

| Field | Zero-value behavior |
| --- | --- |
| `Format` | `FormatBinary`: return raw loader bytes. |
| `Loader.Exit` | `ExitThread`: exit the current thread after execution. |
| `Loader.Entropy` | `EntropyDefault`: randomize names and cryptographic material. |
| `Loader.HostContinuation` | `nil`: do not resume a host image. |
| `Staging` | `nil`: embed the payload in the loader. |

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

`Loader` contains the representation selected by `Request.Format`. `StagedModule` is nil when the payload is embedded. When staging is enabled, `StagedModule.Data` is the opaque module body and is not transformed by `Request.Format`.

Returned byte slices belong to the caller. Generation does not mutate or retain payload bytes, but the caller must not modify their backing slices concurrently with an active call.

## Payloads

### Native executable

```go
type NativeExecutable struct {
	Image []byte
	Flags NativeExecutableFlags
	PE    NativePEConfig
}

type NativeExecutableFlags uint32

const (
	NativeExecutableRunInThread NativeExecutableFlags = 1 << iota
)
```

`Image` must contain a native x64 Windows executable. Unknown flag bits are rejected.

`NativeExecutableRunInThread` runs the unmanaged entrypoint on a new thread, waits for that thread, and replaces common statically imported process-exit functions with `RtlExitUserThread` where possible. It cannot intercept exit functions resolved dynamically or through unsupported import forms. Thread mode leaves the mapped PE image resident while the host remains alive so CRT callbacks retain valid continuations.

This flag is distinct from `LoaderConfig.HostContinuation`: thread mode changes how the payload executable entrypoint runs, while host continuation changes execution of the containing host image.

### Native DLL

```go
type NativeDLL struct {
	Image  []byte
	Export *NativeDLLExport
	PE     NativePEConfig
}

type NativeDLLExport struct {
	Name string
}
```

`Image` must contain a native x64 Windows DLL. Fritter always invokes `DllMain` with `DLL_PROCESS_ATTACH`. A nil `Export` stops there. A non-nil `Export` selects one named export to invoke afterward.

Export lookup is exact, case-sensitive, and name-only; ordinal selection is not supported. The name must be non-blank, valid UTF-8, NUL-free, and at most 255 bytes. The export must have a compatible parameterless signature. Fritter cannot validate or adapt the native signature, and it ignores the return value.

After `DllMain` and any selected export return, the loader intentionally keeps the DLL mapping resident. A DLL may retain threads, callbacks, runtime state, or pointers into its mapped image, so immediately unmapping it would be unsafe. The Go generator itself does not retain the DLL bytes after generation returns.

### Native PE mapping

Both native payload structs contain:

```go
type NativePEConfig struct {
	Headers         PEHeaders
	DecoyModulePath string
}

type PEHeaders uint8

const (
	PEHeadersOverwrite PEHeaders = iota
	PEHeadersPreserve
)
```

`PEHeadersOverwrite` is the zero-value default and permits the mapper to overwrite the payload's mapped headers. `PEHeadersPreserve` keeps them.

`DecoyModulePath` enables module overloading with an exact target-side Windows path. The Go package does not read or inspect that path. It must use printable ASCII, contain no NUL byte, and be at most 519 bytes. The target loader opens it with `CreateFileA`; restricting the API to ASCII avoids target-code-page ambiguity. Generation cannot verify that the target file exists or has a sufficient image size.

### .NET executable

```go
type DotNetExecutable struct {
	Assembly []byte
	Runtime  DotNetRuntime
}
```

`Assembly` must contain a compatible managed executable. Fritter invokes the entrypoint declared in the assembly. An entrypoint with no parameters is called directly; an entrypoint declaring `string[]` receives an empty array.

### .NET DLL

```go
type DotNetDLL struct {
	Assembly   []byte
	EntryPoint DotNetStaticMethod
	Runtime    DotNetRuntime
}

type DotNetStaticMethod struct {
	TypeName   string
	MethodName string
}
```

`EntryPoint.TypeName` is the namespace-qualified managed type, and `EntryPoint.MethodName` is the public static parameterless method to invoke. Both are required, must be valid UTF-8 and NUL-free, and are limited to 255 bytes.

For example:

```go
result, err := fritter.Generate(ctx, fritter.Request{
	Payload: fritter.DotNetDLL{
		Assembly: assembly,
		EntryPoint: fritter.DotNetStaticMethod{
			TypeName:   "Example.Commands",
			MethodName: "Run",
		},
		Runtime: fritter.DotNetRuntime{
			Version: fritter.DotNetRuntimeV4,
		},
	},
})
```

### .NET runtime hosting

```go
type DotNetRuntime struct {
	Version   string
	AppDomain string
}

const (
	DotNetRuntimeV2 = "v2.0.50727"
	DotNetRuntimeV4 = "v4.0.30319"
)
```

An empty `Version` uses assembly metadata, with Fritter's native fallback when metadata does not select a runtime. `DotNetRuntimeV2` and `DotNetRuntimeV4` provide the standard CLR version strings.

An explicit `AppDomain` must be valid UTF-8, NUL-free, and at most eight bytes. When it is empty, `EntropyNone` uses the default CLR domain; `EntropyNames` and `EntropyDefault` generate an eight-byte AppDomain name and create that domain.

### Scripts

```go
type VBScript struct {
	Source []byte
}

type JScript struct {
	Source []byte
}
```

Script payloads expose no invocation settings. The target Active Scripting engine decodes source through the target process's active Windows code page; supply source in that encoding when it contains non-ASCII text.

For PE payloads, Fritter validates that the bytes match the selected native or managed EXE/DLL struct and that the architecture is supported. Selecting the wrong struct does not reinterpret the bytes; generation fails with `ErrorPayloadTypeMismatch`.

## Loader configuration

### Exit behavior

| Constant | Behavior |
| --- | --- |
| `ExitThread` | Exit the current thread after execution; zero-value default |
| `ExitProcess` | Terminate the host process |
| `ExitBlock` | Block without normal cleanup or return |

### Entropy

| Constant | Behavior |
| --- | --- |
| `EntropyDefault` | Random names plus cryptographic protection; zero-value default |
| `EntropyNames` | Random names without the optional module-encryption layer |
| `EntropyNone` | Disable optional name and cryptographic randomization |

The WebAssembly runtime still supplies secure randomness for generation machinery that always requires it, even with `EntropyNone`.

### Host-image continuation

`HostImageContinuation` starts payload processing on a new thread, then resumes the current thread at the current host executable's image base plus `EntryPointRVA`:

```go
request.Loader.HostContinuation = &fritter.HostImageContinuation{
	EntryPointRVA: 0x1234,
}
```

`EntryPointRVA` describes the host image, not the payload PE. It must be nonzero. Fritter cannot verify that the RVA is valid for the process in which the generated loader will eventually execute.

## Output formats

Set `Request.Format` to control `Result.Loader`:

| Constant | Representation |
| --- | --- |
| `FormatBinary` | Raw loader bytes; zero-value default |
| `FormatBase64` | Base64 text |
| `FormatC` | C source representation |
| `FormatRuby` | Ruby source representation |
| `FormatPython` | Python 3 source using a `bytes` value |
| `FormatPowerShell` | PowerShell source representation |
| `FormatCSharp` | C# source representation |
| `FormatHex` | Hexadecimal text |
| `FormatUUID` | UUID strings |

Every representation is returned as `[]byte`; the package does not write it to a file.

## HTTP staging

By default, the loader embeds the payload. Set `Request.Staging` to return the opaque payload module separately:

```go
stageURL, err := url.Parse("https://example.com/fritter/")
if err != nil {
	return err
}

result, err := fritter.Generate(ctx, fritter.Request{
	Payload: fritter.JScript{Source: source},
	Staging: &fritter.HTTPStaging{
		BaseURL:    *stageURL,
		ModuleName: "MOD12345",
	},
})
```

```go
type HTTPStaging struct {
	BaseURL    url.URL
	ModuleName string
}
```

`BaseURL` must use HTTP or HTTPS and contain a valid ASCII hostname; use an IDNA hostname for an internationalized domain. Its path is treated as a directory and is restricted to unescaped URL-safe ASCII characters. Query strings, fragments, explicitly escaped paths, and non-ASCII serialized URLs are rejected because the target loader appends the module name and parses the result with WinINet.

URL user information supplies HTTP Basic Authentication. Decoded usernames and passwords must use printable ASCII and are each limited to 63 bytes. Generation copies the URL value while normalizing it and does not mutate the request.

After scheme normalization and addition of a trailing slash, the base URL must not exceed 247 bytes. `ModuleName` may be empty; a non-empty name must be at most eight URL-safe ASCII bytes and contain no path separators. With an empty name, `EntropyNone` uses `AAAAAAAA`, while other entropy modes generate an eight-character name securely.

`Result.StagedModule` reports the final name, the URL embedded in the loader, and the bytes to serve there. Generation never uploads the module and makes no network request.

The current target loader intentionally accepts invalid HTTPS certificates, including name, date, trust-chain, usage, and revocation failures. Treat HTTPS staging as transport encryption without enforced server authentication unless using a custom module with a stricter client. The loader does not follow redirects, and the module URL must return HTTP 200 directly.

## Reusing a generator

Compile the embedded module once when producing multiple artifacts:

```go
generator, err := fritter.New(ctx)
if err != nil {
	return err
}
defer generator.Close()

first, err := generator.Generate(ctx, fritter.Request{
	Payload: fritter.JScript{Source: firstSource},
})
if err != nil {
	return err
}

second, err := generator.Generate(ctx, fritter.Request{
	Payload: fritter.VBScript{Source: secondSource},
	Format:  fritter.FormatBase64,
})
if err != nil {
	return err
}

_, _ = first, second
```

```go
func New(ctx context.Context) (*Generator, error)
func (g *Generator) Generate(ctx context.Context, request Request) (Result, error)
func (g *Generator) Close() error
```

Each call creates a fresh WebAssembly instance and isolated guest filesystem while reusing the compiled module. A `Generator` may service concurrent calls. `Close` waits for active calls, releases the compiled module and runtime, and is safe to call more than once. Calling `Generate` after `Close` returns `ErrClosed`.

Each embedded guest starts with 64 MiB of linear memory, so applications generating many loaders concurrently should bound their parallelism. Generation observes context cancellation and deadlines. `Close` completes cleanup synchronously.

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

```go
func NewWithWASM(ctx context.Context, module []byte) (*Generator, error)
```

The module must implement the direct bridge ABI used by this package. Required memory and function exports, including exact signatures, are validated during initialization. `New` always uses the embedded module and does not consult `FRITTER_WASM_PATH`; selecting a custom module is explicit.

## Errors and validation

Invalid requests return `*ValidationError` before generation begins:

```go
type ValidationError struct {
	Field   string
	Problem string
}
```

Common `Field` values are:

| Area | Field values |
| --- | --- |
| Request | `payload`, `format`, `loader.exit`, `loader.entropy`, `loader.hostContinuation.entryPointRVA` |
| Native executable | `payload.flags` |
| Native PE mapping | `payload.pe.headers`, `payload.pe.decoyModulePath` |
| Native DLL | `payload.export.name` |
| .NET | `payload.entryPoint.typeName`, `payload.entryPoint.methodName`, `payload.runtime.version`, `payload.runtime.appDomain` |
| HTTP staging | `staging.baseURL`, `staging.moduleName` |

Errors reported by the Fritter generation engine use:

```go
type GenerationError struct {
	Code ErrorCode
}
```

Handle errors without parsing their text:

```go
result, err := generator.Generate(ctx, fritter.Request{
	Payload: fritter.NativeExecutable{Image: executable},
})
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

The engine's stable error codes are:

| Constant | Code | Meaning |
| --- | ---: | --- |
| `ErrorFileNotFound` | 1 | An expected guest file was not found. |
| `ErrorFileEmpty` | 2 | The payload is empty. |
| `ErrorFileAccess` | 3 | A guest artifact could not be opened. |
| `ErrorFileInvalid` | 4 | The payload format or structure is invalid. |
| `ErrorDotNetEntryPoint` | 5 | A .NET DLL is missing its type or method. |
| `ErrorOutOfMemory` | 6 | Native generation could not allocate memory. |
| `ErrorInvalidArchitecture` | 7 | The selected architecture is invalid. |
| `ErrorInvalidURL` | 8 | The staging URL is invalid. |
| `ErrorURLTooLong` | 9 | The staging URL exceeds the native limit. |
| `ErrorInvalidConfiguration` | 10 | The native generation configuration is invalid. |
| `ErrorRandom` | 11 | Secure random generation failed. |
| `ErrorDLLExport` | 12 | The requested native DLL export was not found. |
| `ErrorArchitectureMismatch` | 13 | The payload architecture is unsupported. |
| `ErrorDLLInvocation` | 14 | A native DLL invocation is invalid. |
| `ErrorInvalidFormat` | 16 | The output format is invalid. |
| `ErrorCompressionEngine` | 17 | The compression engine is invalid. |
| `ErrorCompression` | 18 | Payload compression failed. |
| `ErrorInvalidEntropy` | 19 | The entropy mode is invalid. |
| `ErrorMixedAssembly` | 20 | A mixed native and managed assembly is unsupported. |
| `ErrorInvalidHeaders` | 21 | The PE-header policy is invalid. |
| `ErrorInvalidDecoy` | 22 | The decoy module path is invalid. |
| `ErrorPayloadTypeMismatch` | 23 | Payload bytes do not match the selected payload struct. |

Some codes describe engine internals that are not configurable through the root Go package. They remain available for interpreting engine and custom-module failures.

WebAssembly compilation, ABI, allocation, and runtime failures are returned as wrapped Go errors. Context cancellation and deadline errors remain compatible with `errors.Is`. Do not use returned artifacts when generation fails.

## Embedded module behavior

- Importing the root package embeds the canonical `dist/fritter.wasm` artifact in the final Go program.
- The embedded artifact is a WASI/WASMFS reactor with no mounted host filesystem. Payload bytes enter its isolated memory only for one generation call.
- WASI randomness is backed by `crypto/rand`.
- The WASM build does not use aPLib compression, unlike native builds linked with the bundled aPLib library.
- The canonical embedded module shares its per-build polymorphism constants with every program importing that Fritter version. Build and supply a fresh module when unique per-build constants are required.

To rebuild the canonical module after changing native implementation:

```sh
scripts/build-loader-blobs.sh
scripts/build-wasm.sh
go test ./...
```

Consumers do not need these build tools unless producing a custom Fritter WebAssembly module.

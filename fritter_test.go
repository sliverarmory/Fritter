package fritter_test

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/binary"
	"errors"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/sliverarmory/Fritter"
)

var jscriptPayload = []byte(`WScript.Echo("hello from the Go API");`)

//go:embed test/calc.exe
var nativeExecutableImage []byte

func TestGenerateUsesEmbeddedModuleAndPayloadBytes(t *testing.T) {
	t.Setenv("FRITTER_WASM_PATH", filepath.Join(t.TempDir(), "missing.wasm"))
	t.Chdir(t.TempDir())

	result, err := fritter.Generate(context.Background(), fritter.Request{
		Payload: fritter.JScript{Source: jscriptPayload},
	})
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	if len(result.Loader) == 0 {
		t.Fatal("Generate() returned an empty loader")
	}
	if result.StagedModule != nil {
		t.Fatalf("Generate() staged module = %#v, want nil", result.StagedModule)
	}
}

func TestGeneratorReuseProducesUniqueLoaders(t *testing.T) {
	ctx := context.Background()
	generator := newGenerator(t, ctx)
	request := fritter.Request{Payload: fritter.JScript{Source: jscriptPayload}}

	first, err := generator.Generate(ctx, request)
	if err != nil {
		t.Fatalf("first Generate() error = %v", err)
	}
	second, err := generator.Generate(ctx, request)
	if err != nil {
		t.Fatalf("second Generate() error = %v", err)
	}
	if len(first.Loader) == 0 || len(second.Loader) == 0 {
		t.Fatal("Generate() returned an empty loader")
	}
	if bytes.Equal(first.Loader, second.Loader) {
		t.Fatal("reused Generator produced identical loaders with default entropy")
	}
}

func TestGeneratorSupportsConcurrentGeneration(t *testing.T) {
	ctx := context.Background()
	generator := newGenerator(t, ctx)
	request := fritter.Request{Payload: fritter.JScript{Source: jscriptPayload}}

	const calls = 4
	results := make([]fritter.Result, calls)
	errs := make([]error, calls)
	var wait sync.WaitGroup
	for index := range results {
		wait.Add(1)
		go func() {
			defer wait.Done()
			results[index], errs[index] = generator.Generate(ctx, request)
		}()
	}
	wait.Wait()

	for index := range results {
		if errs[index] != nil {
			t.Fatalf("Generate() call %d error = %v", index, errs[index])
		}
		if len(results[index].Loader) == 0 {
			t.Fatalf("Generate() call %d returned an empty loader", index)
		}
		for prior := 0; prior < index; prior++ {
			if bytes.Equal(results[index].Loader, results[prior].Loader) {
				t.Fatalf("concurrent calls %d and %d returned identical loaders", prior, index)
			}
		}
	}
}

func TestLoaderConfigAndHostImageContinuation(t *testing.T) {
	result, err := fritter.Generate(context.Background(), fritter.Request{
		Payload: fritter.JScript{Source: jscriptPayload},
		Format:  fritter.FormatC,
		Loader: fritter.LoaderConfig{
			Exit:    fritter.ExitProcess,
			Entropy: fritter.EntropyNone,
			HostContinuation: &fritter.HostImageContinuation{
				EntryPointRVA: 0x1234,
			},
		},
	})
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	if !bytes.HasPrefix(result.Loader, []byte("unsigned char buf[]")) {
		t.Fatalf("FormatC prefix = %q", result.Loader[:min(32, len(result.Loader))])
	}
}

func TestNativeExecutableConfiguration(t *testing.T) {
	t.Chdir(t.TempDir())
	result, err := fritter.Generate(context.Background(), fritter.Request{
		Payload: fritter.NativeExecutable{
			Image: nativeExecutableImage,
			Flags: fritter.NativeExecutableRunInThread,
			PE: fritter.NativePEConfig{
				Headers:         fritter.PEHeadersPreserve,
				DecoyModulePath: `Z:\this\target\path\does-not-exist.dll`,
			},
		},
		Loader: fritter.LoaderConfig{Entropy: fritter.EntropyNone},
	})
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	if len(result.Loader) == 0 {
		t.Fatal("Generate() returned an empty loader")
	}
}

func TestGenerateHTTPStaging(t *testing.T) {
	result, err := fritter.Generate(context.Background(), fritter.Request{
		Payload: fritter.JScript{Source: jscriptPayload},
		Format:  fritter.FormatHex,
		Loader:  fritter.LoaderConfig{Entropy: fritter.EntropyNone},
		Staging: &fritter.HTTPStaging{BaseURL: mustURL(t, "https://example.com/stage/")},
	})
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	if !bytes.Contains(result.Loader, []byte(`\x`)) {
		t.Fatalf("FormatHex loader does not contain hex escapes: %q", result.Loader[:min(64, len(result.Loader))])
	}
	assertStagedModule(t, result, "AAAAAAAA", "https://example.com/stage/AAAAAAAA")
}

func TestHTTPStagingRequestIsReusableAndNotMutated(t *testing.T) {
	ctx := context.Background()
	generator := newGenerator(t, ctx)
	request := fritter.Request{
		Payload: fritter.JScript{Source: jscriptPayload},
		Loader:  fritter.LoaderConfig{Entropy: fritter.EntropyNone},
		Staging: &fritter.HTTPStaging{
			BaseURL:    mustURL(t, "https://user:password@example.com/original"),
			ModuleName: "STAGE123",
		},
	}
	originalURL := request.Staging.BaseURL.String()

	const calls = 4
	results := make([]fritter.Result, calls)
	errs := make([]error, calls)
	var wait sync.WaitGroup
	for index := range results {
		wait.Add(1)
		go func() {
			defer wait.Done()
			results[index], errs[index] = generator.Generate(ctx, request)
		}()
	}
	wait.Wait()

	if got := request.Staging.BaseURL.String(); got != originalURL {
		t.Fatalf("Generate() mutated request URL: got %q, want %q", got, originalURL)
	}
	for index := range results {
		if errs[index] != nil {
			t.Fatalf("Generate() call %d error = %v", index, errs[index])
		}
		assertStagedModule(t, results[index], "STAGE123", "https://user:password@example.com/original/STAGE123")
	}
}

func TestGenerateOutputFormats(t *testing.T) {
	ctx := context.Background()
	generator := newGenerator(t, ctx)
	tests := []struct {
		name       string
		format     fritter.Format
		wantPrefix []byte
		wantSuffix []byte
	}{
		{name: "C", format: fritter.FormatC, wantPrefix: []byte("unsigned char buf[]")},
		{name: "Ruby", format: fritter.FormatRuby, wantPrefix: []byte("buf = [\n"), wantSuffix: []byte("].pack(\"C*\")\n")},
		{name: "Python", format: fritter.FormatPython, wantPrefix: []byte("buf   = b\"\"\n")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := generator.Generate(ctx, fritter.Request{
				Payload: fritter.JScript{Source: jscriptPayload},
				Format:  test.format,
				Loader:  fritter.LoaderConfig{Entropy: fritter.EntropyNone},
			})
			if err != nil {
				t.Fatalf("Generate() error = %v", err)
			}
			if !bytes.HasPrefix(result.Loader, test.wantPrefix) {
				t.Fatalf("loader prefix = %q, want %q", result.Loader[:min(32, len(result.Loader))], test.wantPrefix)
			}
			if len(test.wantSuffix) != 0 && !bytes.HasSuffix(result.Loader, test.wantSuffix) {
				t.Fatalf("loader does not end with %q", test.wantSuffix)
			}
		})
	}

	uuidResult, err := generator.Generate(ctx, fritter.Request{
		Payload: fritter.VBScript{Source: []byte(`WScript.Echo "hello"`)},
		Format:  fritter.FormatUUID,
		Loader:  fritter.LoaderConfig{Entropy: fritter.EntropyNone},
	})
	if err != nil {
		t.Fatalf("Generate(FormatUUID) error = %v", err)
	}
	firstLine := strings.SplitN(string(uuidResult.Loader), "\n", 2)[0]
	if len(firstLine) != 36 || strings.Count(firstLine, "-") != 4 {
		t.Fatalf("FormatUUID first line = %q, want UUID text", firstLine)
	}
}

func TestGenerateValidationErrors(t *testing.T) {
	ctx := context.Background()
	generator := newGenerator(t, ctx)

	tests := []struct {
		name      string
		request   fritter.Request
		wantField string
	}{
		{name: "missing payload", wantField: "payload"},
		{
			name:      "empty payload",
			request:   fritter.Request{Payload: fritter.JScript{}},
			wantField: "payload",
		},
		{
			name:      "invalid format",
			request:   fritter.Request{Payload: fritter.JScript{Source: jscriptPayload}, Format: fritter.Format(255)},
			wantField: "format",
		},
		{
			name: "invalid exit",
			request: fritter.Request{
				Payload: fritter.JScript{Source: jscriptPayload},
				Loader:  fritter.LoaderConfig{Exit: fritter.ExitBehavior(255)},
			},
			wantField: "loader.exit",
		},
		{
			name: "invalid entropy",
			request: fritter.Request{
				Payload: fritter.JScript{Source: jscriptPayload},
				Loader:  fritter.LoaderConfig{Entropy: fritter.Entropy(255)},
			},
			wantField: "loader.entropy",
		},
		{
			name: "zero host continuation RVA",
			request: fritter.Request{
				Payload: fritter.JScript{Source: jscriptPayload},
				Loader:  fritter.LoaderConfig{HostContinuation: &fritter.HostImageContinuation{}},
			},
			wantField: "loader.hostContinuation.entryPointRVA",
		},
		{
			name: "unknown native executable flag",
			request: fritter.Request{Payload: fritter.NativeExecutable{
				Image: []byte{1}, Flags: fritter.NativeExecutableFlags(1 << 31),
			}},
			wantField: "payload.flags",
		},
		{
			name: "invalid PE header mode",
			request: fritter.Request{Payload: fritter.NativeExecutable{
				Image: []byte{1}, PE: fritter.NativePEConfig{Headers: fritter.PEHeaders(255)},
			}},
			wantField: "payload.pe.headers",
		},
		{
			name: "NUL in decoy path",
			request: fritter.Request{Payload: fritter.NativeDLL{
				Image: []byte{1}, PE: fritter.NativePEConfig{DecoyModulePath: "invalid\x00path"},
			}},
			wantField: "payload.pe.decoyModulePath",
		},
		{
			name: "non-ASCII decoy path",
			request: fritter.Request{Payload: fritter.NativeDLL{
				Image: []byte{1}, PE: fritter.NativePEConfig{DecoyModulePath: `C:\décoy.dll`},
			}},
			wantField: "payload.pe.decoyModulePath",
		},
		{
			name: "empty native export",
			request: fritter.Request{Payload: fritter.NativeDLL{
				Image: []byte{1}, Export: &fritter.NativeDLLExport{},
			}},
			wantField: "payload.export.name",
		},
		{
			name: "missing managed type",
			request: fritter.Request{Payload: fritter.DotNetDLL{
				Assembly: []byte{1}, EntryPoint: fritter.DotNetStaticMethod{MethodName: "Run"},
			}},
			wantField: "payload.entryPoint.typeName",
		},
		{
			name: "missing managed method",
			request: fritter.Request{Payload: fritter.DotNetDLL{
				Assembly: []byte{1}, EntryPoint: fritter.DotNetStaticMethod{TypeName: "Example.Loader"},
			}},
			wantField: "payload.entryPoint.methodName",
		},
		{
			name: "invalid managed runtime",
			request: fritter.Request{Payload: fritter.DotNetExecutable{
				Assembly: []byte{1}, Runtime: fritter.DotNetRuntime{Version: "v4\x00bad"},
			}},
			wantField: "payload.runtime.version",
		},
		{
			name: "managed AppDomain too long",
			request: fritter.Request{Payload: fritter.DotNetExecutable{
				Assembly: []byte{1}, Runtime: fritter.DotNetRuntime{AppDomain: "too-long9"},
			}},
			wantField: "payload.runtime.appDomain",
		},
		{
			name: "missing staging URL",
			request: fritter.Request{
				Payload: fritter.JScript{Source: jscriptPayload}, Staging: &fritter.HTTPStaging{},
			},
			wantField: "staging.baseURL",
		},
		{
			name: "unsupported staging scheme",
			request: fritter.Request{
				Payload: fritter.JScript{Source: jscriptPayload},
				Staging: &fritter.HTTPStaging{BaseURL: mustURL(t, "ftp://example.com/stage/")},
			},
			wantField: "staging.baseURL",
		},
		{
			name: "invalid staging hostname",
			request: fritter.Request{
				Payload: fritter.JScript{Source: jscriptPayload},
				Staging: &fritter.HTTPStaging{BaseURL: url.URL{Scheme: "https", Host: "bad host", Path: "/stage/"}},
			},
			wantField: "staging.baseURL",
		},
		{
			name: "invalid staging port",
			request: fritter.Request{
				Payload: fritter.JScript{Source: jscriptPayload},
				Staging: &fritter.HTTPStaging{BaseURL: url.URL{Scheme: "https", Host: "example.com:70000", Path: "/stage/"}},
			},
			wantField: "staging.baseURL",
		},
		{
			name: "escaped staging path",
			request: fritter.Request{
				Payload: fritter.JScript{Source: jscriptPayload},
				Staging: &fritter.HTTPStaging{BaseURL: mustURL(t, "https://example.com/a%2Fb")},
			},
			wantField: "staging.baseURL",
		},
		{
			name: "staging query",
			request: fritter.Request{
				Payload: fritter.JScript{Source: jscriptPayload},
				Staging: &fritter.HTTPStaging{BaseURL: mustURL(t, "https://example.com/stage/?token=value")},
			},
			wantField: "staging.baseURL",
		},
		{
			name: "invalid staging module name",
			request: fritter.Request{
				Payload: fritter.JScript{Source: jscriptPayload},
				Staging: &fritter.HTTPStaging{
					BaseURL: mustURL(t, "https://example.com/stage/"), ModuleName: "TOO-LONG-1",
				},
			},
			wantField: "staging.moduleName",
		},
		{
			name: "control byte in staging username",
			request: fritter.Request{
				Payload: fritter.JScript{Source: jscriptPayload},
				Staging: &fritter.HTTPStaging{BaseURL: url.URL{
					Scheme: "https", Host: "example.com", Path: "/stage", User: url.UserPassword("user\nname", "password"),
				}},
			},
			wantField: "staging.baseURL",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := generator.Generate(ctx, test.request)
			if err == nil {
				t.Fatal("Generate() error = nil, want validation error")
			}
			var validationErr *fritter.ValidationError
			if !errors.As(err, &validationErr) {
				t.Fatalf("Generate() error type = %T, want *fritter.ValidationError: %v", err, err)
			}
			if validationErr.Field != test.wantField {
				t.Errorf("ValidationError.Field = %q, want %q", validationErr.Field, test.wantField)
			}
			if validationErr.Problem == "" {
				t.Error("ValidationError.Problem is empty")
			}
		})
	}
}

func TestPointerPayloadsAndNilPointers(t *testing.T) {
	ctx := context.Background()
	generator := newGenerator(t, ctx)

	payload := &fritter.JScript{Source: jscriptPayload}
	result, err := generator.Generate(ctx, fritter.Request{Payload: payload})
	if err != nil {
		t.Fatalf("Generate() with pointer payload error = %v", err)
	}
	if len(result.Loader) == 0 {
		t.Fatal("Generate() with pointer payload returned an empty loader")
	}

	nilPayloads := []struct {
		name    string
		payload fritter.Payload
	}{
		{name: "native executable", payload: (*fritter.NativeExecutable)(nil)},
		{name: "native DLL", payload: (*fritter.NativeDLL)(nil)},
		{name: ".NET executable", payload: (*fritter.DotNetExecutable)(nil)},
		{name: ".NET DLL", payload: (*fritter.DotNetDLL)(nil)},
		{name: "VBScript", payload: (*fritter.VBScript)(nil)},
		{name: "JScript", payload: (*fritter.JScript)(nil)},
	}
	for _, test := range nilPayloads {
		t.Run(test.name, func(t *testing.T) {
			_, err := generator.Generate(ctx, fritter.Request{Payload: test.payload})
			var validationErr *fritter.ValidationError
			if !errors.As(err, &validationErr) || validationErr.Field != "payload" {
				t.Fatalf("Generate() error = %v, want payload validation error", err)
			}
		})
	}
}

func TestPublicDomainModelIsConstructible(t *testing.T) {
	requests := []fritter.Request{
		{
			Payload: fritter.NativeExecutable{
				Image: []byte{1},
				Flags: fritter.NativeExecutableRunInThread,
				PE: fritter.NativePEConfig{
					Headers: fritter.PEHeadersPreserve, DecoyModulePath: `C:\Windows\System32\version.dll`,
				},
			},
			Format: fritter.FormatC,
			Loader: fritter.LoaderConfig{
				Exit: fritter.ExitBlock, Entropy: fritter.EntropyNames,
				HostContinuation: &fritter.HostImageContinuation{EntryPointRVA: 0x1000},
			},
			Staging: &fritter.HTTPStaging{BaseURL: mustURL(t, "https://example.com/"), ModuleName: "MODULE01"},
		},
		{Payload: fritter.NativeDLL{
			Image: []byte{1}, Export: &fritter.NativeDLLExport{Name: "Run"},
			PE: fritter.NativePEConfig{Headers: fritter.PEHeadersOverwrite},
		}},
		{Payload: fritter.DotNetExecutable{
			Assembly: []byte{1}, Runtime: fritter.DotNetRuntime{Version: fritter.DotNetRuntimeV4, AppDomain: "Example"},
		}},
		{Payload: fritter.DotNetDLL{
			Assembly:   []byte{1},
			EntryPoint: fritter.DotNetStaticMethod{TypeName: "Example.Loader", MethodName: "Run"},
			Runtime:    fritter.DotNetRuntime{Version: fritter.DotNetRuntimeV2},
		}},
		{Payload: fritter.VBScript{Source: []byte(`WScript.Echo "hello"`)}},
		{Payload: fritter.JScript{Source: jscriptPayload}},
	}
	if len(requests) != 6 {
		t.Fatalf("request count = %d, want 6", len(requests))
	}
	if requests[0].Loader.HostContinuation.EntryPointRVA != 0x1000 {
		t.Fatalf("HostImageContinuation.EntryPointRVA = %#x", requests[0].Loader.HostContinuation.EntryPointRVA)
	}
	if fritter.DotNetRuntimeV2 != "v2.0.50727" || fritter.DotNetRuntimeV4 != "v4.0.30319" {
		t.Fatalf("unexpected .NET runtime constants: %q, %q", fritter.DotNetRuntimeV2, fritter.DotNetRuntimeV4)
	}

	pointerPayloads := []fritter.Payload{
		&fritter.NativeExecutable{},
		&fritter.NativeDLL{},
		&fritter.DotNetExecutable{},
		&fritter.DotNetDLL{},
		&fritter.VBScript{},
		&fritter.JScript{},
	}
	if len(pointerPayloads) != len(requests) {
		t.Fatalf("pointer payload count = %d, want %d", len(pointerPayloads), len(requests))
	}
}

func TestGenerateReportsDomainFailure(t *testing.T) {
	_, err := fritter.Generate(context.Background(), fritter.Request{
		Payload: fritter.NativeExecutable{Image: []byte("not a Portable Executable")},
	})
	if err == nil {
		t.Fatal("Generate() error = nil, want generation error")
	}
	var generationErr *fritter.GenerationError
	if !errors.As(err, &generationErr) {
		t.Fatalf("Generate() error type = %T, want *fritter.GenerationError: %v", err, err)
	}
	if generationErr.Code != fritter.ErrorFileInvalid {
		t.Fatalf("GenerationError.Code = %v, want %v", generationErr.Code, fritter.ErrorFileInvalid)
	}
}

func TestGenerateEnforcesConcretePayloadType(t *testing.T) {
	dllImage := nativeDLLImage()
	tests := []struct {
		name    string
		payload fritter.Payload
	}{
		{name: "native executable as native DLL", payload: fritter.NativeDLL{Image: nativeExecutableImage}},
		{name: "native DLL as native executable", payload: fritter.NativeExecutable{Image: dllImage}},
		{name: "native executable as managed executable", payload: fritter.DotNetExecutable{Assembly: nativeExecutableImage}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := fritter.Generate(context.Background(), fritter.Request{Payload: test.payload})
			var generationErr *fritter.GenerationError
			if !errors.As(err, &generationErr) {
				t.Fatalf("Generate() error = %v, want *fritter.GenerationError", err)
			}
			if generationErr.Code != fritter.ErrorPayloadTypeMismatch {
				t.Fatalf("GenerationError.Code = %v, want %v", generationErr.Code, fritter.ErrorPayloadTypeMismatch)
			}
		})
	}
}

func TestNewWithWASMRejectsInvalidModule(t *testing.T) {
	generator, err := fritter.NewWithWASM(context.Background(), []byte("not wasm"))
	if err == nil {
		if generator != nil {
			_ = generator.Close()
		}
		t.Fatal("NewWithWASM() error = nil, want invalid-module error")
	}
	if generator != nil {
		t.Fatalf("NewWithWASM() generator = %#v, want nil after an error", generator)
	}
}

func TestNewWithWASMValidatesBridgeABI(t *testing.T) {
	emptyModule := []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}
	generator, err := fritter.NewWithWASM(context.Background(), emptyModule)
	if err == nil {
		if generator != nil {
			_ = generator.Close()
		}
		t.Fatal("NewWithWASM() error = nil, want bridge ABI error")
	}
	if generator != nil {
		t.Fatalf("NewWithWASM() generator = %#v, want nil after an ABI error", generator)
	}
	if !strings.Contains(err.Error(), "does not export memory") {
		t.Fatalf("NewWithWASM() error = %q, want missing-memory detail", err)
	}
}

func TestGeneratorCloseAndCancellation(t *testing.T) {
	generator, err := fritter.New(context.Background())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = generator.Generate(canceled, fritter.Request{Payload: fritter.JScript{Source: jscriptPayload}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Generate() cancellation error = %v, want context.Canceled", err)
	}
	if err := generator.Close(); err != nil {
		t.Fatalf("first Close() error = %v", err)
	}
	if err := generator.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	_, err = generator.Generate(context.Background(), fritter.Request{Payload: fritter.JScript{Source: jscriptPayload}})
	if !errors.Is(err, fritter.ErrClosed) {
		t.Fatalf("Generate() after Close error = %v, want ErrClosed", err)
	}
}

func newGenerator(t *testing.T, ctx context.Context) *fritter.Generator {
	t.Helper()
	generator, err := fritter.New(ctx)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() {
		if err := generator.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})
	return generator
}

func assertStagedModule(t *testing.T, result fritter.Result, wantName, wantURL string) {
	t.Helper()
	if result.StagedModule == nil {
		t.Fatal("Generate() returned no staged module")
	}
	if got := result.StagedModule.Name; got != wantName {
		t.Fatalf("staged module name = %q, want %q", got, wantName)
	}
	if got := result.StagedModule.URL.String(); got != wantURL {
		t.Fatalf("staged module URL = %q, want %q", got, wantURL)
	}
	if len(result.StagedModule.Data) == 0 {
		t.Fatal("Generate() returned an empty staged module")
	}
}

func mustURL(t *testing.T, rawURL string) url.URL {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", rawURL, err)
	}
	return *parsed
}

func nativeDLLImage() []byte {
	image := append([]byte(nil), nativeExecutableImage...)
	peOffset := int(binary.LittleEndian.Uint32(image[0x3c:]))
	characteristicsOffset := peOffset + 4 + 18
	characteristics := binary.LittleEndian.Uint16(image[characteristicsOffset:])
	binary.LittleEndian.PutUint16(image[characteristicsOffset:], characteristics|0x2000)
	return image
}

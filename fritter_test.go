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
var nativeExecutablePayload []byte

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
	generator, err := fritter.New(ctx)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() {
		if err := generator.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})

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
		t.Fatal("reused Generator produced identical loaders")
	}
}

func TestGenerateAcceptsStructuredNativeArguments(t *testing.T) {
	result, err := fritter.Generate(context.Background(), fritter.Request{
		Payload: fritter.NativeExecutable{
			Data: nativeExecutablePayload,
			Arguments: []string{
				"--help",
				"-t",
				"two words",
				"",
			},
		},
		Loader: fritter.LoaderOptions{Entropy: fritter.EntropyNone},
	})
	if err != nil {
		t.Fatalf("Generate() with structured native arguments error = %v", err)
	}
	if len(result.Loader) == 0 {
		t.Fatal("Generate() with structured native arguments returned an empty loader")
	}
}

func TestGeneratorSupportsConcurrentGeneration(t *testing.T) {
	ctx := context.Background()
	generator, err := fritter.New(ctx)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() {
		if err := generator.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})

	const calls = 4
	request := fritter.Request{Payload: fritter.JScript{Source: jscriptPayload}}
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
				t.Fatalf("concurrent Generate() calls %d and %d returned identical loaders", prior, index)
			}
		}
	}
}

func TestGenerateHTTPStaging(t *testing.T) {
	baseURL := mustURL(t, "https://example.com/stage/")
	result, err := fritter.Generate(context.Background(), fritter.Request{
		Payload: fritter.JScript{Source: jscriptPayload},
		Format:  fritter.FormatHex,
		Loader:  fritter.LoaderOptions{Entropy: fritter.EntropyNone},
		Staging: &fritter.HTTPStaging{
			BaseURL: baseURL,
		},
	})
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	if len(result.Loader) == 0 {
		t.Fatal("Generate() returned an empty loader")
	}
	if !bytes.Contains(result.Loader, []byte(`\x`)) {
		t.Fatalf("FormatHex loader does not contain hex escapes: %q", result.Loader[:min(64, len(result.Loader))])
	}
	if result.StagedModule == nil {
		t.Fatal("Generate() returned no staged module")
	}
	if result.StagedModule.Name != "AAAAAAAA" {
		t.Fatalf("staged module name = %q, want %q", result.StagedModule.Name, "AAAAAAAA")
	}
	if len(result.StagedModule.Data) == 0 {
		t.Fatal("Generate() returned an empty staged module")
	}
	if got, want := result.StagedModule.URL.String(), "https://example.com/stage/AAAAAAAA"; got != want {
		t.Fatalf("staged module URL = %q, want %q", got, want)
	}
}

func TestGenerateVBScriptUUIDFormat(t *testing.T) {
	result, err := fritter.Generate(context.Background(), fritter.Request{
		Payload: fritter.VBScript{Source: []byte(`WScript.Echo "hello from the Go API"`)},
		Format:  fritter.FormatUUID,
		Loader:  fritter.LoaderOptions{Entropy: fritter.EntropyNone},
	})
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	firstLine := strings.SplitN(string(result.Loader), "\n", 2)[0]
	if len(firstLine) != 36 || strings.Count(firstLine, "-") != 4 {
		t.Fatalf("FormatUUID first line = %q, want UUID text", firstLine)
	}
}

func TestGenerateSourceFormats(t *testing.T) {
	generator, err := fritter.New(context.Background())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() {
		if err := generator.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})

	request := fritter.Request{
		Payload: fritter.JScript{Source: jscriptPayload},
		Loader:  fritter.LoaderOptions{Entropy: fritter.EntropyNone},
	}
	request.Format = fritter.FormatC
	cResult, err := generator.Generate(context.Background(), request)
	if err != nil {
		t.Fatalf("Generate(FormatC) error = %v", err)
	}
	if !bytes.HasPrefix(cResult.Loader, []byte("unsigned char buf[]")) {
		t.Fatalf("FormatC prefix = %q", cResult.Loader[:min(32, len(cResult.Loader))])
	}

	request.Format = fritter.FormatRuby
	rubyResult, err := generator.Generate(context.Background(), request)
	if err != nil {
		t.Fatalf("Generate(FormatRuby) error = %v", err)
	}
	if !bytes.HasPrefix(rubyResult.Loader, []byte("buf = [\n")) ||
		!bytes.HasSuffix(rubyResult.Loader, []byte("].pack(\"C*\")\n")) {
		t.Fatalf("FormatRuby output is not a Ruby byte-array expression")
	}

	request.Format = fritter.FormatPython
	pythonResult, err := generator.Generate(context.Background(), request)
	if err != nil {
		t.Fatalf("Generate(FormatPython) error = %v", err)
	}
	if !bytes.HasPrefix(pythonResult.Loader, []byte("buf   = b\"\"\n")) ||
		!bytes.Contains(pythonResult.Loader, []byte("buf  += b\"")) {
		t.Fatalf("FormatPython output is not a Python 3 bytes expression")
	}
}

func TestHTTPStagingRejectsExplicitlyEscapedPath(t *testing.T) {
	_, err := fritter.Generate(context.Background(), fritter.Request{
		Payload: fritter.JScript{Source: jscriptPayload},
		Loader:  fritter.LoaderOptions{Entropy: fritter.EntropyNone},
		Staging: &fritter.HTTPStaging{
			BaseURL: mustURL(t, "https://example.com/a%2Fb"),
		},
	})
	var validationErr *fritter.ValidationError
	if !errors.As(err, &validationErr) || validationErr.Field != "staging.baseURL" {
		t.Fatalf("Generate() error = %v, want staging.baseURL validation error", err)
	}
}

func TestGenerateValidationErrors(t *testing.T) {
	ctx := context.Background()
	generator, err := fritter.New(ctx)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() {
		if err := generator.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})

	tests := []struct {
		name      string
		request   fritter.Request
		wantField string
	}{
		{
			name:      "missing payload",
			request:   fritter.Request{},
			wantField: "payload",
		},
		{
			name: "empty script",
			request: fritter.Request{
				Payload: fritter.JScript{},
			},
			wantField: "source",
		},
		{
			name: "invalid format",
			request: fritter.Request{
				Payload: fritter.JScript{Source: jscriptPayload},
				Format:  fritter.Format(255),
			},
			wantField: "format",
		},
		{
			name: "argument containing NUL",
			request: fritter.Request{
				Payload: fritter.NativeExecutable{
					Data:      []byte{1},
					Arguments: []string{"valid", "invalid\x00argument"},
				},
			},
			wantField: "arguments[1]",
		},
		{
			name: "native DLL parameter without export",
			request: fritter.Request{
				Payload: fritter.NativeDLL{Data: []byte{1}, Parameter: "value"},
			},
			wantField: "export",
		},
		{
			name: "decoy path on script",
			request: fritter.Request{
				Payload: fritter.JScript{Source: jscriptPayload},
				Loader:  fritter.LoaderOptions{DecoyModulePath: `C:\Windows\System32\version.dll`},
			},
			wantField: "decoymodulepath",
		},
		{
			name: "missing staging URL",
			request: fritter.Request{
				Payload: fritter.JScript{Source: jscriptPayload},
				Staging: &fritter.HTTPStaging{ModuleName: "STAGE123"},
			},
			wantField: "baseurl",
		},
		{
			name: "unsupported staging scheme",
			request: fritter.Request{
				Payload: fritter.JScript{Source: jscriptPayload},
				Staging: &fritter.HTTPStaging{BaseURL: mustURL(t, "ftp://example.com/stage/")},
			},
			wantField: "baseurl",
		},
		{
			name: "invalid staging hostname",
			request: fritter.Request{
				Payload: fritter.JScript{Source: jscriptPayload},
				Staging: &fritter.HTTPStaging{BaseURL: &url.URL{
					Scheme: "https",
					Host:   "bad host",
					Path:   "/stage",
				}},
			},
			wantField: "baseurl",
		},
		{
			name: "invalid staging port",
			request: fritter.Request{
				Payload: fritter.JScript{Source: jscriptPayload},
				Staging: &fritter.HTTPStaging{BaseURL: &url.URL{
					Scheme: "https",
					Host:   "example.com:notaport",
					Path:   "/stage",
				}},
			},
			wantField: "baseurl",
		},
		{
			name: "control byte in staging username",
			request: fritter.Request{
				Payload: fritter.JScript{Source: jscriptPayload},
				Staging: &fritter.HTTPStaging{BaseURL: &url.URL{
					Scheme: "https",
					Host:   "example.com",
					Path:   "/stage",
					User:   url.UserPassword("user\nname", "password"),
				}},
			},
			wantField: "baseurl",
		},
		{
			name: "invalid staging module name",
			request: fritter.Request{
				Payload: fritter.JScript{Source: jscriptPayload},
				Staging: &fritter.HTTPStaging{
					BaseURL:    mustURL(t, "https://example.com/stage/"),
					ModuleName: "TOO-LONG-1",
				},
			},
			wantField: "modulename",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := generator.Generate(ctx, tt.request)
			if err == nil {
				t.Fatal("Generate() error = nil, want validation error")
			}

			var validationErr *fritter.ValidationError
			if !errors.As(err, &validationErr) {
				t.Fatalf("Generate() error type = %T, want *fritter.ValidationError: %v", err, err)
			}
			if !strings.Contains(strings.ToLower(validationErr.Field), tt.wantField) {
				t.Errorf("ValidationError.Field = %q, want it to contain %q", validationErr.Field, tt.wantField)
			}
			if validationErr.Problem == "" {
				t.Error("ValidationError.Problem is empty")
			}
		})
	}
}

func TestGenerateReportsDomainFailure(t *testing.T) {
	_, err := fritter.Generate(context.Background(), fritter.Request{
		Payload: fritter.NativeExecutable{Data: []byte("not a Portable Executable")},
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
	dllBytes := append([]byte(nil), nativeExecutablePayload...)
	peOffset := int(binary.LittleEndian.Uint32(dllBytes[0x3c:]))
	characteristicsOffset := peOffset + 4 + 18
	characteristics := binary.LittleEndian.Uint16(dllBytes[characteristicsOffset:])
	binary.LittleEndian.PutUint16(dllBytes[characteristicsOffset:], characteristics|0x2000)

	tests := []struct {
		name    string
		payload fritter.Payload
	}{
		{name: "native executable as native DLL", payload: fritter.NativeDLL{Data: nativeExecutablePayload}},
		{name: "native DLL as native executable", payload: fritter.NativeExecutable{Data: dllBytes}},
		{name: "native executable as managed executable", payload: fritter.DotNetExecutable{Data: nativeExecutablePayload}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := fritter.Generate(context.Background(), fritter.Request{Payload: tt.payload})
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

func TestForkRVAAppliesToScriptPayloads(t *testing.T) {
	result, err := fritter.Generate(context.Background(), fritter.Request{
		Payload: fritter.JScript{Source: jscriptPayload},
		Loader:  fritter.LoaderOptions{ForkRVA: 0x1234},
	})
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	if len(result.Loader) == 0 {
		t.Fatal("Generate() returned an empty loader")
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
	// A valid, empty WebAssembly module has no Fritter bridge exports.
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
	_, err = generator.Generate(canceled, fritter.Request{
		Payload: fritter.JScript{Source: jscriptPayload},
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Generate() cancellation error = %v, want context.Canceled", err)
	}

	if err := generator.Close(); err != nil {
		t.Fatalf("first Close() error = %v", err)
	}
	if err := generator.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	_, err = generator.Generate(context.Background(), fritter.Request{})
	if !errors.Is(err, fritter.ErrClosed) {
		t.Fatalf("Generate() after Close error = %v, want ErrClosed", err)
	}
}

func TestPayloadImplementationsArePubliclyConstructible(t *testing.T) {
	payloads := []fritter.Payload{
		fritter.NativeExecutable{Data: []byte{1}, Arguments: []string{"one"}, RunInThread: true},
		fritter.NativeDLL{Data: []byte{1}, Export: "Run", Parameter: "value", UTF16Parameter: true},
		fritter.DotNetExecutable{Data: []byte{1}, Arguments: []string{"one"}, RuntimeVersion: "v4.0.30319", AppDomain: "Example"},
		fritter.DotNetDLL{Data: []byte{1}, Class: "Example.Loader", Method: "Run", Arguments: []string{"one"}, RuntimeVersion: "v4.0.30319", AppDomain: "Example"},
		fritter.VBScript{Source: []byte("WScript.Echo \"hello\"")},
		fritter.JScript{Source: jscriptPayload},
	}
	if len(payloads) != 6 {
		t.Fatalf("payload count = %d, want 6", len(payloads))
	}
}

func mustURL(t *testing.T, rawURL string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", rawURL, err)
	}
	return parsed
}

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

	result, err := fritter.Generate(context.Background(), fritter.JScript{Source: jscriptPayload})
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

	payload := fritter.JScript{Source: jscriptPayload}
	first, err := generator.Generate(ctx, payload)
	if err != nil {
		t.Fatalf("first Generate() error = %v", err)
	}
	second, err := generator.Generate(ctx, payload)
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
	result, err := fritter.Generate(
		context.Background(),
		fritter.NativeExecutable{
			Data: nativeExecutablePayload,
			Arguments: []string{
				"--help",
				"-t",
				"two words",
				"",
			},
		},
		fritter.WithEntropy(fritter.EntropyNone),
	)
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
	payload := fritter.JScript{Source: jscriptPayload}
	results := make([]fritter.Result, calls)
	errs := make([]error, calls)
	var wait sync.WaitGroup
	for index := range results {
		wait.Add(1)
		go func() {
			defer wait.Done()
			results[index], errs[index] = generator.Generate(ctx, payload)
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
	result, err := fritter.Generate(
		context.Background(),
		fritter.JScript{Source: jscriptPayload},
		fritter.WithFormat(fritter.FormatHex),
		fritter.WithEntropy(fritter.EntropyNone),
		fritter.WithHTTPStaging(baseURL),
	)
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

func TestGenerateOptionsLastValueWins(t *testing.T) {
	result, err := fritter.Generate(
		context.Background(),
		fritter.JScript{Source: jscriptPayload},
		fritter.WithFormat(fritter.Format(255)),
		fritter.WithFormat(fritter.FormatC),
		fritter.WithEntropy(fritter.EntropyNone),
	)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	if !bytes.HasPrefix(result.Loader, []byte("unsigned char buf[]")) {
		t.Fatalf("last WithFormat option did not win: prefix = %q", result.Loader[:min(32, len(result.Loader))])
	}
}

func TestHTTPStagingAndEntropyOptionsAreOrderIndependent(t *testing.T) {
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

	payload := fritter.JScript{Source: jscriptPayload}
	baseURL := mustURL(t, "https://example.com/stage")
	staging := fritter.WithHTTPStaging(baseURL)

	stagingFirst, err := generator.Generate(
		ctx, payload,
		staging,
		fritter.WithEntropy(fritter.EntropyNone),
	)
	if err != nil {
		t.Fatalf("Generate(staging first) error = %v", err)
	}
	entropyFirst, err := generator.Generate(
		ctx, payload,
		fritter.WithEntropy(fritter.EntropyNone),
		staging,
	)
	if err != nil {
		t.Fatalf("Generate(entropy first) error = %v", err)
	}

	for name, result := range map[string]fritter.Result{
		"staging first": stagingFirst,
		"entropy first": entropyFirst,
	} {
		if result.StagedModule == nil {
			t.Fatalf("%s result has no staged module", name)
		}
		if got, want := result.StagedModule.Name, "AAAAAAAA"; got != want {
			t.Fatalf("%s module name = %q, want %q", name, got, want)
		}
		if got, want := result.StagedModule.URL.String(), "https://example.com/stage/AAAAAAAA"; got != want {
			t.Fatalf("%s module URL = %q, want %q", name, got, want)
		}
	}
}

func TestHTTPStagingOptionClonesURLAndSupportsConcurrentReuse(t *testing.T) {
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

	baseURL := mustURL(t, "https://example.com/original")
	originalURL := baseURL.String()
	staging := fritter.WithHTTPStaging(
		baseURL,
		fritter.WithStagedModuleName("FIRST123"),
		fritter.WithStagedModuleName("STAGE123"),
	)
	payload := fritter.JScript{Source: jscriptPayload}

	first, err := generator.Generate(ctx, payload, staging, fritter.WithEntropy(fritter.EntropyNone))
	if err != nil {
		t.Fatalf("first Generate() error = %v", err)
	}
	if got := baseURL.String(); got != originalURL {
		t.Fatalf("WithHTTPStaging mutated caller URL: got %q, want %q", got, originalURL)
	}
	assertStagedModule(t, first, "STAGE123", "https://example.com/original/STAGE123")

	// Options retain their own URL snapshot and may be shared by concurrent calls.
	baseURL.Scheme = "http"
	baseURL.Host = "mutated.example"
	baseURL.Path = "/changed"

	const calls = 4
	results := make([]fritter.Result, calls)
	errs := make([]error, calls)
	var wait sync.WaitGroup
	for index := range results {
		wait.Add(1)
		go func() {
			defer wait.Done()
			results[index], errs[index] = generator.Generate(
				ctx, payload, staging, fritter.WithEntropy(fritter.EntropyNone),
			)
		}()
	}
	wait.Wait()

	for index := range results {
		if errs[index] != nil {
			t.Fatalf("concurrent Generate() call %d error = %v", index, errs[index])
		}
		assertStagedModule(t, results[index], "STAGE123", "https://example.com/original/STAGE123")
	}
}

func TestNativeGenerationOptionsUseTargetPathWithoutHostIO(t *testing.T) {
	t.Chdir(t.TempDir())
	result, err := fritter.Generate(
		context.Background(),
		fritter.NativeExecutable{Data: nativeExecutablePayload},
		fritter.PreservePEHeaders(),
		fritter.WithDecoyModulePath(`Z:\this\target\path\does-not-exist.dll`),
		fritter.WithEntropy(fritter.EntropyNone),
	)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	if len(result.Loader) == 0 {
		t.Fatal("Generate() returned an empty loader")
	}
}

func TestGenerateVBScriptUUIDFormat(t *testing.T) {
	result, err := fritter.Generate(
		context.Background(),
		fritter.VBScript{Source: []byte(`WScript.Echo "hello from the Go API"`)},
		fritter.WithFormat(fritter.FormatUUID),
		fritter.WithEntropy(fritter.EntropyNone),
	)
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

	payload := fritter.JScript{Source: jscriptPayload}
	cResult, err := generator.Generate(
		context.Background(), payload,
		fritter.WithFormat(fritter.FormatC),
		fritter.WithEntropy(fritter.EntropyNone),
	)
	if err != nil {
		t.Fatalf("Generate(FormatC) error = %v", err)
	}
	if !bytes.HasPrefix(cResult.Loader, []byte("unsigned char buf[]")) {
		t.Fatalf("FormatC prefix = %q", cResult.Loader[:min(32, len(cResult.Loader))])
	}

	rubyResult, err := generator.Generate(
		context.Background(), payload,
		fritter.WithFormat(fritter.FormatRuby),
		fritter.WithEntropy(fritter.EntropyNone),
	)
	if err != nil {
		t.Fatalf("Generate(FormatRuby) error = %v", err)
	}
	if !bytes.HasPrefix(rubyResult.Loader, []byte("buf = [\n")) ||
		!bytes.HasSuffix(rubyResult.Loader, []byte("].pack(\"C*\")\n")) {
		t.Fatalf("FormatRuby output is not a Ruby byte-array expression")
	}

	pythonResult, err := generator.Generate(
		context.Background(), payload,
		fritter.WithFormat(fritter.FormatPython),
		fritter.WithEntropy(fritter.EntropyNone),
	)
	if err != nil {
		t.Fatalf("Generate(FormatPython) error = %v", err)
	}
	if !bytes.HasPrefix(pythonResult.Loader, []byte("buf   = b\"\"\n")) ||
		!bytes.Contains(pythonResult.Loader, []byte("buf  += b\"")) {
		t.Fatalf("FormatPython output is not a Python 3 bytes expression")
	}
}

func TestHTTPStagingRejectsExplicitlyEscapedPath(t *testing.T) {
	_, err := fritter.Generate(
		context.Background(),
		fritter.JScript{Source: jscriptPayload},
		fritter.WithEntropy(fritter.EntropyNone),
		fritter.WithHTTPStaging(mustURL(t, "https://example.com/a%2Fb")),
	)
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
		payload   fritter.Payload
		options   []fritter.GenerateOption
		wantField string
	}{
		{
			name:      "missing payload",
			wantField: "payload",
		},
		{
			name:      "empty script",
			payload:   fritter.JScript{},
			wantField: "source",
		},
		{
			name:      "invalid format",
			payload:   fritter.JScript{Source: jscriptPayload},
			options:   []fritter.GenerateOption{fritter.WithFormat(fritter.Format(255))},
			wantField: "format",
		},
		{
			name:      "invalid exit",
			payload:   fritter.JScript{Source: jscriptPayload},
			options:   []fritter.GenerateOption{fritter.WithExit(fritter.ExitBehavior(255))},
			wantField: "exit",
		},
		{
			name:      "invalid entropy",
			payload:   fritter.JScript{Source: jscriptPayload},
			options:   []fritter.GenerateOption{fritter.WithEntropy(fritter.Entropy(255))},
			wantField: "entropy",
		},
		{
			name:      "zero option",
			payload:   fritter.JScript{Source: jscriptPayload},
			options:   []fritter.GenerateOption{{}},
			wantField: "options[0]",
		},
		{
			name: "argument containing NUL",
			payload: fritter.NativeExecutable{
				Data:      []byte{1},
				Arguments: []string{"valid", "invalid\x00argument"},
			},
			wantField: "arguments[1]",
		},
		{
			name:      "native DLL parameter without export",
			payload:   fritter.NativeDLL{Data: []byte{1}, Parameter: "value"},
			wantField: "export",
		},
		{
			name:      "preserve PE headers on script",
			payload:   fritter.JScript{Source: jscriptPayload},
			options:   []fritter.GenerateOption{fritter.PreservePEHeaders()},
			wantField: "preservepeheaders",
		},
		{
			name:      "decoy path on script",
			payload:   fritter.JScript{Source: jscriptPayload},
			options:   []fritter.GenerateOption{fritter.WithDecoyModulePath(`C:\Windows\System32\version.dll`)},
			wantField: "decoymodulepath",
		},
		{
			name:      "NUL in decoy path",
			payload:   fritter.NativeExecutable{Data: nativeExecutablePayload},
			options:   []fritter.GenerateOption{fritter.WithDecoyModulePath("invalid\x00path")},
			wantField: "decoymodulepath",
		},
		{
			name:      "missing staging URL",
			payload:   fritter.JScript{Source: jscriptPayload},
			options:   []fritter.GenerateOption{fritter.WithHTTPStaging(nil, fritter.WithStagedModuleName("STAGE123"))},
			wantField: "baseurl",
		},
		{
			name:      "zero HTTP staging option",
			payload:   fritter.JScript{Source: jscriptPayload},
			options:   []fritter.GenerateOption{fritter.WithHTTPStaging(mustURL(t, "https://example.com/stage/"), fritter.HTTPStagingOption{})},
			wantField: "staging.options[0]",
		},
		{
			name:      "unsupported staging scheme",
			payload:   fritter.JScript{Source: jscriptPayload},
			options:   []fritter.GenerateOption{fritter.WithHTTPStaging(mustURL(t, "ftp://example.com/stage/"))},
			wantField: "baseurl",
		},
		{
			name:    "invalid staging hostname",
			payload: fritter.JScript{Source: jscriptPayload},
			options: []fritter.GenerateOption{
				fritter.WithHTTPStaging(&url.URL{
					Scheme: "https",
					Host:   "bad host",
					Path:   "/stage",
				}),
			},
			wantField: "baseurl",
		},
		{
			name:    "invalid staging port",
			payload: fritter.JScript{Source: jscriptPayload},
			options: []fritter.GenerateOption{
				fritter.WithHTTPStaging(&url.URL{
					Scheme: "https",
					Host:   "example.com:notaport",
					Path:   "/stage",
				}),
			},
			wantField: "baseurl",
		},
		{
			name:    "control byte in staging username",
			payload: fritter.JScript{Source: jscriptPayload},
			options: []fritter.GenerateOption{
				fritter.WithHTTPStaging(&url.URL{
					Scheme: "https",
					Host:   "example.com",
					Path:   "/stage",
					User:   url.UserPassword("user\nname", "password"),
				}),
			},
			wantField: "baseurl",
		},
		{
			name:      "query in staging URL",
			payload:   fritter.JScript{Source: jscriptPayload},
			options:   []fritter.GenerateOption{fritter.WithHTTPStaging(mustURL(t, "https://example.com/stage/?token=value"))},
			wantField: "baseurl",
		},
		{
			name:      "invalid staging module name",
			payload:   fritter.JScript{Source: jscriptPayload},
			options:   []fritter.GenerateOption{fritter.WithHTTPStaging(mustURL(t, "https://example.com/stage/"), fritter.WithStagedModuleName("TOO-LONG-1"))},
			wantField: "modulename",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := generator.Generate(ctx, tt.payload, tt.options...)
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
	_, err := fritter.Generate(
		context.Background(),
		fritter.NativeExecutable{Data: []byte("not a Portable Executable")},
	)
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
			_, err := fritter.Generate(context.Background(), tt.payload)
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
	result, err := fritter.Generate(
		context.Background(),
		fritter.JScript{Source: jscriptPayload},
		fritter.WithForkRVA(0x1234),
	)
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
	_, err = generator.Generate(canceled, fritter.JScript{Source: jscriptPayload})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Generate() cancellation error = %v, want context.Canceled", err)
	}

	if err := generator.Close(); err != nil {
		t.Fatalf("first Close() error = %v", err)
	}
	if err := generator.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	_, err = generator.Generate(context.Background(), fritter.JScript{Source: jscriptPayload})
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

func mustURL(t *testing.T, rawURL string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", rawURL, err)
	}
	return parsed
}

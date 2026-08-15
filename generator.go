package fritter

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/emscripten"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"github.com/tetratelabs/wazero/sys"
)

// Generator owns a compiled Fritter WebAssembly module. A Generator may be
// reused and called concurrently; each Generate call gets an isolated guest
// instance and filesystem.
type Generator struct {
	mu       sync.RWMutex
	runtime  wazero.Runtime
	compiled wazero.CompiledModule
	closed   bool
}

type execution struct {
	module   api.Module
	instance *moduleInstance
	stdout   *bytes.Buffer
	stderr   *bytes.Buffer
}

type moduleInstance struct {
	memory    api.Memory
	malloc    api.Function
	free      api.Function
	generate  api.Function
	writeFile api.Function
	fileSize  api.Function
	readFile  api.Function
}

// NewWithWASM creates a reusable Generator from a caller-supplied Fritter WASM
// module. The module must implement the typed bridge ABI used by this package.
func NewWithWASM(ctx context.Context, module []byte) (*Generator, error) {
	if len(module) == 0 {
		return nil, fmt.Errorf("compile Fritter WASM: module is empty")
	}

	runtime := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().WithCloseOnContextDone(true))
	if _, err := wasi_snapshot_preview1.Instantiate(ctx, runtime); err != nil {
		_ = runtime.Close(context.WithoutCancel(ctx))
		return nil, fmt.Errorf("instantiate WASI: %w", err)
	}

	compiled, err := runtime.CompileModule(ctx, module)
	if err != nil {
		_ = runtime.Close(context.WithoutCancel(ctx))
		return nil, fmt.Errorf("compile Fritter WASM: %w", err)
	}
	if err := validateCompiledModule(compiled); err != nil {
		_ = compiled.Close(context.WithoutCancel(ctx))
		_ = runtime.Close(context.WithoutCancel(ctx))
		return nil, err
	}

	if _, err := emscripten.InstantiateForModule(ctx, runtime, compiled); err != nil {
		_ = compiled.Close(context.WithoutCancel(ctx))
		_ = runtime.Close(context.WithoutCancel(ctx))
		return nil, fmt.Errorf("instantiate Emscripten environment: %w", err)
	}

	return &Generator{runtime: runtime, compiled: compiled}, nil
}

// Generate builds one loader. Payload bytes are copied into a fresh in-memory
// guest filesystem and are not retained or modified.
func (g *Generator) Generate(ctx context.Context, request Request) (Result, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.closed {
		return Result{}, ErrClosed
	}

	normalized, err := normalizeGeneration(request)
	if err != nil {
		return Result{}, err
	}

	execution, err := g.start(ctx)
	if err != nil {
		return Result{}, normalizeRuntimeError(ctx, err)
	}
	defer execution.close(context.WithoutCancel(ctx))

	if err := execution.instance.writeGuestFile(ctx, normalized.inputName, normalized.payload); err != nil {
		return Result{}, normalizeRuntimeError(ctx, fmt.Errorf("copy payload into Fritter: %w", err))
	}

	code, err := execution.instance.callGenerate(ctx, normalized)
	if err != nil {
		return Result{}, normalizeRuntimeError(ctx, err)
	}
	if code != 0 {
		return Result{}, &GenerationError{Code: ErrorCode(code)}
	}

	loader, err := execution.instance.readGuestFile(ctx, guestOutputName)
	if err != nil {
		return Result{}, normalizeRuntimeError(ctx, fmt.Errorf("read generated loader: %w", err))
	}
	result := Result{Loader: loader}

	if normalized.module != "" {
		module, err := execution.instance.readGuestFile(ctx, normalized.module)
		if err != nil {
			return Result{}, normalizeRuntimeError(ctx, fmt.Errorf("read generated staging module: %w", err))
		}
		moduleURL := *normalized.moduleURL
		result.StagedModule = &StagedModule{
			Name: normalized.module,
			URL:  moduleURL,
			Data: module,
		}
	}

	return result, nil
}

// Close releases the compiled module and runtime. It is safe to call Close
// more than once. Close waits for active Generate calls to finish.
func (g *Generator) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return nil
	}
	g.closed = true

	ctx := context.Background()
	var err error
	if g.compiled != nil {
		err = g.compiled.Close(ctx)
		g.compiled = nil
	}
	if g.runtime != nil {
		if closeErr := g.runtime.Close(ctx); err == nil {
			err = closeErr
		}
		g.runtime = nil
	}
	return err
}

func (g *Generator) start(ctx context.Context) (*execution, error) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	module, err := g.runtime.InstantiateModule(ctx, g.compiled, wazero.NewModuleConfig().
		WithName("").
		WithRandSource(rand.Reader).
		WithStdout(stdout).
		WithStderr(stderr))
	if err != nil {
		return nil, err
	}

	if initialize := findExportedFunction(module, "_initialize", "__initialize"); initialize != nil {
		if _, err := initialize.Call(ctx); err != nil {
			_ = module.Close(context.WithoutCancel(ctx))
			return nil, err
		}
	}

	instance, err := newModuleInstance(module)
	if err != nil {
		_ = module.Close(context.WithoutCancel(ctx))
		return nil, err
	}
	return &execution{module: module, instance: instance, stdout: stdout, stderr: stderr}, nil
}

func (e *execution) close(ctx context.Context) {
	if e.module != nil {
		_ = e.module.Close(ctx)
	}
}

func validateCompiledModule(compiled wazero.CompiledModule) error {
	if _, ok := compiled.ExportedMemories()["memory"]; !ok {
		return fmt.Errorf("Fritter WASM does not export memory")
	}

	i32 := api.ValueTypeI32
	required := []struct {
		names   []string
		params  []api.ValueType
		results []api.ValueType
	}{
		{names: []string{"malloc", "_malloc"}, params: []api.ValueType{i32}, results: []api.ValueType{i32}},
		{names: []string{"free", "_free"}, params: []api.ValueType{i32}},
		{
			names:   []string{"fritter_wasm_generate", "_fritter_wasm_generate"},
			params:  []api.ValueType{i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32},
			results: []api.ValueType{i32},
		},
		{names: []string{"fritter_wasm_write_file", "_fritter_wasm_write_file"}, params: []api.ValueType{i32, i32, i32}, results: []api.ValueType{i32}},
		{names: []string{"fritter_wasm_file_size", "_fritter_wasm_file_size"}, params: []api.ValueType{i32}, results: []api.ValueType{i32}},
		{names: []string{"fritter_wasm_read_file", "_fritter_wasm_read_file"}, params: []api.ValueType{i32, i32, i32}, results: []api.ValueType{i32}},
	}

	exports := compiled.ExportedFunctions()
	for _, expected := range required {
		var definition api.FunctionDefinition
		var exportName string
		for _, name := range expected.names {
			if candidate, ok := exports[name]; ok {
				definition = candidate
				exportName = name
				break
			}
		}
		if definition == nil {
			return fmt.Errorf("Fritter WASM does not export %s", expected.names[0])
		}
		if !slices.Equal(definition.ParamTypes(), expected.params) ||
			!slices.Equal(definition.ResultTypes(), expected.results) {
			return fmt.Errorf(
				"Fritter WASM export %s has signature params=%v results=%v; want params=%v results=%v",
				exportName,
				definition.ParamTypes(),
				definition.ResultTypes(),
				expected.params,
				expected.results,
			)
		}
	}
	return nil
}

func newModuleInstance(module api.Module) (*moduleInstance, error) {
	instance := &moduleInstance{
		memory:    module.Memory(),
		malloc:    findExportedFunction(module, "malloc", "_malloc"),
		free:      findExportedFunction(module, "free", "_free"),
		generate:  findExportedFunction(module, "fritter_wasm_generate", "_fritter_wasm_generate"),
		writeFile: findExportedFunction(module, "fritter_wasm_write_file", "_fritter_wasm_write_file"),
		fileSize:  findExportedFunction(module, "fritter_wasm_file_size", "_fritter_wasm_file_size"),
		readFile:  findExportedFunction(module, "fritter_wasm_read_file", "_fritter_wasm_read_file"),
	}

	switch {
	case instance.memory == nil:
		return nil, fmt.Errorf("Fritter WASM does not export memory")
	case instance.malloc == nil:
		return nil, fmt.Errorf("Fritter WASM does not export malloc")
	case instance.free == nil:
		return nil, fmt.Errorf("Fritter WASM does not export free")
	case instance.generate == nil:
		return nil, fmt.Errorf("Fritter WASM does not export fritter_wasm_generate")
	case instance.writeFile == nil:
		return nil, fmt.Errorf("Fritter WASM does not export fritter_wasm_write_file")
	case instance.fileSize == nil:
		return nil, fmt.Errorf("Fritter WASM does not export fritter_wasm_file_size")
	case instance.readFile == nil:
		return nil, fmt.Errorf("Fritter WASM does not export fritter_wasm_read_file")
	}
	return instance, nil
}

func findExportedFunction(module api.Module, names ...string) api.Function {
	for _, name := range names {
		if function := module.ExportedFunction(name); function != nil {
			return function
		}
	}
	return nil
}

func normalizeRuntimeError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if exitError, ok := err.(*sys.ExitError); ok {
		switch exitError.ExitCode() {
		case sys.ExitCodeContextCanceled:
			return context.Canceled
		case sys.ExitCodeDeadlineExceeded:
			return context.DeadlineExceeded
		}
	}
	return err
}

func (m *moduleInstance) allocBytes(ctx context.Context, data []byte) (uint32, func(), error) {
	if len(data) == 0 {
		data = []byte{0}
	}
	if uint64(len(data)) > uint64(^uint32(0)) {
		return 0, nil, fmt.Errorf("guest allocation exceeds 32-bit address space")
	}

	results, err := m.malloc.Call(ctx, uint64(len(data)))
	if err != nil {
		return 0, nil, err
	}
	if len(results) != 1 {
		return 0, nil, fmt.Errorf("Fritter WASM malloc returned %d results", len(results))
	}
	pointer := uint32(results[0])
	if pointer == 0 {
		return 0, nil, fmt.Errorf("Fritter WASM allocation of %d bytes failed", len(data))
	}
	if ok := m.memory.Write(pointer, data); !ok {
		_, _ = m.free.Call(context.WithoutCancel(ctx), uint64(pointer))
		return 0, nil, fmt.Errorf("write guest memory at %d", pointer)
	}

	release := func() {
		_, _ = m.free.Call(context.WithoutCancel(ctx), uint64(pointer))
	}
	return pointer, release, nil
}

func (m *moduleInstance) allocString(ctx context.Context, value string) (uint32, func(), error) {
	return m.allocBytes(ctx, append([]byte(value), 0))
}

func (m *moduleInstance) writeGuestFile(ctx context.Context, path string, data []byte) error {
	pathPointer, freePath, err := m.allocString(ctx, path)
	if err != nil {
		return err
	}
	defer freePath()

	dataPointer, freeData, err := m.allocBytes(ctx, data)
	if err != nil {
		return err
	}
	defer freeData()

	results, err := m.writeFile.Call(ctx, uint64(pathPointer), uint64(dataPointer), uint64(len(data)))
	if err != nil {
		return err
	}
	if len(results) != 1 {
		return fmt.Errorf("Fritter WASM file write returned %d results", len(results))
	}
	if code := uint32(results[0]); code != 0 {
		return &GenerationError{Code: ErrorCode(code)}
	}
	return nil
}

func (m *moduleInstance) readGuestFile(ctx context.Context, path string) ([]byte, error) {
	pathPointer, freePath, err := m.allocString(ctx, path)
	if err != nil {
		return nil, err
	}
	defer freePath()

	sizeResults, err := m.fileSize.Call(ctx, uint64(pathPointer))
	if err != nil {
		return nil, err
	}
	if len(sizeResults) != 1 {
		return nil, fmt.Errorf("Fritter WASM file size returned %d results", len(sizeResults))
	}
	size := int32(uint32(sizeResults[0]))
	if size < 0 {
		return nil, fmt.Errorf("guest artifact %q was not created", path)
	}
	if size == 0 {
		return []byte{}, nil
	}

	bufferPointer, freeBuffer, err := m.allocBytes(ctx, make([]byte, size))
	if err != nil {
		return nil, err
	}
	defer freeBuffer()

	results, err := m.readFile.Call(ctx, uint64(pathPointer), uint64(bufferPointer), uint64(size))
	if err != nil {
		return nil, err
	}
	if len(results) != 1 {
		return nil, fmt.Errorf("Fritter WASM file read returned %d results", len(results))
	}
	if code := uint32(results[0]); code != 0 {
		return nil, &GenerationError{Code: ErrorCode(code)}
	}

	data, ok := m.memory.Read(bufferPointer, uint32(size))
	if !ok {
		return nil, fmt.Errorf("read guest memory at %d", bufferPointer)
	}
	return bytes.Clone(data), nil
}

func (m *moduleInstance) callGenerate(ctx context.Context, generation normalizedGeneration) (uint32, error) {
	values := []string{
		generation.inputName,
		guestOutputName,
		generation.class,
		generation.method,
		generation.runtime,
		generation.domain,
		generation.decoy,
		generation.server,
		generation.module,
	}
	parameters := make([]uint64, 0, 16)
	releases := make([]func(), 0, len(values))
	defer func() {
		for index := len(releases) - 1; index >= 0; index-- {
			releases[index]()
		}
	}()

	for _, value := range values {
		pointer, release, err := m.allocString(ctx, value)
		if err != nil {
			return 0, err
		}
		parameters = append(parameters, uint64(pointer))
		releases = append(releases, release)
	}
	parameters = append(parameters,
		uint64(generation.format),
		uint64(generation.exit),
		uint64(generation.forkRVA),
		uint64(generation.entropy),
		uint64(generation.headers),
		uint64(generation.thread),
		uint64(generation.expectedType),
	)

	results, err := m.generate.Call(ctx, parameters...)
	if err != nil {
		return 0, err
	}
	if len(results) != 1 {
		return 0, fmt.Errorf("Fritter WASM generation returned %d results", len(results))
	}
	return uint32(results[0]), nil
}

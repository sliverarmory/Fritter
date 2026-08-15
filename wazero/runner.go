package fritterwazero

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/emscripten"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"github.com/tetratelabs/wazero/sys"
)

const wasmPathEnvVar = "FRITTER_WASM_PATH"

type Result struct {
	Stdout string
	Stderr string

	ExitCode uint32

	OutputName string
	Output     []byte

	ModuleName string
	Module     []byte

	Files map[string][]byte
}

type CLIError struct {
	ExitCode uint32
	Stdout   string
	Stderr   string
}

func (e *CLIError) Error() string {
	return fmt.Sprintf("fritter exited with code %d", e.ExitCode)
}

type Runner struct {
	runtime  wazero.Runtime
	compiled wazero.CompiledModule
}

type execution struct {
	mod      api.Module
	stdout   *bytes.Buffer
	stderr   *bytes.Buffer
	instance *moduleInstance
}

type moduleInstance struct {
	memory    api.Memory
	malloc    api.Function
	free      api.Function
	run       api.Function
	writeFile api.Function
	fileSize  api.Function
	readFile  api.Function
}

func DefaultModulePath() string {
	if env := os.Getenv(wasmPathEnvVar); env != "" {
		return env
	}

	_, filename, _, ok := goruntime.Caller(0)
	if !ok {
		return filepath.Join("dist", "fritter.wasm")
	}

	return filepath.Join(filepath.Dir(filepath.Dir(filename)), "dist", "fritter.wasm")
}

func New(ctx context.Context, wasm []byte) (*Runner, error) {
	r := wazero.NewRuntime(ctx)
	if _, err := wasi_snapshot_preview1.Instantiate(ctx, r); err != nil {
		_ = r.Close(ctx)
		return nil, fmt.Errorf("instantiate wasi: %w", err)
	}

	compiled, err := r.CompileModule(ctx, wasm)
	if err != nil {
		_ = r.Close(ctx)
		return nil, fmt.Errorf("compile wasm: %w", err)
	}

	if _, err := emscripten.InstantiateForModule(ctx, r, compiled); err != nil {
		_ = compiled.Close(ctx)
		_ = r.Close(ctx)
		return nil, fmt.Errorf("instantiate emscripten env: %w", err)
	}

	return &Runner{
		runtime:  r,
		compiled: compiled,
	}, nil
}

func NewFromPath(ctx context.Context, wasmPath string) (*Runner, error) {
	wasm, err := os.ReadFile(wasmPath)
	if err != nil {
		return nil, fmt.Errorf("read wasm module %q: %w", wasmPath, err)
	}
	return New(ctx, wasm)
}

func NewFromDefaultPath(ctx context.Context) (*Runner, error) {
	return NewFromPath(ctx, DefaultModulePath())
}

func (r *Runner) Close(ctx context.Context) error {
	var err error
	if r.compiled != nil {
		err = r.compiled.Close(ctx)
	}
	if r.runtime != nil {
		if closeErr := r.runtime.Close(ctx); err == nil {
			err = closeErr
		}
	}
	return err
}

func (r *Runner) Usage(ctx context.Context) (string, error) {
	exec, err := r.start(ctx)
	if err != nil {
		return "", err
	}
	defer exec.close(ctx)

	exitCode, err := exec.instance.callCLI(ctx, []string{"fritter", "--help"})
	result := exec.result(exitCode)
	if exitErr := wrapExitError(err, result); exitErr != nil {
		return "", exitErr
	}
	return result.Stdout, nil
}

func (r *Runner) Generate(ctx context.Context, opts Options) (Result, error) {
	if err := opts.validate(); err != nil {
		return Result{}, err
	}

	exec, err := r.start(ctx)
	if err != nil {
		return Result{}, err
	}
	defer exec.close(ctx)

	inputName := filepath.Base(opts.InputPath)
	inputData, err := os.ReadFile(opts.InputPath)
	if err != nil {
		return Result{}, fmt.Errorf("read input %q: %w", opts.InputPath, err)
	}
	if err := exec.instance.writeGuestFile(ctx, inputName, inputData); err != nil {
		return Result{}, err
	}

	if opts.DecoyPath != "" {
		decoyName := filepath.Base(opts.DecoyPath)
		decoyData, err := os.ReadFile(opts.DecoyPath)
		if err != nil {
			return Result{}, fmt.Errorf("read decoy %q: %w", opts.DecoyPath, err)
		}
		if err := exec.instance.writeGuestFile(ctx, decoyName, decoyData); err != nil {
			return Result{}, err
		}
	}

	exitCode, err := exec.instance.callCLI(ctx, opts.Args())
	result := exec.result(exitCode)
	if exitErr := wrapExitError(err, result); exitErr != nil {
		return result, exitErr
	}
	if result.ExitCode != 0 {
		return result, &CLIError{
			ExitCode: result.ExitCode,
			Stdout:   result.Stdout,
			Stderr:   result.Stderr,
		}
	}

	result.Files = map[string][]byte{}

	outputName := opts.OutputFileName()
	output, err := exec.instance.readGuestFile(ctx, outputName)
	if err != nil {
		return result, err
	}
	result.OutputName = outputName
	result.Output = output
	result.Files[outputName] = output

	moduleName := opts.ModuleName
	if opts.ServerURL != "" && moduleName == "" {
		moduleName = discoverModuleName(result.Stdout)
	}
	if moduleName != "" {
		module, err := exec.instance.readGuestFile(ctx, moduleName)
		if err == nil {
			result.ModuleName = moduleName
			result.Module = module
			result.Files[moduleName] = module
		}
	}

	return result, nil
}

func (r *Runner) start(ctx context.Context) (*execution, error) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	mod, err := r.runtime.InstantiateModule(ctx, r.compiled, wazero.NewModuleConfig().
		WithStdout(stdout).
		WithStderr(stderr))
	if err != nil {
		return nil, err
	}

	if initFn := findExportedFunction(mod, "_initialize", "__initialize"); initFn != nil {
		if _, err := initFn.Call(ctx); err != nil {
			_ = mod.Close(ctx)
			return nil, err
		}
	}

	instance, err := newModuleInstance(mod)
	if err != nil {
		_ = mod.Close(ctx)
		return nil, err
	}

	return &execution{
		mod:      mod,
		stdout:   stdout,
		stderr:   stderr,
		instance: instance,
	}, nil
}

func (e *execution) close(ctx context.Context) {
	if e.mod != nil {
		_ = e.mod.Close(ctx)
	}
}

func (e *execution) result(exitCode uint32) Result {
	return Result{
		Stdout:   e.stdout.String(),
		Stderr:   e.stderr.String(),
		ExitCode: exitCode,
		Files:    map[string][]byte{},
	}
}

func newModuleInstance(mod api.Module) (*moduleInstance, error) {
	instance := &moduleInstance{
		memory:    mod.Memory(),
		malloc:    findExportedFunction(mod, "malloc", "_malloc"),
		free:      findExportedFunction(mod, "free", "_free"),
		run:       findExportedFunction(mod, "fritter_wasm_run", "_fritter_wasm_run"),
		writeFile: findExportedFunction(mod, "fritter_wasm_write_file", "_fritter_wasm_write_file"),
		fileSize:  findExportedFunction(mod, "fritter_wasm_file_size", "_fritter_wasm_file_size"),
		readFile:  findExportedFunction(mod, "fritter_wasm_read_file", "_fritter_wasm_read_file"),
	}

	switch {
	case instance.memory == nil:
		return nil, fmt.Errorf("wasm module does not export memory")
	case instance.malloc == nil:
		return nil, fmt.Errorf("wasm module does not export malloc")
	case instance.free == nil:
		return nil, fmt.Errorf("wasm module does not export free")
	case instance.run == nil:
		return nil, fmt.Errorf("wasm module does not export fritter_wasm_run")
	case instance.writeFile == nil:
		return nil, fmt.Errorf("wasm module does not export fritter_wasm_write_file")
	case instance.fileSize == nil:
		return nil, fmt.Errorf("wasm module does not export fritter_wasm_file_size")
	case instance.readFile == nil:
		return nil, fmt.Errorf("wasm module does not export fritter_wasm_read_file")
	}

	return instance, nil
}

func findExportedFunction(mod api.Module, names ...string) api.Function {
	for _, name := range names {
		if fn := mod.ExportedFunction(name); fn != nil {
			return fn
		}
	}
	return nil
}

func wrapExitError(err error, result Result) error {
	if err == nil {
		return nil
	}
	if exitErr, ok := err.(*sys.ExitError); ok {
		if exitErr.ExitCode() == 0 {
			return nil
		}
		return &CLIError{
			ExitCode: exitErr.ExitCode(),
			Stdout:   result.Stdout,
			Stderr:   result.Stderr,
		}
	}
	return err
}

func (m *moduleInstance) allocBytes(ctx context.Context, data []byte) (uint32, func(), error) {
	if len(data) == 0 {
		data = []byte{0}
	}

	results, err := m.malloc.Call(ctx, uint64(len(data)))
	if err != nil {
		return 0, nil, err
	}

	ptr := uint32(results[0])
	if ok := m.memory.Write(ptr, data); !ok {
		return 0, nil, fmt.Errorf("write guest memory at %d", ptr)
	}

	release := func() {
		_, _ = m.free.Call(ctx, uint64(ptr))
	}

	return ptr, release, nil
}

func (m *moduleInstance) allocString(ctx context.Context, value string) (uint32, func(), error) {
	return m.allocBytes(ctx, append([]byte(value), 0))
}

func (m *moduleInstance) writeGuestFile(ctx context.Context, path string, data []byte) error {
	pathPtr, freePath, err := m.allocString(ctx, path)
	if err != nil {
		return err
	}
	defer freePath()

	dataPtr, freeData, err := m.allocBytes(ctx, data)
	if err != nil {
		return err
	}
	defer freeData()

	results, err := m.writeFile.Call(ctx, uint64(pathPtr), uint64(dataPtr), uint64(len(data)))
	if err != nil {
		return err
	}
	if len(results) != 1 || uint32(results[0]) != 0 {
		return fmt.Errorf("write guest file %q failed with code %d", path, uint32(results[0]))
	}

	return nil
}

func (m *moduleInstance) readGuestFile(ctx context.Context, path string) ([]byte, error) {
	pathPtr, freePath, err := m.allocString(ctx, path)
	if err != nil {
		return nil, err
	}
	defer freePath()

	sizeResults, err := m.fileSize.Call(ctx, uint64(pathPtr))
	if err != nil {
		return nil, err
	}
	if len(sizeResults) != 1 {
		return nil, fmt.Errorf("unexpected file size result count for %q", path)
	}

	size := int32(uint32(sizeResults[0]))
	if size < 0 {
		return nil, fmt.Errorf("guest file %q not found", path)
	}
	if size == 0 {
		return []byte{}, nil
	}

	bufPtr, freeBuf, err := m.allocBytes(ctx, make([]byte, size))
	if err != nil {
		return nil, err
	}
	defer freeBuf()

	results, err := m.readFile.Call(ctx, uint64(pathPtr), uint64(bufPtr), uint64(size))
	if err != nil {
		return nil, err
	}
	if len(results) != 1 || uint32(results[0]) != 0 {
		return nil, fmt.Errorf("read guest file %q failed with code %d", path, uint32(results[0]))
	}

	data, ok := m.memory.Read(bufPtr, uint32(size))
	if !ok {
		return nil, fmt.Errorf("read guest memory at %d", bufPtr)
	}

	return append([]byte(nil), data...), nil
}

func (m *moduleInstance) callCLI(ctx context.Context, args []string) (uint32, error) {
	argc := len(args)
	argPtrs := make([]uint32, 0, argc)
	releases := make([]func(), 0, argc+1)
	defer func() {
		for i := len(releases) - 1; i >= 0; i-- {
			releases[i]()
		}
	}()

	for _, arg := range args {
		ptr, release, err := m.allocString(ctx, arg)
		if err != nil {
			return 0, err
		}
		argPtrs = append(argPtrs, ptr)
		releases = append(releases, release)
	}

	argv := make([]byte, argc*4)
	for i, ptr := range argPtrs {
		binary.LittleEndian.PutUint32(argv[i*4:], ptr)
	}

	argvPtr, releaseArgv, err := m.allocBytes(ctx, argv)
	if err != nil {
		return 0, err
	}
	releases = append(releases, releaseArgv)

	results, err := m.run.Call(ctx, uint64(argc), uint64(argvPtr))
	if err != nil {
		return 0, err
	}
	if len(results) != 1 {
		return 0, fmt.Errorf("unexpected run result count")
	}

	return uint32(results[0]), nil
}

func discoverModuleName(stdout string) string {
	for _, line := range strings.Split(stdout, "\n") {
		fields := strings.Fields(line)
		for i := 0; i+1 < len(fields); i++ {
			if fields[i] == "Module" {
				return fields[i+1]
			}
		}
	}
	return ""
}

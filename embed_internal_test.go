package fritter

import (
	"context"
	"testing"

	"github.com/tetratelabs/wazero"
)

func TestEmbeddedModuleDoesNotExportLegacyCLI(t *testing.T) {
	ctx := context.Background()
	runtime := wazero.NewRuntime(ctx)
	t.Cleanup(func() {
		if err := runtime.Close(ctx); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})

	compiled, err := runtime.CompileModule(ctx, embeddedModule)
	if err != nil {
		t.Fatalf("CompileModule() error = %v", err)
	}
	for _, name := range []string{"fritter_wasm_run", "_fritter_wasm_run"} {
		if _, ok := compiled.ExportedFunctions()[name]; ok {
			t.Errorf("embedded module still exports legacy CLI bridge %q", name)
		}
	}
}

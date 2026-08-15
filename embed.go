package fritter

import (
	"context"
	_ "embed"
	"fmt"
)

//go:embed dist/fritter.wasm
var embeddedModule []byte

// New creates a reusable Generator backed by the embedded Fritter WebAssembly
// module. Close the generator when it is no longer needed.
func New(ctx context.Context) (*Generator, error) {
	generator, err := NewWithWASM(ctx, embeddedModule)
	if err != nil {
		return nil, fmt.Errorf("initialize embedded Fritter module: %w", err)
	}
	return generator, nil
}

// Generate performs one generation with the embedded module. Create a
// Generator with New when producing multiple loaders so compilation is reused.
func Generate(ctx context.Context, payload Payload, options ...GenerateOption) (result Result, err error) {
	generator, err := New(ctx)
	if err != nil {
		return Result{}, err
	}
	defer func() {
		if closeErr := generator.Close(); err == nil && closeErr != nil {
			result = Result{}
			err = fmt.Errorf("close Fritter generator: %w", closeErr)
		}
	}()

	return generator.Generate(ctx, payload, options...)
}

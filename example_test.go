package fritter_test

import (
	"context"
	"fmt"

	"github.com/sliverarmory/Fritter"
)

func ExampleGenerate() {
	result, err := fritter.Generate(
		context.Background(),
		fritter.JScript([]byte(`WScript.Echo("hello");`)),
	)
	fmt.Println(err == nil, len(result.Loader) > 0)
	// Output: true true
}

func ExampleWithArguments() {
	payload := []byte("native executable bytes")
	_, _ = fritter.Generate(
		context.Background(),
		fritter.NativeExecutable(payload),
		fritter.WithArguments("arg1", "arg2", "two words", ""),
	)
}

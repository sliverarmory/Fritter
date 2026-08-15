package fritter_test

import (
	"context"
	"fmt"

	"github.com/sliverarmory/Fritter"
)

func ExampleGenerate() {
	result, err := fritter.Generate(context.Background(), fritter.Request{
		Payload: fritter.JScript{Source: []byte(`WScript.Echo("hello");`)},
	})
	fmt.Println(err == nil, len(result.Loader) > 0)
	// Output: true true
}

func ExampleRequest() {
	payload := []byte("native executable image")
	request := fritter.Request{
		Payload: fritter.NativeExecutable{
			Image: payload,
			Flags: fritter.NativeExecutableRunInThread,
			PE: fritter.NativePEConfig{
				Headers:         fritter.PEHeadersPreserve,
				DecoyModulePath: `C:\Windows\System32\version.dll`,
			},
		},
		Format: fritter.FormatBinary,
		Loader: fritter.LoaderConfig{
			Exit:    fritter.ExitThread,
			Entropy: fritter.EntropyDefault,
		},
	}
	_, _ = fritter.Generate(context.Background(), request)
}

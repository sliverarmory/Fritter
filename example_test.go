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

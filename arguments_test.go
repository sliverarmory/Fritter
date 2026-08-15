package fritter

import (
	"errors"
	"strings"
	"testing"
)

func TestEncodeArguments(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "nil", args: nil, want: ""},
		{name: "empty slice", args: []string{}, want: ""},
		{name: "empty argument", args: []string{""}, want: `""`},
		{name: "simple", args: []string{"one", "two"}, want: "one two"},
		{name: "space", args: []string{"one", "two words"}, want: `one "two words"`},
		{name: "tab", args: []string{"one\ttwo"}, want: "\"one\ttwo\""},
		{name: "quote", args: []string{`one"two`}, want: `one\"two`},
		{name: "quoted trailing slash", args: []string{`C:\Program Files\`}, want: `"C:\Program Files\\"`},
		{name: "unicode", args: []string{"雪", "man"}, want: "雪 man"},
		{name: "maximum encoded length", args: []string{strings.Repeat("x", maxArgumentsBytes)}, want: strings.Repeat("x", maxArgumentsBytes)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := encodeArguments(tt.args)
			if err != nil {
				t.Fatalf("encodeArguments() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("encodeArguments() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestEncodeArgumentsRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		wantField string
	}{
		{name: "NUL", args: []string{"one", "two\x00three"}, wantField: "payload.arguments[1]"},
		{name: "encoded command line too long", args: []string{strings.Repeat("x", maxArgumentsBytes+1)}, wantField: "payload.arguments"},
		{name: "quoting exceeds limit", args: []string{strings.Repeat("x", maxArgumentsBytes-2) + " "}, wantField: "payload.arguments"},
		{name: "invalid UTF-8", args: []string{string([]byte{0xff})}, wantField: "payload.arguments[0]"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := encodeArguments(tt.args)
			if err == nil {
				t.Fatal("encodeArguments() error = nil, want validation error")
			}
			var validationErr *ValidationError
			if !errors.As(err, &validationErr) {
				t.Fatalf("encodeArguments() error type = %T, want *ValidationError: %v", err, err)
			}
			if validationErr.Field != tt.wantField {
				t.Fatalf("ValidationError.Field = %q, want %q", validationErr.Field, tt.wantField)
			}
		})
	}
}

package fritter

import (
	"errors"
	"fmt"
)

// ErrClosed is returned when Generate is called after Generator.Close.
var ErrClosed = errors.New("fritter: generator is closed")

// ValidationError reports an invalid Request field.
type ValidationError struct {
	Field   string
	Problem string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("fritter: invalid %s: %s", e.Field, e.Problem)
}

// ErrorCode is a stable error code returned by Fritter's generation engine.
type ErrorCode uint32

const (
	// ErrorFileNotFound means an expected guest file was not found.
	ErrorFileNotFound ErrorCode = 1
	// ErrorFileEmpty means the input payload is empty.
	ErrorFileEmpty ErrorCode = 2
	// ErrorFileAccess means a guest file could not be opened.
	ErrorFileAccess ErrorCode = 3
	// ErrorFileInvalid means the payload format or structure is invalid.
	ErrorFileInvalid ErrorCode = 4
	// ErrorDotNetParameters means a .NET DLL lacks a class or method.
	ErrorDotNetParameters ErrorCode = 5
	// ErrorOutOfMemory means native generation could not allocate memory.
	ErrorOutOfMemory ErrorCode = 6
	// ErrorInvalidArchitecture means the configured architecture is invalid.
	ErrorInvalidArchitecture ErrorCode = 7
	// ErrorInvalidURL means an HTTP staging URL is invalid.
	ErrorInvalidURL ErrorCode = 8
	// ErrorURLTooLong means an HTTP staging URL exceeds the native limit.
	ErrorURLTooLong ErrorCode = 9
	// ErrorInvalidParameter means a native generation parameter is invalid.
	ErrorInvalidParameter ErrorCode = 10
	// ErrorRandom means secure random generation failed.
	ErrorRandom ErrorCode = 11
	// ErrorDLLExport means a requested native DLL export was not found.
	ErrorDLLExport ErrorCode = 12
	// ErrorArchitectureMismatch means the payload architecture is unsupported.
	ErrorArchitectureMismatch ErrorCode = 13
	// ErrorDLLParameter means a native DLL parameter lacks an export.
	ErrorDLLParameter ErrorCode = 14
	// ErrorInvalidFormat means the output format is invalid.
	ErrorInvalidFormat ErrorCode = 16
	// ErrorCompressionEngine means the compression engine is invalid.
	ErrorCompressionEngine ErrorCode = 17
	// ErrorCompression means payload compression failed.
	ErrorCompression ErrorCode = 18
	// ErrorInvalidEntropy means the entropy mode is invalid.
	ErrorInvalidEntropy ErrorCode = 19
	// ErrorMixedAssembly means a mixed native and managed assembly is unsupported.
	ErrorMixedAssembly ErrorCode = 20
	// ErrorInvalidHeaders means the PE-header option is invalid.
	ErrorInvalidHeaders ErrorCode = 21
	// ErrorInvalidDecoy means the target decoy module path is invalid.
	ErrorInvalidDecoy ErrorCode = 22
	// ErrorPayloadTypeMismatch means the payload bytes do not match their
	// concrete Go payload type.
	ErrorPayloadTypeMismatch ErrorCode = 23
)

// String returns the human-readable description associated with c.
func (c ErrorCode) String() string {
	switch c {
	case ErrorFileNotFound:
		return "file not found"
	case ErrorFileEmpty:
		return "file is empty"
	case ErrorFileAccess:
		return "cannot access file"
	case ErrorFileInvalid:
		return "file is invalid"
	case ErrorDotNetParameters:
		return ".NET DLL requires a class and method"
	case ErrorOutOfMemory:
		return "memory allocation failed"
	case ErrorInvalidArchitecture:
		return "invalid architecture"
	case ErrorInvalidURL:
		return "invalid URL"
	case ErrorURLTooLong:
		return "URL is too long"
	case ErrorInvalidParameter:
		return "invalid parameter"
	case ErrorRandom:
		return "random generation failed"
	case ErrorDLLExport:
		return "DLL export was not found"
	case ErrorArchitectureMismatch:
		return "payload architecture is not supported"
	case ErrorDLLParameter:
		return "native DLL parameter requires an export"
	case ErrorInvalidFormat:
		return "invalid output format"
	case ErrorCompressionEngine:
		return "invalid compression engine"
	case ErrorCompression:
		return "compression failed"
	case ErrorInvalidEntropy:
		return "invalid entropy"
	case ErrorMixedAssembly:
		return "mixed native and managed assemblies are unsupported"
	case ErrorInvalidHeaders:
		return "invalid PE header option"
	case ErrorInvalidDecoy:
		return "invalid decoy module path"
	case ErrorPayloadTypeMismatch:
		return "payload bytes do not match the requested payload type"
	default:
		return fmt.Sprintf("unknown error code %d", c)
	}
}

// GenerationError reports a domain error returned by Fritter while generating
// a loader.
type GenerationError struct {
	Code ErrorCode
}

func (e *GenerationError) Error() string {
	return fmt.Sprintf("fritter: generation failed: %s", e.Code)
}

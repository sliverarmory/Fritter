// Package fritter generates 64-bit Windows Fritter loaders in-process using an
// embedded WebAssembly module. The package accepts and returns bytes; it never
// reads or writes host files.
package fritter

import "net/url"

// Payload is one of the payload types supported by Fritter. Its concrete type
// identifies the payload format and which invocation options are valid.
//
// The supported implementations are NativeExecutable, NativeDLL,
// DotNetExecutable, DotNetDLL, VBScript, and JScript.
type Payload interface {
	fritterPayload()
}

// NativeExecutable is an unmanaged Windows executable image.
type NativeExecutable []byte

func (NativeExecutable) fritterPayload() {}

// NativeDLL is an unmanaged Windows DLL image.
type NativeDLL []byte

func (NativeDLL) fritterPayload() {}

// DotNetExecutable is a managed Windows executable assembly.
type DotNetExecutable []byte

func (DotNetExecutable) fritterPayload() {}

// DotNetDLL is a managed Windows library assembly.
type DotNetDLL []byte

func (DotNetDLL) fritterPayload() {}

// VBScript is VBScript source encoded for the target Windows environment.
type VBScript []byte

func (VBScript) fritterPayload() {}

// JScript is JScript source encoded for the target Windows environment.
type JScript []byte

func (JScript) fritterPayload() {}

// Result contains the generated loader and, for staged generation, its module.
// Returned byte slices are owned by the caller.
type Result struct {
	Loader       []byte
	StagedModule *StagedModule
}

// StagedModule is the payload module to host at URL.
type StagedModule struct {
	Name string
	URL  url.URL
	Data []byte
}

// Format selects the representation of Result.Loader.
type Format uint8

const (
	// FormatBinary returns raw shellcode bytes and is the zero-value default.
	FormatBinary Format = iota
	// FormatBase64 returns Base64 text.
	FormatBase64
	// FormatC returns a C source representation.
	FormatC
	// FormatRuby returns a Ruby source representation.
	FormatRuby
	// FormatPython returns a Python 3 bytes-source representation.
	FormatPython
	// FormatPowerShell returns a PowerShell source representation.
	FormatPowerShell
	// FormatCSharp returns a C# source representation.
	FormatCSharp
	// FormatHex returns hexadecimal text.
	FormatHex
	// FormatUUID returns UUID strings.
	FormatUUID
)

// ExitBehavior controls what the loader does after the payload returns.
type ExitBehavior uint8

const (
	// ExitThread exits the current thread and is the zero-value default.
	ExitThread ExitBehavior = iota
	// ExitProcess exits the host process.
	ExitProcess
	// ExitBlock blocks instead of returning.
	ExitBlock
)

// Entropy controls optional per-output randomization.
type Entropy uint8

const (
	// EntropyDefault randomizes names and cryptographic material. It is the
	// zero-value default.
	EntropyDefault Entropy = iota
	// EntropyNames randomizes names without encrypting the module and instance.
	EntropyNames
	// EntropyNone disables optional name and cryptographic randomization.
	EntropyNone
)

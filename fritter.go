// Package fritter generates 64-bit Windows Fritter loaders in-process using an
// embedded WebAssembly module. The package accepts and returns bytes; it never
// reads or writes host files.
package fritter

import "net/url"

// Payload is one of the payload types supported by Fritter. The concrete
// payload value also describes how the payload will be invoked.
//
// The supported implementations are NativeExecutable, NativeDLL,
// DotNetExecutable, DotNetDLL, VBScript, and JScript.
type Payload interface {
	fritterPayload()
}

// NativeExecutable is an unmanaged Windows executable. Arguments contains
// argv[1:] values; Fritter supplies a synthetic argv[0] inside the loader.
type NativeExecutable struct {
	Data        []byte
	Arguments   []string
	RunInThread bool
}

func (NativeExecutable) fritterPayload() {}

// NativeDLL is an unmanaged Windows DLL. DllMain is always invoked. When
// Export is non-empty, that export is invoked after DllMain. Parameter is an
// optional single text buffer passed to the export, not an argv slice.
type NativeDLL struct {
	Data           []byte
	Export         string
	Parameter      string
	UTF16Parameter bool
}

func (NativeDLL) fritterPayload() {}

// DotNetExecutable is a managed Windows executable. Arguments is supplied to
// the assembly entry point as its string array.
type DotNetExecutable struct {
	Data           []byte
	Arguments      []string
	RuntimeVersion string
	AppDomain      string
}

func (DotNetExecutable) fritterPayload() {}

// DotNetDLL is a managed Windows library. Class and Method identify the static
// method to invoke. Arguments supplies its positional string parameters.
type DotNetDLL struct {
	Data           []byte
	Class          string
	Method         string
	Arguments      []string
	RuntimeVersion string
	AppDomain      string
}

func (DotNetDLL) fritterPayload() {}

// VBScript is a VBScript source payload.
type VBScript struct {
	Source []byte
}

func (VBScript) fritterPayload() {}

// JScript is a JScript source payload.
type JScript struct {
	Source []byte
}

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

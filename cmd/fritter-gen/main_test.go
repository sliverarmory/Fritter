package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/sliverarmory/Fritter"
)

func TestPayloadForPathClassifiesPEContents(t *testing.T) {
	nativeEXE := readNativeEXE(t)

	payload, err := payloadForPath("payload.exe", nativeEXE, payloadOptions{})
	if err != nil {
		t.Fatalf("payloadForPath(native EXE) error = %v", err)
	}
	executable, ok := payload.(fritter.NativeExecutable)
	if !ok {
		t.Fatalf("payloadForPath(native EXE) type = %T", payload)
	}
	if !bytes.Equal(executable.Image, nativeEXE) {
		t.Fatal("NativeExecutable.Image differs from input")
	}
	if executable.Flags != 0 || executable.PE != (fritter.NativePEConfig{}) {
		t.Fatalf("NativeExecutable defaults = %#v, want zero values", executable)
	}

	managedEXE := withPEFlags(t, nativeEXE, false, true)
	payload, err = payloadForPath("payload.exe", managedEXE, payloadOptions{
		runtimeVersion: fritter.DotNetRuntimeV4,
		appDomain:      "Example",
	})
	if err != nil {
		t.Fatalf("payloadForPath(managed EXE) error = %v", err)
	}
	managedExecutable, ok := payload.(fritter.DotNetExecutable)
	if !ok {
		t.Fatalf("payloadForPath(managed EXE) type = %T", payload)
	}
	if !bytes.Equal(managedExecutable.Assembly, managedEXE) {
		t.Fatal("DotNetExecutable.Assembly differs from input")
	}
	if got, want := managedExecutable.Runtime, (fritter.DotNetRuntime{Version: fritter.DotNetRuntimeV4, AppDomain: "Example"}); got != want {
		t.Fatalf("DotNetExecutable.Runtime = %#v, want %#v", got, want)
	}

	managedDLL := withPEFlags(t, nativeEXE, true, true)
	payload, err = payloadForPath("payload.dll", managedDLL, payloadOptions{
		class:          "Example.Loader",
		method:         "Run",
		runtimeVersion: fritter.DotNetRuntimeV2,
		appDomain:      "Managed",
	})
	if err != nil {
		t.Fatalf("payloadForPath(managed DLL) error = %v", err)
	}
	managedLibrary, ok := payload.(fritter.DotNetDLL)
	if !ok {
		t.Fatalf("payloadForPath(managed DLL) type = %T", payload)
	}
	if !bytes.Equal(managedLibrary.Assembly, managedDLL) {
		t.Fatal("DotNetDLL.Assembly differs from input")
	}
	if got, want := managedLibrary.EntryPoint, (fritter.DotNetStaticMethod{TypeName: "Example.Loader", MethodName: "Run"}); got != want {
		t.Fatalf("DotNetDLL.EntryPoint = %#v, want %#v", got, want)
	}
	if got, want := managedLibrary.Runtime, (fritter.DotNetRuntime{Version: fritter.DotNetRuntimeV2, AppDomain: "Managed"}); got != want {
		t.Fatalf("DotNetDLL.Runtime = %#v, want %#v", got, want)
	}
}

func TestPayloadForPathMapsParameterlessNativeDLLExport(t *testing.T) {
	nativeDLL := withPEFlags(t, readNativeEXE(t), true, false)

	tests := []struct {
		name       string
		method     string
		wantExport *fritter.NativeDLLExport
	}{
		{name: "DllMain only"},
		{name: "named export", method: "Run", wantExport: &fritter.NativeDLLExport{Name: "Run"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload, err := payloadForPath("payload.dll", nativeDLL, payloadOptions{method: test.method})
			if err != nil {
				t.Fatalf("payloadForPath() error = %v", err)
			}
			library, ok := payload.(fritter.NativeDLL)
			if !ok {
				t.Fatalf("payloadForPath() type = %T, want fritter.NativeDLL", payload)
			}
			if !bytes.Equal(library.Image, nativeDLL) {
				t.Fatal("NativeDLL.Image differs from input")
			}
			if test.wantExport == nil {
				if library.Export != nil {
					t.Fatalf("NativeDLL.Export = %#v, want nil", library.Export)
				}
				return
			}
			if library.Export == nil || *library.Export != *test.wantExport {
				t.Fatalf("NativeDLL.Export = %#v, want %#v", library.Export, test.wantExport)
			}
		})
	}
}

func TestPayloadForPathMapsScripts(t *testing.T) {
	vbscript := []byte(`WScript.Echo "hello"`)
	payload, err := payloadForPath("payload.vbs", vbscript, payloadOptions{})
	if err != nil {
		t.Fatalf("payloadForPath(VBScript) error = %v", err)
	}
	vbs, ok := payload.(fritter.VBScript)
	if !ok || !bytes.Equal(vbs.Source, vbscript) {
		t.Fatalf("payloadForPath(VBScript) = %#v", payload)
	}

	jscript := []byte(`WScript.Echo("hello");`)
	payload, err = payloadForPath("payload.js", jscript, payloadOptions{})
	if err != nil {
		t.Fatalf("payloadForPath(JScript) error = %v", err)
	}
	js, ok := payload.(fritter.JScript)
	if !ok || !bytes.Equal(js.Source, jscript) {
		t.Fatalf("payloadForPath(JScript) = %#v", payload)
	}
}

func TestPayloadForPathRejectsInvalidMappings(t *testing.T) {
	nativeEXE := readNativeEXE(t)
	nativeDLL := withPEFlags(t, nativeEXE, true, false)

	tests := []struct {
		name    string
		path    string
		data    []byte
		options payloadOptions
	}{
		{name: "EXE name with DLL contents", path: "payload.exe", data: nativeDLL},
		{name: "DLL name with EXE contents", path: "payload.dll", data: nativeEXE},
		{name: "DLL method on EXE", path: "payload.exe", data: nativeEXE, options: payloadOptions{method: "Run"}},
		{name: ".NET runtime on native EXE", path: "payload.exe", data: nativeEXE, options: payloadOptions{runtimeVersion: fritter.DotNetRuntimeV4}},
		{name: ".NET class on native DLL", path: "payload.dll", data: nativeDLL, options: payloadOptions{class: "Example.Loader"}},
		{name: ".NET runtime on native DLL", path: "payload.dll", data: nativeDLL, options: payloadOptions{runtimeVersion: fritter.DotNetRuntimeV4}},
		{name: "invocation flag on script", path: "payload.js", data: []byte("script"), options: payloadOptions{method: "Run"}},
		{name: "unsupported extension", path: "payload.bin", data: []byte("payload")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := payloadForPath(test.path, test.data, test.options); err == nil {
				t.Fatal("payloadForPath() error = nil, want mapping error")
			}
		})
	}
}

func TestRemovedInvocationFlagsAreRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("building the CLI is an integration check")
	}
	binaryName := "fritter-gen-test"
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}
	binaryPath := filepath.Join(t.TempDir(), binaryName)
	build := exec.Command("go", "build", "-o", binaryPath, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build fritter-gen: %v\n%s", err, output)
	}

	for _, flagName := range []string{"arg", "parameter", "utf16-parameter"} {
		t.Run(flagName, func(t *testing.T) {
			command := exec.Command(binaryPath, "-"+flagName, "value")
			output, err := command.CombinedOutput()
			if err == nil {
				t.Fatalf("fritter-gen -%s exited successfully, want rejected flag", flagName)
			}
			if !strings.Contains(string(output), "flag provided but not defined: -"+flagName) {
				t.Fatalf("fritter-gen -%s output = %q, want undefined-flag diagnostic", flagName, output)
			}
		})
	}
}

func readNativeEXE(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "test", "calc.exe"))
	if err != nil {
		t.Fatalf("read calc.exe: %v", err)
	}
	return data
}

func withPEFlags(t *testing.T, input []byte, dll, managed bool) []byte {
	t.Helper()
	data := append([]byte(nil), input...)
	peOffset := int(binary.LittleEndian.Uint32(data[0x3c:]))
	characteristicsOffset := peOffset + 4 + 18
	characteristics := binary.LittleEndian.Uint16(data[characteristicsOffset:])
	if dll {
		characteristics |= 0x2000
	} else {
		characteristics &^= 0x2000
	}
	binary.LittleEndian.PutUint16(data[characteristicsOffset:], characteristics)

	optionalHeaderOffset := peOffset + 4 + 20
	var dataDirectoryOffset int
	switch binary.LittleEndian.Uint16(data[optionalHeaderOffset:]) {
	case 0x10b:
		dataDirectoryOffset = 96
	case 0x20b:
		dataDirectoryOffset = 112
	default:
		t.Fatalf("unknown PE optional-header magic")
	}
	comDescriptorOffset := optionalHeaderOffset + dataDirectoryOffset + 14*8
	if managed {
		binary.LittleEndian.PutUint32(data[comDescriptorOffset:], 1)
	} else {
		binary.LittleEndian.PutUint32(data[comDescriptorOffset:], 0)
	}
	return data
}

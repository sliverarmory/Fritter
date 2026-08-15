package main

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/sliverarmory/Fritter"
)

func TestPayloadForPathClassifiesPEContents(t *testing.T) {
	nativeEXE := readNativeEXE(t)

	payload, err := payloadForPath("payload.exe", nativeEXE, payloadOptions{
		arguments: []string{"one", "two words"},
	})
	if err != nil {
		t.Fatalf("payloadForPath(native EXE) error = %v", err)
	}
	executable, ok := payload.(fritter.NativeExecutable)
	if !ok {
		t.Fatalf("payloadForPath(native EXE) type = %T", payload)
	}
	if len(executable.Arguments) != 2 || executable.Arguments[1] != "two words" {
		t.Fatalf("NativeExecutable.Arguments = %#v", executable.Arguments)
	}

	managedEXE := withPEFlags(t, nativeEXE, false, true)
	payload, err = payloadForPath("payload.exe", managedEXE, payloadOptions{
		arguments:      []string{"managed"},
		runtimeVersion: "v4.0.30319",
		appDomain:      "Example",
	})
	if err != nil {
		t.Fatalf("payloadForPath(managed EXE) error = %v", err)
	}
	if _, ok := payload.(fritter.DotNetExecutable); !ok {
		t.Fatalf("payloadForPath(managed EXE) type = %T", payload)
	}

	managedDLL := withPEFlags(t, nativeEXE, true, true)
	payload, err = payloadForPath("payload.dll", managedDLL, payloadOptions{
		class:  "Example.Loader",
		method: "Run",
	})
	if err != nil {
		t.Fatalf("payloadForPath(managed DLL) error = %v", err)
	}
	if _, ok := payload.(fritter.DotNetDLL); !ok {
		t.Fatalf("payloadForPath(managed DLL) type = %T", payload)
	}
}

func TestPayloadForPathRejectsExtensionMismatch(t *testing.T) {
	nativeDLL := withPEFlags(t, readNativeEXE(t), true, false)
	if _, err := payloadForPath("payload.exe", nativeDLL, payloadOptions{}); err == nil {
		t.Fatal("payloadForPath() error = nil, want EXE/DLL mismatch")
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

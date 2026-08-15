//go:build windows

package main

import (
	"flag"
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"
)

const (
	memCommit            = 0x1000
	memReserve           = 0x2000
	memRelease           = 0x8000
	pageReadWrite        = 0x04
	pageExecuteReadWrite = 0x40
	waitObject0          = 0x00000000
	waitTimeout          = 0x00000102
	waitFailed           = 0xffffffff
)

var (
	kernel32                  = syscall.NewLazyDLL("kernel32.dll")
	ntdll                     = syscall.NewLazyDLL("ntdll.dll")
	procVirtualAlloc          = kernel32.NewProc("VirtualAlloc")
	procVirtualProtect        = kernel32.NewProc("VirtualProtect")
	procVirtualFree           = kernel32.NewProc("VirtualFree")
	procFlushInstructionCache = kernel32.NewProc("FlushInstructionCache")
	procGetCurrentProcess     = kernel32.NewProc("GetCurrentProcess")
	procCreateThread          = kernel32.NewProc("CreateThread")
	procWaitForSingleObject   = kernel32.NewProc("WaitForSingleObject")
	procCloseHandle           = kernel32.NewProc("CloseHandle")
	procRtlMoveMemory         = ntdll.NewProc("RtlMoveMemory")
)

func main() {
	inputPath := flag.String("input", "", "path to raw x64 Windows shellcode")
	timeout := flag.Duration("timeout", 30*time.Second, "maximum execution time")
	flag.Parse()

	if *inputPath == "" {
		fatalf("missing required -input")
	}
	if *timeout <= 0 {
		fatalf("timeout must be positive")
	}

	shellcode, err := os.ReadFile(*inputPath)
	if err != nil {
		fatalf("read shellcode: %v", err)
	}
	if len(shellcode) == 0 {
		fatalf("shellcode is empty")
	}

	address, _, callErr := procVirtualAlloc.Call(
		0,
		uintptr(len(shellcode)),
		memCommit|memReserve,
		pageReadWrite,
	)
	if address == 0 {
		fatalf("VirtualAlloc: %v", callErr)
	}
	defer procVirtualFree.Call(address, 0, memRelease)

	procRtlMoveMemory.Call(
		address,
		uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)),
	)

	// Fritter's entry decoder updates the shellcode buffer in place.
	var oldProtect uint32
	ok, _, callErr := procVirtualProtect.Call(
		address,
		uintptr(len(shellcode)),
		pageExecuteReadWrite,
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if ok == 0 {
		fatalf("VirtualProtect: %v", callErr)
	}

	process, _, _ := procGetCurrentProcess.Call()
	ok, _, callErr = procFlushInstructionCache.Call(process, address, uintptr(len(shellcode)))
	if ok == 0 {
		fatalf("FlushInstructionCache: %v", callErr)
	}

	thread, _, callErr := procCreateThread.Call(0, 0, address, 0, 0, 0)
	if thread == 0 {
		fatalf("CreateThread: %v", callErr)
	}
	defer procCloseHandle.Call(thread)

	waitResult, _, callErr := procWaitForSingleObject.Call(thread, uintptr(timeout.Milliseconds()))
	switch waitResult {
	case waitObject0:
		fmt.Printf("executed %s (%d bytes)\n", *inputPath, len(shellcode))
	case waitTimeout:
		fatalf("shellcode did not finish within %s", timeout.String())
	case waitFailed:
		fatalf("WaitForSingleObject: %v", callErr)
	default:
		fatalf("unexpected wait result 0x%x", waitResult)
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

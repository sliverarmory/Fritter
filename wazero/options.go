package fritterwazero

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
)

type Format uint32

const (
	FormatBinary Format = 1 + iota
	FormatBase64
	FormatC
	FormatRuby
	FormatPython
	FormatPowerShell
	FormatCSharp
	FormatHex
)

type Entropy uint32

const (
	EntropyNone Entropy = 1 + iota
	EntropyRandom
	EntropyDefault
)

type HeadersMode uint32

const (
	HeadersOverwrite HeadersMode = 1 + iota
	HeadersKeep
)

type ExitMode uint32

const (
	ExitThread ExitMode = 1 + iota
	ExitProcess
	ExitBlock
)

type Options struct {
	InputPath  string
	Parameters string
	Class      string
	Method     string
	Runtime    string
	Domain     string

	OutputName string
	Format     Format
	Exit       ExitMode
	ForkOffset uint32
	Entropy    Entropy
	Headers    HeadersMode
	Chunked    *bool

	Unicode bool
	Thread  bool

	DecoyPath  string
	ModuleName string
	ServerURL  string
}

func Bool(v bool) *bool {
	return &v
}

func (o Options) Args() []string {
	inputGuest := ""
	if o.InputPath != "" {
		inputGuest = filepath.Base(o.InputPath)
	}

	decoyGuest := ""
	if o.DecoyPath != "" {
		decoyGuest = filepath.Base(o.DecoyPath)
	}

	outputGuest := ""
	if o.OutputName != "" {
		outputGuest = filepath.Base(o.OutputName)
	}

	return o.argsForGuestPaths(inputGuest, decoyGuest, outputGuest)
}

func (o Options) OutputFileName() string {
	o = o.withDefaults()
	if o.OutputName != "" {
		return filepath.Base(o.OutputName)
	}

	switch o.Format {
	case FormatBase64:
		return "loader.b64"
	case FormatC:
		return "loader.c"
	case FormatRuby:
		return "loader.rb"
	case FormatPython:
		return "loader.py"
	case FormatPowerShell:
		return "loader.ps1"
	case FormatCSharp:
		return "loader.cs"
	case FormatHex:
		return "loader.hex"
	default:
		return "loader.bin"
	}
}

func (o Options) withDefaults() Options {
	if o.Format == 0 {
		o.Format = FormatBinary
	}
	if o.Entropy == 0 {
		o.Entropy = EntropyDefault
	}
	if o.Headers == 0 {
		o.Headers = HeadersOverwrite
	}
	if o.Exit == 0 {
		o.Exit = ExitThread
	}
	return o
}

func (o Options) validate() error {
	if strings.TrimSpace(o.InputPath) == "" {
		return fmt.Errorf("input path is required")
	}
	return nil
}

func (o Options) argsForGuestPaths(inputGuest, decoyGuest, outputGuest string) []string {
	o = o.withDefaults()

	args := []string{"fritter"}
	if o.Headers != HeadersOverwrite {
		args = append(args, "-k", strconv.Itoa(int(o.Headers)))
	}
	if o.Class != "" {
		args = append(args, "-c", o.Class)
	}
	if o.Domain != "" {
		args = append(args, "-d", o.Domain)
	}
	if o.Entropy != EntropyDefault {
		args = append(args, "-e", strconv.Itoa(int(o.Entropy)))
	}
	if o.Format != FormatBinary {
		args = append(args, "-f", strconv.Itoa(int(o.Format)))
	}

	args = append(args, "-i", inputGuest)

	if o.Method != "" {
		args = append(args, "-m", o.Method)
	}
	if o.ModuleName != "" {
		args = append(args, "-n", o.ModuleName)
	}
	if decoyGuest != "" {
		args = append(args, "-j", decoyGuest)
	}
	if outputGuest != "" {
		args = append(args, "-o", outputGuest)
	}
	if o.Parameters != "" {
		args = append(args, "-p", o.Parameters)
	}
	if o.Runtime != "" {
		args = append(args, "-r", o.Runtime)
	}
	if o.ServerURL != "" {
		args = append(args, "-s", o.ServerURL)
	}
	if o.Thread {
		args = append(args, "-t")
	}
	if o.Unicode {
		args = append(args, "-w")
	}
	if o.Exit != ExitThread {
		args = append(args, "-x", strconv.Itoa(int(o.Exit)))
	}
	if o.ForkOffset != 0 {
		args = append(args, "-y", strings.ToUpper(strconv.FormatUint(uint64(o.ForkOffset), 16)))
	}
	if o.Chunked != nil {
		chunked := "0"
		if *o.Chunked {
			chunked = "1"
		}
		args = append(args, "-g", chunked)
	}
	return args
}

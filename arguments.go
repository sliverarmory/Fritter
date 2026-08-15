package fritter

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// encodeArguments composes an argv slice using the quoting rules consumed by
// CommandLineToArgvW. The result is stored as a single command-line string in
// a Fritter module.
func encodeArguments(arguments []string) (string, error) {
	var commandLine []byte
	for index, argument := range arguments {
		if !utf8.ValidString(argument) {
			return "", invalid(fmt.Sprintf("payload.arguments[%d]", index), "is not valid UTF-8")
		}
		if strings.ContainsRune(argument, '\x00') {
			return "", invalid(fmt.Sprintf("payload.arguments[%d]", index), "contains a NUL byte")
		}
		if index != 0 {
			commandLine = append(commandLine, ' ')
		}
		commandLine = appendWindowsArgument(commandLine, argument)
	}

	if len(commandLine) > maxArgumentsBytes {
		return "", invalid("payload.arguments", fmt.Sprintf("encoded command line exceeds %d bytes", maxArgumentsBytes))
	}
	return string(commandLine), nil
}

// appendWindowsArgument follows the same quoting algorithm as Go's Windows
// process launcher, but is available on every host OS.
func appendWindowsArgument(buffer []byte, argument string) []byte {
	if len(argument) == 0 {
		return append(buffer, `""`...)
	}

	needsBackslash := false
	hasSpace := false
	for index := 0; index < len(argument); index++ {
		switch argument[index] {
		case '"', '\\':
			needsBackslash = true
		case ' ', '\t':
			hasSpace = true
		}
	}

	if !needsBackslash && !hasSpace {
		return append(buffer, argument...)
	}
	if !needsBackslash {
		buffer = append(buffer, '"')
		buffer = append(buffer, argument...)
		return append(buffer, '"')
	}

	if hasSpace {
		buffer = append(buffer, '"')
	}
	backslashes := 0
	for index := 0; index < len(argument); index++ {
		character := argument[index]
		switch character {
		default:
			backslashes = 0
		case '\\':
			backslashes++
		case '"':
			for ; backslashes > 0; backslashes-- {
				buffer = append(buffer, '\\')
			}
			buffer = append(buffer, '\\')
		}
		buffer = append(buffer, character)
	}
	if hasSpace {
		for ; backslashes > 0; backslashes-- {
			buffer = append(buffer, '\\')
		}
		buffer = append(buffer, '"')
	}
	return buffer
}

package main

import "C"

import (
	"fmt"
	"os"
)

const helloMessage = "hello world from Go DLL\n"

//export HelloWorld
func HelloWorld() {
	path := os.Getenv("FRITTER_HELLO_PATH")
	if path == "" {
		path = "hello-world.txt"
	}

	if err := os.WriteFile(path, []byte(helloMessage), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write hello-world marker: %v\n", err)
	}
}

func main() {}

package main

import (
	"io"
	"os"
)

var (
	cliStdout io.Writer = os.Stdout
	cliStderr io.Writer = os.Stderr
)

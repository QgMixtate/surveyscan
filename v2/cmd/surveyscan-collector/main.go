package main

import (
	"fmt"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/buildinfo"
	"os"
)

func main() {
	if len(os.Args) == 2 && (os.Args[1] == "version" || os.Args[1] == "--version") {
		if err := buildinfo.Print(os.Stdout, "collector"); err != nil {
			os.Exit(1)
		}
		return
	}
	fmt.Fprintln(os.Stderr, "collector runtime is not implemented in C04; only version is available")
	os.Exit(2)
}

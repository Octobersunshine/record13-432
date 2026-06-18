//go:build !windows
// +build !windows

package main

import (
	"fmt"
	"os"
)

func isExecutable(filePath string, info os.FileInfo) (bool, string) {
	if info.IsDir() {
		return false, "directory"
	}
	mode := info.Mode()
	if mode&0111 != 0 {
		return true, fmt.Sprintf("has execute permission (mode: %s)", mode.Perm())
	}
	return false, fmt.Sprintf("no execute permission (mode: %s)", mode.Perm())
}

func isReadable(filePath string, info os.FileInfo) bool {
	file, err := os.Open(filePath)
	if err == nil {
		file.Close()
		return true
	}
	return false
}

func isWritable(filePath string, info os.FileInfo) bool {
	mode := info.Mode()
	return mode&0200 != 0
}

func getOSName() string {
	return "unix"
}

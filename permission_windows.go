//go:build windows
// +build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

var executableExtensions = map[string]bool{
	".exe": true, ".bat": true, ".cmd": true,
	".com": true, ".ps1": true, ".msi": true,
	".scr": true, ".cpl": true, ".jar": true,
}

func isExecutable(filePath string, info os.FileInfo) (bool, string) {
	if info.IsDir() {
		return false, "directory"
	}

	ext := strings.ToLower(filepath.Ext(filePath))
	if executableExtensions[ext] {
		return true, fmt.Sprintf("executable extension: %s", ext)
	}

	return false, fmt.Sprintf("non-executable extension: %s", ext)
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
	if info.IsDir() {
		testFile := filepath.Join(filePath, ".write_test_"+fmt.Sprintf("%d", os.Getpid()))
		f, err := os.OpenFile(testFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err == nil {
			f.Close()
			os.Remove(testFile)
			return true
		}
		return false
	}

	attr, ok := getFileAttributes(info)
	if ok {
		if attr&syscall.FILE_ATTRIBUTE_READONLY != 0 {
			return false
		}
		return true
	}

	return true
}

func getFileAttributes(info os.FileInfo) (uint32, bool) {
	if sysInfo, ok := info.Sys().(*syscall.Win32FileAttributeData); ok {
		return sysInfo.FileAttributes, true
	}
	return 0, false
}

func getOSName() string {
	return "windows"
}

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
)

type FilePermissionResponse struct {
	FilePath       string `json:"file_path"`
	FileName       string `json:"file_name"`
	Exists         bool   `json:"exists"`
	IsExecutable   bool   `json:"is_executable"`
	IsReadable     bool   `json:"is_readable"`
	IsWritable     bool   `json:"is_writable"`
	Size           int64  `json:"size"`
	Permission     string `json:"permission"`
	IsDir          bool   `json:"is_dir"`
	OS             string `json:"os"`
	ExecutableInfo string `json:"executable_info"`
	Error          string `json:"error,omitempty"`
}

type CheckRequest struct {
	FilePath string `json:"file_path"`
}

var executableExtensions = map[string]bool{
	".exe": true, ".bat": true, ".cmd": true,
	".com": true, ".ps1": true, ".msi": true,
	".scr": true, ".cpl": true, ".jar": true,
}

func isExecutableUnix(info os.FileInfo) bool {
	mode := info.Mode()
	return mode&0111 != 0
}

func isExecutableWindows(filePath string, info os.FileInfo) (bool, string) {
	if info.IsDir() {
		return false, "directory"
	}

	ext := strings.ToLower(filepath.Ext(filePath))
	if executableExtensions[ext] {
		return true, fmt.Sprintf("executable extension: %s", ext)
	}

	return false, fmt.Sprintf("non-executable extension: %s", ext)
}

func checkPermissions(filePath string) FilePermissionResponse {
	resp := FilePermissionResponse{
		FilePath: filePath,
		OS:       runtime.GOOS,
	}

	absPath, err := filepath.Abs(filePath)
	if err == nil {
		resp.FilePath = absPath
	}

	resp.FileName = filepath.Base(resp.FilePath)

	info, err := os.Stat(resp.FilePath)
	if err != nil {
		if os.IsNotExist(err) {
			resp.Exists = false
			resp.Error = "file does not exist"
			return resp
		}
		resp.Exists = false
		resp.Error = fmt.Sprintf("stat error: %v", err)
		return resp
	}

	resp.Exists = true
	resp.IsDir = info.IsDir()
	resp.Size = info.Size()
	resp.Permission = info.Mode().Perm().String()

	file, err := os.Open(resp.FilePath)
	if err == nil {
		resp.IsReadable = true
		file.Close()
	} else {
		resp.IsReadable = false
	}

	testWritePath := resp.FilePath + ".write_test"
	testFile, err := os.OpenFile(testWritePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err == nil {
		resp.IsWritable = true
		testFile.Close()
		os.Remove(testWritePath)
	} else {
		writeDir := filepath.Dir(resp.FilePath)
		testFile, err = os.OpenFile(filepath.Join(writeDir, ".write_test_"+fmt.Sprintf("%d", os.Getpid())), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err == nil {
			resp.IsWritable = true
			testFile.Close()
			os.Remove(filepath.Join(writeDir, ".write_test_"+fmt.Sprintf("%d", os.Getpid())))
		} else {
			resp.IsWritable = false
		}
	}

	switch runtime.GOOS {
	case "windows":
		isExe, infoMsg := isExecutableWindows(resp.FilePath, info)
		resp.IsExecutable = isExe
		resp.ExecutableInfo = infoMsg
	default:
		resp.IsExecutable = isExecutableUnix(info)
		if resp.IsExecutable {
			resp.ExecutableInfo = fmt.Sprintf("has execute permission (mode: %s)", info.Mode().Perm())
		} else {
			resp.ExecutableInfo = fmt.Sprintf("no execute permission (mode: %s)", info.Mode().Perm())
		}
	}

	if runtime.GOOS == "windows" && resp.IsExecutable {
		if sysInfo, ok := info.Sys().(*syscall.Win32FileAttributeData); ok {
			_ = sysInfo
		}
	}

	return resp
}

func checkHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	var filePath string

	if r.Method == http.MethodPost {
		var req CheckRequest
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&req); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"invalid request body: %v"}`, err), http.StatusBadRequest)
			return
		}
		filePath = req.FilePath
	} else if r.Method == http.MethodGet {
		filePath = r.URL.Query().Get("path")
	} else {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	if filePath == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "file_path parameter is required"})
		return
	}

	result := checkPermissions(filePath)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(result)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "ok",
		"os":      runtime.GOOS,
		"arch":    runtime.GOARCH,
		"version": runtime.Version(),
	})
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/check", checkHandler)
	mux.HandleFunc("/health", healthHandler)

	server := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	fmt.Printf("Server starting on port %s...\n", port)
	fmt.Printf("GET  /check?path=<filepath>  - Check file permissions\n")
	fmt.Printf("POST /check                   - Check file permissions (JSON body)\n")
	fmt.Printf("GET  /health                  - Health check\n")

	if err := server.ListenAndServe(); err != nil {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		os.Exit(1)
	}
}
